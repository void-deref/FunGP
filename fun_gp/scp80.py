from fun_gp import CP, SMSPP, CardDataBase
from fun_gp import decode_bcd, hex_to_bytes
from Crypto.Cipher import DES3, AES
from Crypto.Hash import CMAC
from math import ceil
import atexit

class SCP80Params:
    def __init__(self, spi:str='1621', tar:str='000000', kic:int=0x00, kid:int=0x00, por:int=0x00):
        self.spi = hex_to_bytes(spi)
        self.kic = kic
        self.kid = kid
        self.tar = hex_to_bytes(tar)
        self.por = por
    
    def _build_list(self):
        return  self.spi + [self.kic] + [self.kid] + self.tar + [self.por]

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())


class SCP80:
    def __init__(self, path_to_card_deck:str, plain_apdu:callable):
        self.params:SCP80Params = SCP80Params()
        self._plain_apdu        = plain_apdu

        self.imsi      = self._get_imsi()
        self.db        = CardDataBase(path_to_card_deck)
        self.curr_file = self.db.load_json()

        self.curr_card = self.curr_file.get(self.imsi)
        if not self.curr_card:
            raise ValueError(f"Card with IMSI '{self.imsi}' not found")

        self.cntr      = self.curr_card.cntr
        self.kic_key   = hex_to_bytes(self.curr_card.kic)
        self.kid_key   = hex_to_bytes(self.curr_card.kid) 
        self.kik_key   = hex_to_bytes(self.curr_card.kik)
        self.key_id    = int(self.curr_card.key_id, 16)

        atexit.register(self._update_counter)


    def _update_counter(self):
        self.curr_card.cntr       = self.cntr
        self.curr_file[self.imsi] = self.curr_card
        self.db.update_json(self.curr_file)
        print('JSON file has been updated.')


    def set_params(self, params:SCP80Params):
        self.params.spi = params.spi
        self.params.kic = (self.key_id << 4) | params.kic
        self.params.kid = (self.key_id << 4) | params.kid
        self.params.tar = params.tar
        self.params.por = params.por


    def make_secured_packet(self, payload:str|list, chunk_size:int=132) -> list[SMSPP]:

        if isinstance(payload, str):
            payload = hex_to_bytes(payload)
        
        cmd_pkt = CP(self.cntr, payload)
        cmd_pkt.ch.spi = self.params.spi        
        cmd_pkt.ch.kic = self.params.kic
        cmd_pkt.ch.kid = self.params.kid
        cmd_pkt.ch.tar = self.params.tar

        if cmd_pkt.ch.spi[0] & 0x02 != 0x00: # checksum takes place. Add 8 bytes to length of CP and CH
            cmd_pkt.ch.len     += 8
            cp_len              = int.from_bytes(cmd_pkt.len)
            cmd_pkt.len         = hex_to_bytes(f'{(cp_len + 8):04x}')
        
        if cmd_pkt.ch.spi[0] & 0x04 != 0x00: # ciphering takes place. Count padding bytes
            cc_len           = (cmd_pkt.ch.len - 0x0d)
            cmd_pkt.ch.pcntr = self._count_padding(len(cmd_pkt[10:]) + cc_len, cmd_pkt.ch.kic)
            cmd_pkt.data    += [0] * cmd_pkt.ch.pcntr
            cp_len           = int.from_bytes(cmd_pkt.len)
            cmd_pkt.len      = hex_to_bytes(f'{(cp_len + cmd_pkt.ch.pcntr):04x}')
        
        if cmd_pkt.ch.spi[0] & 0x02 != 0x00: # calculate checksum
            cmd_pkt.ch.checksum = self._checksum(cmd_pkt[0:], cmd_pkt.ch.kid)

        # print(f'\nCommandPacket as plain text: {bytes_to_hex(cmd_pkt)}\n')

        if cmd_pkt.ch.spi[0] & 0x04 != 0x00: # encipher Command Packet
            cipher_text         = self._encrypt(cmd_pkt[10:], cmd_pkt.ch.kic)
            cmd_pkt.ch.cntr     = cipher_text[0:5]
            cmd_pkt.ch.pcntr    = cipher_text[5]
            cmd_pkt.ch.checksum = cipher_text[6:14]
            cmd_pkt.data        = cipher_text[14:]
        
        # print(f'CommandPacket as cipher text: {cmd_pkt}')

        total_length = len(cmd_pkt)
        chunks_total = ceil(total_length / chunk_size)

        sms_seq_num  = 1
        is_concat    = True if chunks_total > 1 else False
        is_secured   = True
        sms_list:list[SMSPP] = []

        for i in range(0, total_length, chunk_size):
            sms = SMSPP(user_data=cmd_pkt[i:i + chunk_size], is_concat=is_concat, is_secured=is_secured)
            sms.tpdu.ud.udh.concat.max_num = chunks_total
            sms.tpdu.ud.udh.concat.seq_num = sms_seq_num
            sms_seq_num += 1
            is_secured  = False # the 'IEI STK' must present in the first chunk only
            sms_list.append(sms)

        
        if ((cmd_pkt.ch.spi[0] & 0x18) != 0):
            self._increment_cntr()
        
        return sms_list


    def _encrypt(self, input_data:list|str, algo:int) -> list[int]:

        if isinstance(input_data, str): # transform hex string into byte array
            input_data = hex_to_bytes(input_data)
        
        plain_text = input_data.copy()
        
        padding_bytes = self._count_padding(len(plain_text), algo)
        plain_text   += [0] * padding_bytes

        algo &= 0x03
        if algo not in (0x01, 0x02):
            raise ValueError(f'Unsupported algorithm {algo:02x}')
        
        if algo == 0x01:
            cipher = DES3.new(self.kic_key, DES3.MODE_CBC, (b'\x00' * 8))
        else:
            cipher = AES.new(bytes(self.kic_key), AES.MODE_CBC, (b'\x00' * 16))
        
        cipher_text = list(cipher.encrypt(bytes(plain_text)))
        return cipher_text


    def _checksum(self, input_data:list|str, algo:int) -> list[int]:
    
        if isinstance(input_data, str):
            input_data = hex_to_bytes(input_data)

        plain_text = input_data.copy()

        algo &= 0x03
        if algo not in (0x01, 0x02):
            raise ValueError(f'Unsupported algorithm {algo:02x}')
        
        if algo == 0x01: # 3DES
            padding_bytes = self._count_padding(len(plain_text), algo)
            plain_text   += [0] * padding_bytes
            cipher        = DES3.new(self.kid_key, DES3.MODE_CBC, (b'\x00' * 8))
            checksum = list(cipher.encrypt(bytes(plain_text)))
            checksum = checksum[-8:]
        else: # AES
            cobj = CMAC.new(bytes(self.kid_key), ciphermod=AES)
            cobj.update(bytes(plain_text))
        
            checksum = cobj.digest()
            checksum = checksum[:8]
            # checksum = checksum[-8:]

        return list(checksum)


    def _count_padding(self, data_length:int, algo:int):
        
        algo &= 0x03
        if algo not in (0x01, 0x02):
            raise ValueError(f'Unsupported algorithm {algo:02x}')
        
        # eight bytes padding in case of 3DES; Otherwise, 16 for AES
        op = 8 if algo == 0x01 else 16
        padding = (op - (data_length % op)) % op
        return padding


    def _increment_cntr(self):
        cntr_int = int(self.cntr, 16)
        cntr_int = (cntr_int + 1) & 0xffffffffff
        self.cntr = f'{cntr_int:010x}'
        print(f'\tCounter\'s next value: {self.cntr}')
    

    def _get_imsi(self):
        self._plain_apdu('00a4 000C 02 3F00', 0x90, cmd_name='select MF')
        self._plain_apdu('00a4 000C 02 7F20', 0x90, 0x00, cmd_name='select DF GSM')
        self._plain_apdu('00a4 000C 02 6F07', 0x90, 0x00, cmd_name='select EF IMSI')
        imsi, _, _ = self._plain_apdu('00b0 0000', 0x90, 0x00, cmd_name='read IMSI')
        imsi = decode_bcd(imsi)
        print(f'\nIMSI: {imsi}')
        
        return imsi