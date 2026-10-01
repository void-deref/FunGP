from fun_gp import bytes_to_hex, hex_to_bytes
from Crypto.Cipher import DES3, DES
from enum import IntEnum

class SecurityLevel(IntEnum):
    NO_SECURITY_LEVEL = 0x00
    C_MAC             = 0x01
    C_DECRYPTION      = 0x03


class SCP02:
    def __init__(self, key_set:list[str]):
        
        self.enc = key_set[0]
        self.mac = key_set[1]
        self.dec = key_set[2]

        self.skey_enc = None
        self.skey_mac = None
        self.skey_dek = None
        self.IV = bytes([0] * 8)
        self.authenticated = False

    def make_scp02_c_mac(self, cmd:str|list) ->list[int]:
        if isinstance(cmd, str):
            cmd = hex_to_bytes(cmd)

        if len(cmd) == 4:
            cmd.append(0)
        
        cmd[0] &= 0xFC # clean channel indication
        cmd[0] |= 0x04 # set GP proprietary SM flag
        cmd[4] += 8
        if cmd[4] > 255:
            raise ValueError(f'Expected 255 bytes for CDATA, but got {cmd[4]}')
        cmd += self._retail_mac(cmd)
        return cmd

    def make_scp02_c_decryption(self, cmd:str|list) ->list[int]:
        cmd = self.make_scp02_c_mac(cmd)

        if (cmd[4] == 0x08): # there are C-MAC only in payload, which shouldn't be ciphered.
            return cmd       # bail out
        
        header = cmd[0:5]
        cdata  = cmd[5:-8] # strip off the command header and C-MAC
        c_mac  = cmd[-8:] 
        cdata  = self._padding(cdata) # apply padding
        header[4] = len(cdata) + 8   # update Lc field with the new length of payload

        if (header[4] > 255):
            raise ValueError(f'Expected 255 bytes for CDATA, but got {header[4]}')
        
        cdata  = list(self._apply_3des_cbc(cdata, self.skey_enc))
        return header + cdata + c_mac
        

    
    def init_update(self, response, host_challenge):
        counter, card_challenge, card_cryptogram = self._parse_card_response(response)

        self.skey_enc = self._derive_key(self.enc, counter, 'enc')
        self.skey_mac = self._derive_key(self.enc, counter, 'mac')
        self.skey_dek = self._derive_key(self.enc, counter, 'dec')
        
        # GP, appendix E.4.2.1: card authentication cryptogram
        card_cryptogram_check = self._card_crypto(host_challenge, counter, card_challenge)
        
        if card_cryptogram != card_cryptogram_check:
            raise ValueError(
                f'ERROR: cryptograms mismatch!\
                \nexpected: {bytes_to_hex(card_cryptogram)}\
                \ngot     : {bytes_to_hex(card_cryptogram_check)}\
                \n****************************** NOTICE! ******************************\
                \nYou see this message because \'INITIALIZE UPDATE\' command failed.\
                \nAfter 5 or more attemts ISD can intentionally increase the time of \
                \nperformig this operation because he thinks you\'re brute-forcing him.')

        return counter, card_challenge, host_challenge


    def external_authenticate(self, counter, card_challenge, host_challenge, security_level:int=SecurityLevel.C_MAC):
        # GP, appendix E.4.2.2: host authentication cryptogram
        host_crypto  = self._host_crypto(counter, card_challenge, host_challenge)
        ext_auth_cmd = [0x80, 0x82, security_level, 0x00, 0x08] + host_crypto
        ext_auth_cmd[0] &= 0xFC # clean channel indication
        ext_auth_cmd[0] |= 0x04 # set GP proprietary SM flag
        ext_auth_cmd[4] += 8
        c_mac = self._retail_mac(ext_auth_cmd)

        ext_auth_cmd = ext_auth_cmd + c_mac
        return ext_auth_cmd
        

    def _host_crypto(self, counter, card_challenge, host_challenge):
        auth_data = counter + card_challenge + host_challenge + [0x80] + [0] * 7
        auth_data = self._apply_3des_cbc(auth_data, self.skey_enc)
        auth_data = list(auth_data[-8:])
        
        print(f'\t\thost cryptogram         : {bytes_to_hex(auth_data)}\n')
        
        return auth_data


    def _card_crypto(self, host_challenge, counter, card_challenge):
        auth_data = host_challenge + counter + card_challenge + [0x80] + [0] * 7
        auth_data = self._apply_3des_cbc(auth_data, self.skey_enc)
        auth_data = list(auth_data[-8:])

        print(f'\t\tcard cryptogram         : {bytes_to_hex(auth_data)}')
        
        return auth_data
    

    def _derive_key(self, key, sequence_counter, key_type):
        plain_text = [1, 0] # the first byte is always '1'. See GP 2.3, appendix E.4
        # define the second byte
        if (key_type == 'mac'):
            plain_text[1] = 0x01
        elif (key_type == 'enc'):
            plain_text[1] = 0x82
        elif (key_type == 'dec'):
            plain_text[1] = 0x81
        else:
            # raise ValueError(f'Unknown type of ISD static key.')
            return None
        
        plain_text = plain_text + sequence_counter
        plain_text = plain_text + [0] * 12

        session_key = self._apply_3des_cbc(plain_text, key)
        print(f'\t\t{key_type.upper()} session key         : {bytes_to_hex(session_key)}')
        return session_key


    def _apply_3des_cbc(self, plain_text:str|list[int], key:str|list[int]):
        if isinstance(key, str):
            key = hex_to_bytes(key)
        key = bytes(key)

        if isinstance(plain_text, str):
            plain_text = hex_to_bytes(plain_text)
        plain_text = bytes(plain_text)
        
        # 3DES in CBC mode with IV of 8 bytes length all equal '00'. See GP 2.3, appendix E.3
        des3_cbc = DES3.new(key, DES3.MODE_CBC, (b'\x00' * 8))
        result   = des3_cbc.encrypt(plain_text)
        return bytes(result)


    def _apply_des_ecb(self, plain_text:str|list[int], key:str|list[int]):
        
        if isinstance(key, str):
            key = hex_to_bytes(key)
        key = bytes(key)

        if isinstance(plain_text, str):
            plain_text = hex_to_bytes(plain_text)
        plain_text = bytes(plain_text)

        des_ecb  = DES.new(key, DES.MODE_ECB)
        result   = des_ecb.encrypt(plain_text)
        
        return bytes(result)


    def _parse_card_response(self, response):
        diversification_data = response[0:10]
        kvn_and_scp_id       = response[10:12]
        counter              = response[12:14]
        card_challenge       = response[14:20]
        card_cryptogram      = response[20:28]
        
        print(f'\t\tKey diversification data: {bytes_to_hex(diversification_data)}')
        print(f'\t\tKVN and SCP ID          : {bytes_to_hex(kvn_and_scp_id)}')
        print(f'\t\tKey Sequence counter    : {bytes_to_hex(counter)}')
        print(f'\t\tCard challenge          : {bytes_to_hex(card_challenge)}')

        return counter, card_challenge, card_cryptogram


    def _padding(self, data:list[int]) -> list[int]:

        padding = 0

        data.append(0x80)

        data_len = len(data)
        padding  = (8 - (data_len % 8)) % 8
        data    += [0] * padding
        
        return data


    def _retail_mac(self, input_list:list) -> list[int]:
        # ISO 9797-1 MAC 3 (also known as Retail MAC)
        data = list(input_list)
        data = self._padding(data)

        if self.authenticated == True:
            des_ecb  = DES.new(self.skey_mac[0:8], DES.MODE_ECB)
            self.IV = des_ecb.encrypt(self.IV)

        last_block      = bytes(data[-8:])
        previous_blocks = bytes(data[0:-8])
        current_iv      = self.IV

        if previous_blocks:
            des_K1     = DES.new(bytes(self.skey_mac[0:8]), DES.MODE_CBC, self.IV)
            Hq         = des_K1.encrypt(previous_blocks)
            current_iv = Hq[-8:]

        des_K2  = DES3.new(bytes(self.skey_mac), DES.MODE_CBC, current_iv)
        self.IV = des_K2.encrypt(last_block)
        mac     = list(self.IV)

        return mac
