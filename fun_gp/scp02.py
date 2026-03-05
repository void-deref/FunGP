from fun_gp.utils import bytes_to_hex, hex_to_bytes
from Crypto.Cipher import DES3, DES


# class SCP02(Reader):
class SCP02:
    def __init__(self, key_set:list=['','','']):
        self.enc = key_set[0]
        self.mac = key_set[1]
        self.dec = key_set[2]

        self.session_enc = None
        self.session_mac = None
        self.session_dec = None
        self.IV = [0] * 8
        
        self.authenticated = False

    def _init_update(self, response, host_challenge):
        counter,              \
        card_challenge,       \
        card_cryptogram,      \
        diversification_data, \
        kvn_and_scp_id = self._parse_card_response(response)

        print(f'\t\tKey diversification data: {bytes_to_hex(diversification_data)}')
        print(f'\t\tKVN and SCP ID          : {bytes_to_hex(kvn_and_scp_id)}')
        print(f'\t\tKey Sequence counter    : {bytes_to_hex(counter)}')
        print(f'\t\tCard challenge          : {bytes_to_hex(card_challenge)}')

        self.session_enc = self._derive_key(self.enc, counter, 'enc')
        self.session_mac = self._derive_key(self.enc, counter, 'mac')
        self.session_dec = self._derive_key(self.enc, counter, 'dec')
        
        # GP, appendix E.4.2.1: card authentication cryptogram
        card_cryptogram_check = self._card_crypto(host_challenge, counter, card_challenge)
        
        if card_cryptogram != card_cryptogram_check:
            raise ValueError(
                f'ERROR: cryptograms mismatch!\
                \n\t\t\t****************************** CAUTION! ******************************\
                \n\t\t\tYou see this message because \'INITIALIZE UPDATE\' command failed.\
                \n\t\t\tAfter 5 or more attemts ISD can intentionally increase the time of \
                \n\t\t\tperformig this operation because he thinks you\'re brute-forcing him.')
       
        return counter, card_challenge, host_challenge

    def _external_authenticate(self, counter, card_challenge, host_challenge):
        # GP, appendix E.4.2.2: host authentication cryptogram
        host_crypto  = self._host_crypto(counter, card_challenge, host_challenge)
        ext_auth_cmd = [0x80, 0x82, 0x01, 0x00, 0x08] + host_crypto
        ext_auth_cmd[0] &= 0xFC # clean channel indication
        ext_auth_cmd[0] |= 0x04 # set GP proprietary SM flag
        ext_auth_cmd[4] += 8
        c_mac = self._retail_mac(ext_auth_cmd)

        ext_auth_cmd = ext_auth_cmd + c_mac
        return ext_auth_cmd
        

    def _host_crypto(self, counter, card_challenge, host_challenge):
        auth_data = counter + card_challenge + host_challenge + [0x80] + [0] * 7
        auth_data = self._apply_3des_cbc(auth_data, self.session_enc)
        auth_data = list(auth_data[-8:])
        
        print(f'\t\thost cryptogram         : {bytes_to_hex(auth_data)}\n')
        
        return auth_data

    def _card_crypto(self, host_challenge, counter, card_challenge):
        auth_data = host_challenge + counter + card_challenge + [0x80] + [0] * 7
        auth_data = self._apply_3des_cbc(auth_data, self.session_enc)
        auth_data = list(auth_data[-8:])

        print(f'\t\tcard cryptogram         : {bytes_to_hex(auth_data)}')
        
        return auth_data
    
    def _derive_key(self, key, sequence_counter, key_type):
        plain_text = [1, 0] # the first byte of constant value. See GP 2.3, appendix E.4
        # define the second byte of constant value
        if (key_type == 'mac'):
            plain_text[1] = 0x01
        elif (key_type == 'enc'):
            plain_text[1] = 0x82
        elif (key_type == 'dec'):
            plain_text[1] = 0x81
        else:
            # self.close_context()
            # raise ValueError(f'Unknown type of ISD static key.')
            return None
        
        plain_text = plain_text + sequence_counter
        plain_text = plain_text + [0] * 12

        session_key = self._apply_3des_cbc(plain_text, key)
        # print(f'\t\t{key_type}                     : {bytes_to_hex(session_key)}')
        return session_key

    def _apply_3des_cbc(self, plain_text, key):
        if isinstance(key, str):
            key = bytes(hex_to_bytes(key))

        if isinstance(key, list):
            key = bytes(key)
        
        # 3DES in CBC mode with IV of 8 bytes length all equal '00'. See GP 2.3, appendix E.3
        cipher = DES3.new(key, DES3.MODE_CBC, (b'\x00' * 8))
        return cipher.encrypt(bytes(plain_text))

    def _parse_card_response(self, response):
        diversification_data = response[0:10]
        kvn_and_scp_id       = response[10:12]
        counter              = response[12:14]
        card_challenge       = response[14:20]
        card_cryptogram      = response[20:28]
        
        return counter, card_challenge, card_cryptogram, diversification_data, kvn_and_scp_id

    def _retail_mac(self, cmd:list):
        
        # According to ISO 9797-1
        # Step 1: padding method 2
        cmd = cmd + [0x80]
        data_len = len(cmd)
        padding  = (8 - (data_len % 8)) % 8
        cmd     += [0] * padding

        # cmd[4] += 8
        des_ecb =  DES.new(self.session_mac[0:8], DES.MODE_ECB)
        des3_ecb = DES3.new(self.session_mac, DES3.MODE_ECB)

        if self.authenticated == True:
            self.IV = list(des_ecb.encrypt(bytes(self.IV)))
        
        i = 0
        # Steps 2-4: splitting, initial trasformation and iteration
        while i < (len(cmd) - 8):
            for j in range(8):
                self.IV[j] ^=cmd[i + j]
            
            self.IV = list(des_ecb.encrypt(bytes(self.IV)))
            i += 8
        
        # step 5: output transformation
        for j in range(8):
            self.IV[j] ^=cmd[i + j]
        
        self.IV = list(des3_ecb.encrypt(bytes(self.IV)))   
        return self.IV
