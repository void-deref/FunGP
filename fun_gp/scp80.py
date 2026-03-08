from fun_gp.utils import hex_to_bytes, bytes_to_hex, lv
from Crypto.Cipher import DES3, AES
from Crypto.Hash import CMAC

class SCP80:
    def __init__(self, key_set:list=[str], counter:list|str=''):
        
        if isinstance(counter, str): # transform hex string into byte array
            counter = hex_to_bytes(counter)

        self.kic_key = hex_to_bytes(key_set[0])
        self.kid_key = hex_to_bytes(key_set[1])
        self.kik_key = hex_to_bytes(key_set[2])
        self.cntr    = counter


    def _encrypt(self, plain_text:list|str, algo:int) -> str:

        if isinstance(plain_text, str): # transform hex string into byte array
            plain_text = hex_to_bytes(plain_text)
        
        padding_bytes = self._count_padding(len(plain_text), algo)
        plain_text   += [0] * padding_bytes

        if algo & 0x03 == 0x03:
            raise ValueError(f'Unsupported algorithm')
        
        if algo & 0x01 == 0x01:
            cipher = DES3.new(self.kic_key, DES3.MODE_CBC, (b'\x00' * 8))
        else:
            cipher = AES.new(bytes(self.kic_key), AES.MODE_CBC, (b'\x00' * 16))
        
        cipher_text = list(cipher.encrypt(bytes(plain_text)))
        
        if padding_bytes != 0: # truncate padding bytes (if any)
            cipher_text = cipher_text[0:-padding_bytes]
        
        return cipher_text


    def _checksum(self, plain_text:list|str, algo:int) -> str:

        if isinstance(plain_text, str):
            plain_text = hex_to_bytes(plain_text)

        # print(f'Checksum input: {bytes_to_hex(plain_text)}')

        if (algo & 0x03 == 0x00) or (algo & 0x03 == 0x03):
            raise ValueError(f'Unsupported algorithm')
        
        if algo & 0x01 == 0x01:
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

        return list(checksum)


    def _count_padding(self, data_length:int, algo:int):
        
        if (algo & 0x03 == 0x00) or (algo & 0x03 == 0x03):
            raise ValueError(f'Unsupported algorithm')
        
        if algo & 0x01 == 0x01: # DES
            padding  = (8 - (data_length % 8)) % 8
        else:
            padding  = (16 - (data_length % 16)) % 16
        
        return padding


    def _increment_cntr(self):

        for i in range(0, 5):
            self.cntr[-1 - i] += 1 # increment starting from the least significant byte
            self.cntr[-1 - i] &= 0xff # truncate to byte size
            if self.cntr[-1 - i] != 0x00:
                break
        
        # print(f'\tCounter\'s next value: {bytes_to_hex(self.cntr)}')
