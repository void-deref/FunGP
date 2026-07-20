from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fun_gp import Reader, SmartCard, lv_hex, bytes_to_hex, hex_to_bytes

class DiffieHellman:
    def __init__(self):
        self.priv_key = ec.generate_private_key(ec.SECP256K1())
        self.pub_key  = self.priv_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        ).hex()

        self.cipher = None
        self.iv = bytearray(16)


    def generate_shared_secret(self, raw_bytes:bytes|list[int]):

        if isinstance(raw_bytes, list):
            raw_bytes = bytes(raw_bytes)
    
        card_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw_bytes)
        shared_secret = self.priv_key.exchange(ec.ECDH(), card_public_key)
        return list(shared_secret)


    def init_aes_cipher(self, shared_secret:bytes|list[int]):
        if isinstance(shared_secret, list):
            shared_secret = bytes(shared_secret)
        self.cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(self.iv))
    

    def aes_encrypt(self, plain_text:str|bytes|list[int]) -> list[int]:
        if isinstance(plain_text, str):
            plain_text = hex_to_bytes(plain_text)
        plain_text = bytes(plain_text)
        
        # Add padding bytes
        padded_data = plain_text + b'\x80'
        remainder = len(padded_data) % 16
        if remainder != 0:
            padded_data += b'\x00' * (16 - remainder)

        encryptor = self.cipher.encryptor()
        cipher_text = list(encryptor.update(padded_data) + encryptor.finalize())
        return cipher_text


    def aes_decrypt(self, cipher_text:bytes|list[int]):
        cipher_text = bytes(cipher_text)
        decryptor   = self.cipher.decryptor()
        plain_text  = decryptor.update(cipher_text) + decryptor.finalize()
        
        # Trim the padding (if any)
        idx = plain_text.rfind(b'\x80')
        if idx == -1:
            raise ValueError("Invalid padding bytes: marker 0x80 not found")


        return plain_text[:idx]


def send_cipher_text(isd:SmartCard, dh:DiffieHellman):
    input_data = '0102030405060708090a0b0c0d0e0f'
    # encrypting plain text
    cipher_text = dh.aes_encrypt(input_data)
    # passing over cipher text
    resp, _,_ = isd.transmit('8004 0100' + lv_hex(cipher_text), 0x90, 0x00, cmd_name='Decrypt data')
    # plain_text = dh.aes_decrypt(resp)
    
    # conparison
    print(f'input data: {input_data}')
    print(f'plain text: {bytes_to_hex(resp)}')


def send_plain_text(isd:SmartCard, dh:DiffieHellman):
    # passing over plain text
    input_data = '0102030405060708090a0b0c0d0e0f'
    resp, _,_ = isd.transmit('8004 0200' + lv_hex(input_data), 0x90, 0x00, cmd_name='Encrypt data')
    # decrypting result
    plain_text = dh.aes_decrypt(resp)
    
    # conparison
    print(f'input data: {input_data}')
    print(f'plain text: {bytes_to_hex(plain_text)}')


def main():
    dh = DiffieHellman()

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu)
        isd.transmit('00a4 0400' + lv_hex('A0000000837365636D7367'), 0x90, 0x00, cmd_name='Select Secure Message applet')
        resp, _,_ = isd.transmit('8002 0000' + lv_hex(dh.pub_key), 0x90, 0x00, cmd_name='Public key exchange between Host and Card')

        shared_secret = dh.generate_shared_secret(resp)
        print(f'Shared secret: {bytes_to_hex(shared_secret)}')
        dh.init_aes_cipher(shared_secret[0:16])

        send_cipher_text(isd, dh)
        send_plain_text(isd, dh)

main()