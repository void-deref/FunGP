from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fun_gp import hex_to_bytes


class DiffieHellman:
    def __init__(self):

        self.priv_key = ec.generate_private_key(ec.SECP256K1())
        self.pub_key  = self.priv_key.public_key().public_bytes(
                            serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint
                        ).hex()

        self.cipher = None
        self.iv = bytearray(16)


    def generate_shared_secret(self, raw_bytes:bytes|list[int]) -> list[int]:

        if isinstance(raw_bytes, list):
            raw_bytes = bytes(raw_bytes)

        print('Generating Host\'s shared secret... ', end='')
        card_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw_bytes)
        shared_secret = self.priv_key.exchange(ec.ECDH(), card_public_key)
        print('Done.')
        return list(shared_secret)


    def init_aes_cipher(self, shared_secret:bytes|list[int]):
        if isinstance(shared_secret, list):
            shared_secret = bytes(shared_secret)
        
        print('Initializing Host\'s AES cipher... ', end='')
        self.cipher = Cipher(algorithms.AES(shared_secret), modes.CBC(self.iv))
        print('Done.')
    

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


    def aes_decrypt(self, cipher_text:bytes|list[int]) -> list[int]:
        cipher_text = bytes(cipher_text)
        decryptor   = self.cipher.decryptor()
        plain_text  = decryptor.update(cipher_text) + decryptor.finalize()
        
        # Trim the padding (if any)
        idx = plain_text.rfind(b'\x80')
        if idx == -1:
            raise ValueError("Invalid padding bytes: marker 0x80 not found")


        return list(plain_text[:idx])