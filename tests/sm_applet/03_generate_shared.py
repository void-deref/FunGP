from fun_gp import Reader, SmartCard, lv_hex, bytes_to_hex
from ECDH import DiffieHellman

def send_cipher_text(isd:SmartCard, dh:DiffieHellman):
    input_data = '0102030405060708090a0b0c0d0e0f'
    # encrypting plain text
    cipher_text = dh.aes_encrypt(input_data)
    # passing over cipher text
    resp, _,_ = isd.transmit('8004 0100' + lv_hex(cipher_text), 0x90, 0x00, cmd_name='Decrypt data')
    # plain_text = dh.aes_decrypt(resp)
    
    # conparison
    print(f'input data: {input_data}\nplain text: {bytes_to_hex(resp)}')
    assert input_data.lower() == bytes_to_hex(resp).lower(), f"Assertion failed: expected {input_data}, got: {bytes_to_hex(resp)}"


def send_plain_text(isd:SmartCard, dh:DiffieHellman):
    # passing over plain text
    input_data = '0102030405060708090a0b0c0d0e0f'
    resp, _,_ = isd.transmit('8004 0200' + lv_hex(input_data), 0x90, 0x00, cmd_name='Encrypt data')
    # decrypting result
    plain_text = dh.aes_decrypt(resp)
    
    # conparison
    print(f'input data: {input_data}\nplain text: {bytes_to_hex(plain_text)}')
    assert input_data.lower() == bytes_to_hex(plain_text).lower(), f"Assertion failed: expected {input_data}, got: {bytes_to_hex(plain_text)}"


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