from fun_gp import Reader, SmartCard, lv_hex, bytes_to_hex
from ECDH import DiffieHellman

def fetch_secret(isd:SmartCard, dh:DiffieHellman):
    resp,_,_ = isd.transmit('8006 0000 20', 0x90, 0x00, cmd_name='Fetch the secret')
    plain_text = dh.aes_decrypt(resp)
    print(f'Card\'s secret: {bytes_to_hex(plain_text)}')


def store_secret(isd:SmartCard, dh:DiffieHellman):
    # cdata = '0000000000000000000000000000000000000000000000000000000000000000'
    cdata = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
    cipher_text = dh.aes_encrypt(cdata)
    _,_,_ = isd.transmit('8008 0000' + lv_hex(cipher_text), 0x90, 0x00, cmd_name='Update the secret')


def main():
    dh = DiffieHellman()

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu)
        isd.transmit('00a4 0400' + lv_hex('A0000000837365636D7367'), 0x90, 0x00, cmd_name='Select Secure Message applet')
        card_pub_key,_,_ = isd.transmit('8002 0000' + lv_hex(dh.pub_key), 0x90, 0x00, cmd_name='Public key exchange between Host and Card')
        
        shared_secret = dh.generate_shared_secret(card_pub_key)

        dh.init_aes_cipher(shared_secret[0:16])

        fetch_secret(isd, dh)
        store_secret(isd, dh)
        fetch_secret(isd, dh)
        

main()