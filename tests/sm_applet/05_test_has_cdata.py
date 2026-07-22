from fun_gp import Reader, SmartCard, lv_hex, bytes_to_hex
from ECDH import DiffieHellman

def main():
    dh = DiffieHellman()

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu)
        isd.transmit('00a4 0400' + lv_hex('A0000000837365636D7367'), 0x90, 0x00, cmd_name='Select Secure Message applet')

        card_pub_key,_,_ = isd.transmit('8002 0000', 0x67, 0x00, cmd_name='Public key exchange between Host and Card')

main()