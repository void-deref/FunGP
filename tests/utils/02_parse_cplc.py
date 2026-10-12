from fun_gp import Reader, SmartCard, lv_hex, parse_card_resources


def main():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu)
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        resp ,_,_ = isd.transmit('80CA 9F7F', 0x90, 0x00, 'get CPLC')

main()