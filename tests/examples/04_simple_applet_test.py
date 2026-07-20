from fun_gp import Reader, SmartCard, lv_hex


def main():

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu)
        isd.transmit(cmd='00A4 0400' + lv_hex('A000000082'), exp_sw1=0x90, exp_sw2=0x00, cmd_name='Select Simple Applet', is_secured=False)

        array = list(range(255, 0, -1))
        isd.transmit('0012 0000' + lv_hex('0504 0302 0100'), 0x90, 0x00, 'XOR input')

        array = list(range(128, 0, -1))
        isd.transmit('0014 0000' + lv_hex(array), 0x90, 0x00, 'Bubble sort 128-0')

        array = list(range(64, 0, -1))
        isd.transmit('0014 0000' + lv_hex(array), 0x90, 0x00, cmd_name='Bubble sort 64-0')

        array = list(range(32, 0, -1))
        isd.transmit('0014 0000' + lv_hex(array), 0x90, 0x00, cmd_name='Bubble sort 32-0')

main()
