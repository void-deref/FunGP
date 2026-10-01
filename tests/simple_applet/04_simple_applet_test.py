from fun_gp import Reader, SmartCard, SecurityLevel, lv_hex


def main():

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu)
        isd.transmit(cmd='00A4 0400' + lv_hex('A00000008453696D706C65417070'), exp_sw1=0x90, exp_sw2=0x00, cmd_name='Select Simple Applet', security_level=SecurityLevel.C_MAC)

        isd.transmit('8012 0000' + lv_hex('00 01 02 03 04 05'), 0x90, 0x00, 'XOR input')

        array = list(range(128, 0, -1))
        isd.transmit('8014 0000' + lv_hex(array), 0x90, 0x00, 'Bubble sort 128-0')

        isd.transmit('8016 0000' + lv_hex('2143f5'), 0x90, 0x00, 'parse BCD')
        
        # array = list(range(64, 0, -1))
        # isd.transmit('8014 0000' + lv_hex(array), 0x90, 0x00, cmd_name='Bubble sort 64-0')

        # array = list(range(32, 0, -1))
        # isd.transmit('8014 0000' + lv_hex(array), 0x90, 0x00, cmd_name='Bubble sort 32-0')
        

main()
