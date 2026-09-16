from fun_gp import Reader, SmartCard, SCP02, CCM, lv_hex


isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']

data_list  = {
    ('80CA 2F00 02 5C00', 0x90, 0x00, 'GET DATA: list of applications'),
    ('80CA 00E0 00',      0x90, 0x00, 'GET DATA: Key info template'),
    ('80CA 0042 00',      0x6a, 0x88, 'GET DATA: Issuer Identification Number'),
    ('80CA 0045 00',      0x6a, 0x88, 'GET DATA: Card or Security Domain Image Number'),
    ('80CA 5F50 00',      0x6a, 0x88, 'GET DATA: Security Domain Manager URL'),
    ('80CA 00CF 00',      0x90, 0x00, 'GET DATA: User Key Diversification Data'),
    ('80CA 00E0 00',      0x90, 0x00, 'GET DATA: Key info template'),
    ('80CA 00C1 00',      0x90, 0x00, 'GET DATA: Sequence Counter of the Default Key Set'),
    ('80CA 00C2 00',      0x90, 0x00, 'GET DATA: Confirmation Counter'),
    ('80CA 0066 00',      0x90, 0x00, 'GET DATA: Card or Security Domain Recognition Data'),
    ('80CA 0067 00',      0x90, 0x00, 'GET DATA: Card capability information'),
}

def get_data_scp02():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, scp02=SCP02(isd_keyset), ccm=CCM())
        isd.transmit('00A4 0400' + lv_hex('a000000151000000'), 0x90, 0x00, 'SELECT: isd')
        isd.mutual_auth()
        for cmd, sw1, sw2, name in data_list:
            isd.transmit(cmd=cmd, exp_sw1=sw1, exp_sw2=sw2, cmd_name=name, is_secured=True)


def get_data_plain():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu)
        isd.transmit('00A4 0400' + lv_hex('a000000151000000'), 0x90, 0x00, 'SELECT: isd')

        for cmd, sw1, sw2, name in data_list:
            isd.transmit(cmd=cmd, exp_sw1=sw1, exp_sw2=sw2, cmd_name=name, is_secured=False)

def main():
    over_scp02 = True

    if over_scp02:
        get_data_scp02()
    else:
        get_data_plain()

main()