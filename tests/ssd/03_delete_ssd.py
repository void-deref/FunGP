from fun_gp import Reader, SmartCard, SCP02, CCM

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']


ssd_pkg = 'A000000151535041'
ssd_aid = ssd_pkg + '6D7920535344'


def install_applet():
    with Reader() as reader:
        isd = SmartCard(plain_apdu=reader.plain_apdu, scp02=SCP02(isd_keyset), ccm=CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()
        isd.uninstall_app_scp02(ssd_aid)

install_applet()