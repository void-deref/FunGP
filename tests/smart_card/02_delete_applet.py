from fun_gp import Reader, SmartCard, SCP02, CCM

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']


def install_applet():
    with Reader() as reader:
        isd = SmartCard(plain_apdu=reader.plain_apdu, scp02=SCP02(isd_keyset), ccm=CCM())
        isd.mutual_auth()
        isd.uninstall_app_scp02('A000000082')

install_applet()