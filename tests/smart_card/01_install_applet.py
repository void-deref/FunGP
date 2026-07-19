from fun_gp import Reader, SmartCard, SCP02, CCM, InstallParams, APPLET_PATH

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
cap_path = APPLET_PATH / 'SimpleApplet.cap'

def install_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.mutual_auth()
        isd.install_app_scp02(cap_path, InstallParams(), 0x90, 0x00)

install_applet()