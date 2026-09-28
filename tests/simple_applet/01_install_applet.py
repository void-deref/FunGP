from fun_gp import Reader, SmartCard, SCP02, CCM, InstallParams, APPLET_PATH

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
applet_cap_path = APPLET_PATH / 'SimpleApplet.cap'
lib_cap_path    = APPLET_PATH / 'fun.libutils.cap'

def install_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()
        isd.install_lib_scp02(lib_cap_path, 0x90, 0x00)
        isd.install_app_scp02(applet_cap_path, InstallParams(), exp_sw1=0x90, exp_sw2=0x00)

install_applet()