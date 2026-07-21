from fun_gp import Reader, SmartCard, SCP02, CCM, InstallParams, APPLET_PATH

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
cap_path = APPLET_PATH / 'SM_applet.cap'

def install_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()

        install_params = InstallParams(
            app_params='000102030405060708090A0B0C0D0E0F 101112131415161718191A1B1C1D1E1F'
        )
        isd.install_app_scp02(cap_path, install_params, 0x90, 0x00)

install_applet()