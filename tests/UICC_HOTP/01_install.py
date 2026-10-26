from fun_gp import Reader, SmartCard, CCM, UICC, InstallParams, \
                    SIMParams, UICCParams, SCP80, SCP80Params,\
                    RESOURCES_DIR

from fun_gp import lv_hex, encode_bcd
import time

card_deck_path = RESOURCES_DIR / "sysmocom-cards.json"

# https://github.com/void-deref/UICC-HOTP
path_to_applet = RESOURCES_DIR / 'UICC_HOTP.cap'
sys_params     = UICCParams(msl='16',  tar='46554E', text_length='14', menu_entries='010100')
install_params = InstallParams(
    app_params =
        '01020304050607000010203040506070 01020304050607000010203040506070\
         01020304050607000010203040506070 01020304050607000010203040506070',
    sim_params=sys_params
    )


def main():
    with Reader() as reader:
        scp80 = SCP80(card_deck_path, reader.plain_apdu)
        scp80.set_params(SCP80Params(spi='0621', tar='000000', kic=0x05, kid=0x05))
        uicc  = UICC(reader.plain_apdu, scp80)
        uicc.terminal_profile()

        startTime = time.time()
        uicc.install_app_scp80(path_to_applet, install_params)
        duration = time.time() - startTime
        
        print(f'duration: {str(round(duration, 2))}\n')


main()