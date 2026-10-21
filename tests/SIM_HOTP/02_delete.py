from fun_gp import Reader, UICC, SCP80, SCP80Params, RESOURCES_DIR

card_deck_path = RESOURCES_DIR / "sysmocom-cards.json"

applets_dict = {
    'A000000087':'SIM HOTP'
}

def main():
    with Reader() as reader:
        scp80 = SCP80(card_deck_path, reader.plain_apdu)
        scp80.set_params(SCP80Params(spi='0621', tar='000000', kic=0x05, kid=0x05))
        
        uicc = UICC(reader.plain_apdu, scp80)
        uicc.terminal_profile()

        for applet_aid, pkg_name in applets_dict.items():
            print(f'\nApplet: {pkg_name}')
            uicc.remove_app_scp80(applet_aid)
    
main()