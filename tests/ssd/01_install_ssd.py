from fun_gp import Reader, SmartCard, SCP02, CCM, InstallParams, lv_list, lv_hex

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']

def install_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()

        # 84E6 0C00 35 07A000000151535008A0000001515350410EA0000001515350416D79205353440180     09 C907 81020255 820120 00DD B20088B0E4A257 00
        # 80E6 0C00 2e 07A000000151535008A0000001515350410EA0000001515350416D792053534403800000 08 C90481020255EF0000
        for_install = isd._ccm.make_cmd_install_for_install(
            load_file_aid  = 'A0000001515350',
            module_aid     = 'A000000151535041',
            instance_aid   = 'A0000001515350416D7920535344', # my SSD
            install_params = InstallParams(
                # The absence of 81 tag was the reason I had been running into SW 6A80
                '81020255' # SCP02, i=55
                # '820120'   # accept extradition from ISD
            ),
            privileges = lv_list('80'),
        )

        print(for_install)
    
        isd.transmit(
            for_install,
            0x90, 0x00,
            'INSTALL[for install and make selectable]',
            is_secured=True
        )

install_applet()