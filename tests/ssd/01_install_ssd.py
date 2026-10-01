from fun_gp import Reader, SmartCard, SCP02, CCM, InstallParams, SecurityLevel, lv_list, lv_hex
from params import isd_keyset, ssd_pkg, ssd_aid


def install_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()

        for_install = isd._ccm.make_cmd_install_for_install(
            load_file_aid  = 'A0000001515350',
            module_aid     = ssd_pkg,
            instance_aid   = ssd_aid, # my SSD
            install_params = InstallParams(
                # GP CIC, 3.3.1.3:
                # Tag '81' may be omitted only if the card supports only a single
                # SCP (i.e. obvious default value) or if the card otherwise supports a
                # default value or specific policy defined by the Card Issuer,
                # which remains out of scope of this document.
                '8102 0255' # SCP02, i=55
                '8201 20'   # accept extradition from ISD
            ),
            # the simulator accepts 800000, while real cards fail with SW 6A80.
            privileges = lv_list('80'),
        )

        isd.transmit(
            for_install,
            0x90, 0x00,
            'INSTALL[for install and make selectable]',
            security_level=SecurityLevel.C_MAC
        )

install_applet()