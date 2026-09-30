from fun_gp import Reader, SmartCard, SCP02, CCM

from params import isd_keyset, ssd_aid


def install_applet():
    with Reader() as reader:
        isd = SmartCard(plain_apdu=reader.plain_apdu, scp02=SCP02(isd_keyset), ccm=CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()
        isd.uninstall_app_scp02(ssd_aid)

install_applet()