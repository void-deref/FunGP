from fun_gp import Reader, SmartCard, SCP02, CCM, SecurityLevel, lv_hex
from params import isd_keyset, ssd_keyset, ssd_aid, isd_aid


def uninstall_applet():
    with Reader() as reader:
        isd = SmartCard(plain_apdu=reader.plain_apdu, scp02=SCP02(isd_keyset), ccm=CCM())
        isd.transmit('00a4 0400' + lv_hex(isd_aid), 0x90, 0x00, 'Select ISD')
        isd.mutual_auth(security_level=SecurityLevel.C_MAC)
        isd.uninstall_app_scp02('A000000086', exp_sw1=0x90, exp_sw2=0x00) # isd_secured_applet
        isd.uninstall_app_scp02(ssd_aid, exp_sw1=0x90, exp_sw2=0x00) # 'my SSD' Supplementary Security Domain

uninstall_applet()