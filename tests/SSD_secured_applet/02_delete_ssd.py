from fun_gp import Reader, SmartCard, SCP02, CCM, lv_hex

from params import isd_keyset, ssd_keyset, ssd_aid, isd_aid


def uninstall_applet():

    # For the demostration purpose only: 'my SSD' hasn't application deletion privilege.
    with Reader() as reader:
        my_SSD = SmartCard(plain_apdu=reader.plain_apdu, scp02=SCP02(ssd_keyset), ccm=CCM())
        my_SSD.transmit('00a4 0400' + lv_hex(ssd_aid), 0x90, 0x00, 'Select my SSD')
        my_SSD.mutual_auth()
        my_SSD.uninstall_app_scp02('A000000086', exp_sw1=0x69, exp_sw2=0x85) # isd_secured_applet

    with Reader() as reader:
        isd = SmartCard(plain_apdu=reader.plain_apdu, scp02=SCP02(isd_keyset), ccm=CCM())
        isd.transmit('00a4 0400' + lv_hex(isd_aid), 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()
        isd.uninstall_app_scp02('A000000086', exp_sw1=0x90, exp_sw2=0x00) # isd_secured_applet
        isd.uninstall_app_scp02(ssd_aid, exp_sw1=0x90, exp_sw2=0x00) # 'my SSD' Supplementary Security Domain

uninstall_applet()