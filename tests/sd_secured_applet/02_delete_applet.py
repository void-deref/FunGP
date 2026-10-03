from fun_gp import Reader, SmartCard, SecurityLevel, SCP02, CCM

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']

# https://github.com/void-deref/ISD_secured_applet

def install_applet():
    sec_level = SecurityLevel.C_MAC
    with Reader() as reader:
        isd = SmartCard(plain_apdu=reader.plain_apdu, scp02=SCP02(isd_keyset), ccm=CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth(security_level=sec_level)
        
        isd.uninstall_app_scp02('A000000001')
        isd.uninstall_app_scp02('A000000081')
        isd.uninstall_app_scp02('A000000082')
        isd.uninstall_app_scp02('A000000083') # sm_applet

        isd.uninstall_app_scp02('A000000084') # simple_applet
        isd.uninstall_app_scp02('A0000000856C69627574696C73') # libutils
        isd.uninstall_app_scp02('A000000086') # sd_secured_applet

install_applet()