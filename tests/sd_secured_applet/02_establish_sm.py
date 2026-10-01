from fun_gp import Reader, SecurityLevel, SmartCard, SCP02, CCM, lv_hex, APPLET_PATH

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
applet_cap_path = APPLET_PATH / 'sd_secured_applet.cap'


def store_secret(isd:SmartCard, msg:str, security_level:SecurityLevel, coding:str='latin-1'):
    cdata = msg.encode(coding)
    isd.transmit('8020 0000' + lv_hex(lv_hex(cdata)), 0x90, 0x00, 'store the secret', security_level=security_level)
    
    print(f"the secret '{msg}' has been stored\n")


def fetch_secret(isd:SmartCard, security_level:SecurityLevel, coding:str='latin-1'):
    resp, _,_ = isd.transmit('8022 0000', 0x90, 0x00, 'get the secret', security_level=security_level)

    resp = bytes(resp)
    resp = resp.decode(coding)

    print(f"The secret is: '{resp}'\n")


def sd_based_security():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex('A000000086 53442053656375726564'), 0x90, 0x00, cmd_name='Select sd_secured_applet')
        isd.mutual_auth(security_level=SecurityLevel.C_DECRYPTION)

        store_secret(isd, 'A little secret', SecurityLevel.C_DECRYPTION)
        fetch_secret(isd, SecurityLevel.C_DECRYPTION)
        store_secret(isd, 'сокрытие', SecurityLevel.C_DECRYPTION, coding='utf-16-be')
        fetch_secret(isd, SecurityLevel.C_DECRYPTION, coding='utf-16-be')

        

sd_based_security()