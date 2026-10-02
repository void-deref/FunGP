from fun_gp import Reader, SecurityLevel, SmartCard, SCP02, CCM, bytes_to_hex, lv_hex, APPLET_PATH

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
applet_cap_path = APPLET_PATH / 'sd_secured_applet.cap'


def store_secret(isd:SmartCard, msg:str, security_level:SecurityLevel, coding:str='latin-1'):
    cdata = msg.encode(coding)
    isd.transmit('8020 0000' + lv_hex(lv_hex(cdata)), 0x90, 0x00, 'store the secret', security_level=security_level)
    
    print(f"the secret '{msg}' has been stored\n")


def fetch_secret(isd:SmartCard, security_level:SecurityLevel, coding:str='latin-1'):
    resp, _,_ = isd.transmit('8022 0000', 0x90, 0x00, 'get the secret', security_level=security_level)

    mac_str = ''
    if (security_level & SecurityLevel.R_MAC):
        mac   = resp[-8:]
        resp = resp[0:-8]
        mac_str = f"\nR_MAC: {bytes_to_hex(mac)}"

    resp = bytes(resp)
    resp = resp.decode(coding)

    print(f"The secret is: '{resp}'{mac_str}\n")


def sd_based_security():
    sec_level = SecurityLevel.C_DECRYPTION

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex('A000000086 53442053656375726564'), 0x90, 0x00, cmd_name='Select ISD secured applet')
        isd.mutual_auth(security_level=sec_level)

        store_secret(isd, 'A little secret', sec_level)
        fetch_secret(isd, sec_level)

        store_secret(isd, 'сокрытие', sec_level, coding='utf-16-be')
        fetch_secret(isd, sec_level, coding='utf-16-be')

        

sd_based_security()