from fun_gp import Reader, SecurityLevel, SmartCard, SCP02, CCM, bytes_to_hex, hex_to_bytes, lv_hex, APPLET_PATH
from ECDH import DiffieHellman

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']

# https://github.com/void-deref/ISD_secured_applet
applet_cap_path = APPLET_PATH / 'sd_secured_applet.cap'


def store_secret(isd:SmartCard, msg:bytes, coding:str='latin-1'):
    cdata = msg
    isd.transmit('8020 0000' + lv_hex(cdata), 0x90, 0x00, 'Store the AES key')
    
    print(f"Secret key:    set\n")


def set_peronal_info(isd:SmartCard, coding:str='latin-1'):
    perso_data = "11" + lv_hex("Исламов".encode(coding))\
               + "12" + lv_hex("Тельман".encode(coding)) \
               + "13" + lv_hex("Исламович".encode(coding))
    
    duties     = "14" + lv_hex("Департамент грёз и бесконечных возможностей".encode(coding)) \
               + "15" + lv_hex("Отдел по непонятным вопросам".encode(coding)) \
               + "16" + lv_hex("Суетолог".encode(coding))

    cdata = lv_hex(perso_data + duties)
    _, _,_ = isd.transmit('8024 0000' + cdata, 0x90, 0x00, 'Set personal data')

    print(f"Personal data: set\n")


def initialize_applet():
    sec_level   = SecurityLevel.C_DECRYPTION
    aes_16_key = hex_to_bytes("0102030405060708 0102030405060708")
    coding      = 'utf-16-be'

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex('A000000086 53442053656375726564'), 0x90, 0x00, cmd_name='Select ISD secured applet')
        isd.mutual_auth(security_level=sec_level)

        store_secret(isd, aes_16_key)
        set_peronal_info(isd, coding)

initialize_applet()