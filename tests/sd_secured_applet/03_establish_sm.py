from fun_gp import Reader, SecurityLevel, SmartCard, SCP02, CCM, bytes_to_hex, lv_hex, APPLET_PATH
import os

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
applet_cap_path = APPLET_PATH / 'sd_secured_applet.cap'


def store_secret(isd:SmartCard, msg:str, security_level:SecurityLevel, coding:str='latin-1'):
    cdata = msg.encode(coding)
    isd.transmit('8020 0000' + lv_hex(lv_hex(cdata)), 0x90, 0x00, 'store the secret', security_level=security_level)
    
    print(f"the secret '{msg}' has been stored\n")


def set_peronal_info(isd:SmartCard, security_level:SecurityLevel, coding:str='latin-1'):
    perso_data = "11" + lv_hex("Исламов".encode(coding))\
               + "12" + lv_hex("Тельман".encode(coding)) \
               + "13" + lv_hex("Исламович".encode(coding))
    
    duties     = "14" + lv_hex("Департамент грез и бесконечных возможностей".encode(coding)) \
               + "15" + lv_hex("Отдел по непонятным вопросам".encode(coding)) \
               + "16" + lv_hex("Суетолог".encode(coding))

    cdata = lv_hex(perso_data + duties)
    _, _,_ = isd.transmit('8024 0000' + cdata, 0x90, 0x00, 'Set personal data', security_level=security_level)
    

def get_personal_info(isd:SmartCard, security_level:SecurityLevel, coding:str='latin-1'):
    resp, _,_ = isd.transmit('8022 0000', 0x90, 0x00, 'Get personal data', security_level=security_level)

    total_len = len(resp)
    offset = 0
    length = 0

    tags = {
        0x11:"Surname",    0x12:"Name",     0x13:"Middle/Patronymic name",
        0x14:"Department", 0x15:"Division", 0x16:"Position"
    }

    print('***ДАННЫЕ ДЕРЖАТЕЛЯ КАРТЫ***')
    while offset < total_len:
        tag     = resp[offset]
        offset += 1
        length  = resp[offset]
        offset += 1
        field   = bytes(resp[offset:offset + length]).decode(coding)
        print(f"\t| {tags.get(tag, 'Unknow field'):<25} | {field:<30} |")
        offset += length
    print('\n')


def sd_based_security():
    sec_level = SecurityLevel.C_MAC
    coding = 'utf-16-be'

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex('A000000086 53442053656375726564'), 0x90, 0x00, cmd_name='Select ISD secured applet')
        isd.mutual_auth(security_level=sec_level)

        # set_peronal_info(isd, sec_level, coding)
        get_personal_info(isd, sec_level, coding)
        # store_secret(isd, "Thirty two bytes long *HMAC* key", sec_level)
        # fetch_secret(isd, sec_level)

        # store_secret(isd, 'сокрытие', sec_level, coding='utf-16-be')
        # fetch_secret(isd, sec_level, coding='utf-16-be')

        

sd_based_security()