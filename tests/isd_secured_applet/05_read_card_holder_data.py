from fun_gp import Reader, SmartCard, SCP02, CCM, bytes_to_hex, hex_to_bytes, lv_hex, APPLET_PATH
from AESHandler import AESHandler

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']

# https://github.com/void-deref/ISD_secured_applet
applet_cap_path = APPLET_PATH / 'sd_secured_applet.cap'

def get_personal_info(isd:SmartCard, dh:AESHandler, coding:str='latin-1'):

    resp, _,_ = isd.transmit('0022 0000', 0x90, 0x00, 'Get personal data')
    resp      = dh.aes_decrypt(resp)
    
    total_len = len(resp)
    offset = 0
    length = 0

    tags = {0x11:"Фамилия",    0x12:"Имя",   0x13:"Отчество",
            0x14:"Департамент",0x15:"Отдел", 0x16:"Должность",
            0x17:"Действителен до"}
    
    print('\n\t\t\t***ДАННЫЕ ДЕРЖАТЕЛЯ КАРТЫ***')
    while offset < total_len:
        tag     = resp[offset]
        offset += 1
        length  = resp[offset]
        offset += 1

        field   = bytes(resp[offset:offset + length]).decode(coding)
        print(f"\t| {tags.get(tag, 'Unknow field'):<15} | {field:<32} |")
        offset += length
    print('\n')


def read_card_holder_info():
    aes_16_key = hex_to_bytes("0102030405060708 0102030405060708")
    coding      = 'utf-16-be'

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex('A000000086 4953442053656375726564'), 0x90, 0x00, cmd_name='Select ISD secured applet')

        dh = AESHandler()
        dh.init_aes_cipher(aes_16_key[0:16])
        get_personal_info(isd, dh, coding=coding)


read_card_holder_info()