from fun_gp import Reader, SecurityLevel, SmartCard, SCP02, CCM, hex_to_bytes, lv_hex
from params import ssd_keyset


def store_secret(my_SSD:SmartCard, msg:bytes, coding:str='latin-1'):
    cdata = msg
    my_SSD.transmit('8020 0000' + lv_hex(cdata), 0x90, 0x00, 'Store the AES key')
    print(f"Secret key:    set\n")


def initialize_applet():
    sec_level   = SecurityLevel.C_DECRYPTION
    aes_16_key = hex_to_bytes("0102030405060708 0102030405060708")

    with Reader() as reader:
        my_SSD = SmartCard(reader.plain_apdu, SCP02(ssd_keyset), CCM())
        my_SSD.transmit('00a4 0400' + lv_hex('A000000086 4953442053656375726564'), 0x90, 0x00, cmd_name='Select ISD secured applet')
        my_SSD.mutual_auth(security_level=sec_level)

        store_secret(my_SSD, aes_16_key)

initialize_applet()