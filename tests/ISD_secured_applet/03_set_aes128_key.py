from fun_gp import Reader, SecurityLevel, SmartCard, SCP02, CCM, hex_to_bytes, lv_hex

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']


def store_secret(isd:SmartCard, msg:bytes, coding:str='latin-1'):
    cdata = msg
    isd.transmit('8020 0000' + lv_hex(cdata), 0x90, 0x00, 'Store the AES key')
    print(f"Secret key:    set\n")


def initialize_applet():
    sec_level   = SecurityLevel.C_DECRYPTION
    aes_16_key = hex_to_bytes("0102030405060708 0102030405060708")

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex('A000000086 4953442053656375726564'), 0x90, 0x00, cmd_name='Select ISD secured applet')
        isd.mutual_auth(security_level=sec_level)

        store_secret(isd, aes_16_key)

initialize_applet()