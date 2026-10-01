from fun_gp import Reader, SmartCard, SCP02, CCM, lv_hex, APPLET_PATH

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
applet_cap_path = APPLET_PATH / 'sd_secured_applet.cap'

def store_secret(isd:SmartCard, msg:str, coding:str='latin-1'):
    msg = msg.encode(coding)
    isd.transmit('8020 0000' + lv_hex(lv_hex(msg)), 0x90, 0x00, 'store the secret', is_secured=True)
    resp, _,_ = isd.transmit('8022 0000', 0x90, 0x00, 'get the secret', is_secured=True)
    
    resp = bytes(resp)
    resp = resp.decode(coding)

    print(f'secret: {resp}')


def install_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex('A000000086 53442053656375726564'), 0x90, 0x00, cmd_name='Select sd_secured_applet')
        isd.mutual_auth()

        store_secret(isd, 'A little secret')
        store_secret(isd, 'Секретик', coding='utf-16-be')

        

install_applet()