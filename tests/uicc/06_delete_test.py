from fun_gp import UICC

from fun_gp.utils import hex_to_bytes, bytes_to_hex, lv

known_readers = ['ACS ACR39U ICC Reader 0']
iccid         = '89 701 99 0123456789 1'
tar_value     = '746172'

text     = 'длина этой строки 28 символа'
text     = lv('08' + bytes_to_hex(text.encode('utf-16-be')))
test_mds = '11221122334455667788AE0001031122330D' + text


def main():
    uicc = UICC(known_readers, iccid)
    uicc.terminal_profile()
    uicc.apdu_scp80(test_mds, spi='1622', kic=0x09, kid=0x09, tar=tar_value)

main()

