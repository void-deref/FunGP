
from fun_gp.utils import hex_to_bytes, bytes_to_hex, lv
from fun_gp import UICC

known_readers = ['ACS ACR39U ICC Reader 0']
iccid         = '8970199 0123456789 1'
tar_value     = '74 61 72'
card_deck_path = '../../resources/known-simcards.json'

text     = 'длина этой строки 29 символов'
test_msg = lv('08' + bytes_to_hex(text.encode('utf-16-be')))


def main():
    uicc = UICC(known_readers, iccid, card_deck_path)
    uicc.terminal_profile()
    uicc.apdu_scp80(test_msg, spi='1622', kic=0xa9, kid=0xa9, tar=tar_value)

main()

