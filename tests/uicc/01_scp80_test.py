
from fun_gp.utils import hex_to_bytes, bytes_to_hex, lv
from fun_gp import UICC, SCP80Params

known_readers = ['ACS ACR39U ICC Reader 0']
# iccid         = '8970199 0123456789 1'
card_deck_path = '../../resources/known-simcards.json'

text     = 'длина этой строки 29 символов'
test_msg = lv('08' + bytes_to_hex(text.encode('utf-16-be')))

def main():
    uicc = UICC(known_readers, card_deck_path)

    uicc.terminal_profile()
    
    params = SCP80Params('1622', 0x09, '746172')
    uicc.apdu_scp80(test_msg, params, 0x9000, 'DISPLAY TEXT')

main()