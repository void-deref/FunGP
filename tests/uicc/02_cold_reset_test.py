
from fun_gp.utils import decode_bcd, bytes_to_hex, lv
from fun_gp import UICC

known_readers = ['ACS ACR39U ICC Reader 0']
# iccid         = '8970199 0123456789 1'
tar_value     = '74 61 72'
card_deck_path = '../../resources/known-simcards.json'





def main():
    uicc = UICC(known_readers, card_deck_path)

    uicc.apdu_plain('00A4 0000 02 3F00', expected_sw=0x9000)
    uicc.apdu_plain('00A4 000C 02 2FE2', expected_sw=0x9000, name='Select EF-ICCID')
    id = uicc.apdu_plain('00B0 0000 00', expected_sw=0x9000)
    
    id = decode_bcd(id[0:-2])
    print(f'Card\'s ICCID: {id}')

    uicc.cold_reset()
    uicc.warm_reset()

main()

