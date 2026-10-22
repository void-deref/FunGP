from fun_gp import Reader, UICC, SCP80, SCP80Params, RESOURCES_DIR, MenuSelection
from fun_gp import bytes_to_hex, hex_to_bytes, lv_list
import time

card_deck_path = RESOURCES_DIR / "sysmocom-cards.json"

def event_routine(uicc:UICC, event:MenuSelection, add_info_select:list[int], add_info_time:list[int], cmd_name:str=''):
    resp, sw1, sw2 = uicc.envelope(event[0:], cmd_name=f'[EVENT DOWNLOAD] {cmd_name}')
    while sw1 == 0x91:
            uicc.gen_res.add_info = []
            resp, _, _ = uicc.fetch(sw2)
            cmd_type   = uicc.parser.parse(resp)
            
            if cmd_type[3] == 0x26: # DATE/TIME
                uicc.gen_res.add_info = add_info_time
            elif cmd_type[3] == 0x24: # SELECT ITEM
                uicc.gen_res.add_info = add_info_select
                
            _, sw1, sw2   = uicc.terminal_response(cmd_type, uicc.gen_res)
    return resp, sw1, sw2


def event_menu_selection(uicc:UICC, menu_id:int, item_id:int):
    event    = MenuSelection(menu_id)
    add_info_select = [0x10, 0x01, item_id]
    add_info_time   = hex_to_bytes('26 07 62012232859501')
    _,_,_ = event_routine(uicc, event, add_info_select, add_info_time, cmd_name='SELECT HOTP option')


def main():
    with Reader() as reader:
        scp80 = SCP80(card_deck_path, reader.plain_apdu)
        scp80.set_params(SCP80Params(spi='0621', tar='46554E', kic=0x05, kid=0x05))
        
        uicc  = UICC(reader.plain_apdu, scp80)
        uicc.terminal_profile()
        event_menu_selection(uicc, 0x80, 0x01)

main()