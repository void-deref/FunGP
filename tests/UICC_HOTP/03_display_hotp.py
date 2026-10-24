from fun_gp import Reader, UICC, SCP80, SCP80Params, RESOURCES_DIR, MenuSelection
from fun_gp import bytes_to_hex, hex_to_bytes, encode_bcd
from datetime import datetime

card_deck_path = RESOURCES_DIR / "sysmocom-cards.json"


def event_menu_selection(uicc:UICC, menu_id:int, item_id:int):
    event    = MenuSelection(menu_id)
    add_info_select = [0x10, 0x01, item_id]

    curr_time = datetime.now()
    curr_time = encode_bcd(curr_time.strftime("%y%m%d%H%M%S"))
    add_info_date_time = hex_to_bytes(f'26 07 {curr_time}21')

    resp, sw1, sw2 = uicc.envelope(event[0:], cmd_name=f'[EVENT DOWNLOAD] SELECT HOTP option')
    while sw1 == 0x91:
        uicc.gen_res.add_info = []
        resp, _, _ = uicc.fetch(sw2)
        cmd_type   = uicc.parser.parse(resp)
        
        if cmd_type[3] == 0x26: # DATE/TIME
            uicc.gen_res.add_info = add_info_date_time
        elif cmd_type[3] == 0x24: # SELECT ITEM
            uicc.gen_res.add_info = add_info_select
            
        _, sw1, sw2   = uicc.terminal_response(cmd_type, uicc.gen_res)

    print(f"\ncurrent date: {curr_time}\n")

def main():
    with Reader() as reader:
        scp80 = SCP80(card_deck_path, reader.plain_apdu)
        scp80.set_params(SCP80Params(spi='0621', tar='46554E', kic=0x05, kid=0x05))
        
        uicc  = UICC(reader.plain_apdu, scp80)
        uicc.terminal_profile()
        event_menu_selection(uicc, 0x80, 0x01)

main()