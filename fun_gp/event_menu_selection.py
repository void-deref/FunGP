from fun_gp import EnumDeviceID, bytes_to_hex

class MenuSelection:
    def __init__(self, item_id:int):
        self.tag = 0xD3  # ETSI 102 223, c. 9.1 -> ETSI 102 220, table 7.17
        self.devices = [0x82, 0x02, EnumDeviceID.KEYBOARD, EnumDeviceID.UICC] # ETSI 102 223, c. 8.7
        self.item_id = [0x90, 0x01, item_id] # ETSI 102 223, c. 8.10
        
        self.len = len(self.devices + self.item_id)

    def _build_list(self):
        return [self.tag] + [self.len] + self.devices + self.item_id

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())