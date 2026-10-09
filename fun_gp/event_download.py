from enum import IntEnum
from fun_gp import lv_list, bytes_to_hex


class EnumDeviceID(IntEnum):
    """
    ETSI 102 223, c. 8.7
    """
    KEYBOARD = 0x01
    DISPLAY  = 0x02
    UICC     = 0x81
    TERMIAL  = 0x82
    NETWORK  = 0x83


class EnumEventType(IntEnum):
    """
    ETSI 102 223, c. 8.25
    """
    MT_CALL             = 0x00
    CALL_CONNECTED      = 0x01
    CALL_DICONNECTED    = 0x02
    LOCATION_STATUS     = 0x03
    USER_ACTIVITY       = 0x04
    IDLE_SCREEN_AVAILABLE = 0x05
    CARD_READER_STATUS  = 0x06
    LANGUAGE_SELECTION  = 0x07
    BROWSER_TERMINATION = 0x08
    DATA_AVAILABLE      = 0x09
    CHANNEL_STATUS      = 0x0A
    ACCESS_TECH_CHANGED_SINGLE = 0x0B
    DISPLAY_PARAMS_CHANGED = 0x0C
    LOCAL_CONNECTION       = 0x0D
    NETWORK_SEARCH_MODE_CHANGE = 0x0E
    BROWSING_STATUS     = 0x0F
    FRAMES_INFO_CHANGE  = 0x10
    IWLAN_ACCESS_STATUS = 0x11
    NETWORK_REJECTION   = 0x12
    HCI_CONNECTIVITY    = 0x13
    ACCESS_TECH_CHANGED_MULTIPLE = 0x14
    CSG_CELL_SELECTION        = 0x15
    CONTACTLESS_STATE_REQUEST = 0x16
    IMS_REGISTRATION    = 0x17
    IMS_INCOMING_DATA   = 0x18
    PROFILE_CONTAINER   = 0x19
    SECURED_PROFILE_CONTAINER = 0x1B
    POLL_INTERVAL_NEGOTIATION = 0x1C


class EnumLocationStatus(IntEnum):
    NORMAL     = 0x00
    LIMITED    = 0x01
    NO_SERVICE = 0x02


class EnumCardReaderStatus(IntEnum):
    """
    ETSI 102 223, c. 8.33
    """
    REMOVABLE     = 0x08
    CARD_READER_PRESENT = 0x10
    READER_IS_ID1 = 0x20
    CARD_PRESENT  = 0x40
    CARD_POWERED  = 0x80


class EventDownload:
    """
    ETSI 102 223, clause 7.5
    """
    def __init__(self, event:int, from_:int, to:int):
        self.tag     = 0xD6  # ETSI 102 223, c. 9.1 -> ETSI 102 220, table 7.17
        self.len     = 0
        self.event   = [0x99, 0x01, event] # ETSI 102 223, c. 8.25
        self.devices = [0x82, 0x02, from_, to] # ETSI 102 223, c. 8.7


class LocationStatus(EventDownload):
    """
    ETSI 102 223, clause 7.5.4  
    Default parameter is as follows:  
    MCC(250) | MNC(01) | TAC(4155)  | Cell ID(079A DFF2)
    """
    def __init__(self, location_status:int, location_info:str='52F010 4155 079ADFF2'):
        super().__init__(EnumEventType.LOCATION_STATUS, EnumDeviceID.TERMIAL, EnumDeviceID.UICC)

        self.status = [0x9B, 0x01, location_status]   # ETSI 102 223, c. 8.27
        self.info   = [0x93] + lv_list(location_info) # ETSI 131 111, c. 8.19
        self.len    = len(self.event + self.devices + self.status + self.info)

    def _build_list(self):
        return [self.tag] + [self.len] + self.event \
             + self.devices + self.status + self.info

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())



class UserActivity(EventDownload):
    """
    ETSI 102 223, clause 7.5.5
    """
    def __init__(self):
        super().__init__(EnumEventType.USER_ACTIVITY, EnumDeviceID.TERMIAL, EnumDeviceID.UICC)
        self.len = len(self.event + self.devices)

    def _build_list(self):
        return [self.tag] + [self.len] + self.event + self.devices
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())


class CardReaderStatus(EventDownload):
    """
    ETSI 102 223, clause 7.5.7
    """
    def __init__(self, reader_status:int):
        super().__init__(EnumEventType.CARD_READER_STATUS, EnumDeviceID.TERMIAL, EnumDeviceID.UICC)
        self.status = [0xA0, 0x01, reader_status] # ETSI 102 223, c. 8.33
        self.len = len(self.event + self.devices + self.status)

    def _build_list(self):
        return [self.tag] + [self.len] + self.event + self.devices  + self.status
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())
    
    def __repr__(self):
        return bytes_to_hex(self._build_list())


class LanguageSelection(EventDownload):
    """
    ETSI 102 223, clause 7.5.8  
    Default values are: 72(u) 75(u).  
    Another values could be:  
    - 656E (en)
    - 6465 (de)
    - etc
    """
    def __init__(self, sym1:int=0x72, sym2:int=0x75):
        super().__init__(EnumEventType.LANGUAGE_SELECTION, EnumDeviceID.TERMIAL, EnumDeviceID.UICC)
        self.language = [0xAD, 0x02, sym1, sym2] # ETSI 102 223, c. 8.45
        self.len = len(self.event + self.devices + self.language)

    def _build_list(self):
        return [self.tag] + [self.len] + self.event + self.devices + self.language
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())
    
    def __repr__(self):
        return bytes_to_hex(self._build_list())