from fun_gp.utils import bytes_to_hex, decode_ucs2, decode_bcd
from math import ceil

class ProParser:
    def __init__(self):
        self.data = list

    def _init_parser(self, raw_bytes:list):
        data_offset = 2
        if raw_bytes[1] < 0x80:
            self.length = raw_bytes[1]
        else:
            self.length = raw_bytes[2]
            data_offset = 3
        
        self.data = raw_bytes[data_offset:]
        self.idx    = 0
        self.length = 0
        

    def parse(self, raw_bytes:list, por:int=0x00)->list[list[int], list[int]]:

        self._init_parser(raw_bytes)

        tag    = 0
        length = 0
        command_type = [[],[]]

        while self.idx < len(self.data):
            tag, length, value = self._next()

            # The values in match-case expressions are taken from ETSI 102 220, table 7.23
            match tag:

                case 0x01 | 0x81: # Command details (102 223, 8.6)
                    if length != 3:
                        raise ValueError(f'the length of \'Command details\' object must be \'3\', but got {length}.')
                    else:
                        print(f'\tcommand number: {value[0]:02x}')
                        print(f'\tcommand type:   {type_of_command[value[1]]}')
                        print(f'\tqualifier:      {value[2]:02x} (see ETSI 102 223, c. 8.6)')
                    command_type[0] = value # this value will be used in TERMINAL RESPONSE
                
                case 0x02 | 0x82: # Device identity, (ETSI 102 223, 8.7)
                    if length != 2:
                        raise ValueError(f'the length of \'Device identity\' object must be \'2\', but got {length}.')
                    
                    entities = {0x02:'Display', 0x81:'UICC', 0x82:'ME', 0x83:'Network'}
                    source      = entities[value[0]]
                    destination = entities[value[1]]

                    print(f'\tfrom:           {source}\n\tto:             {destination}')

                case 0x03 | 0x83: # Result (102 223, 8.12)
                    pass
                case 0x04 | 0x84: # Duration (102 223, 8.8)
                    
                    if length != 2:
                        raise ValueError(f'the length of \'Duration\' object must be \'2\', but got {length}.')
                    
                    coding = ''
                    if value[0] == 0:
                        coding = 'minutes'
                    elif value[0] == 1:
                        coding = 'seconds'
                    elif value[0] == 2:
                        coding = 'milliseconds'
                    else:
                        raise ValueError(f'unknown format of \'Duration\' time unit coding {value[0]:02x}')
                    print(f'\tduration:       {value[1]} {coding}')
                    
                    command_type[1] = [tag] + [length] + value

                case 0x05 | 0x85: # Alpha identifier  (ETSI 102 223, 8.2)
                    alpha_str = bytes_to_hex(value)
                    decoded = decode_ucs2(alpha_str)
                    print(f'\tAlpha identifier: {decoded}')

                case 0x06 | 0x86: # Address
                    address = bytes_to_hex(value)
                    address = decode_bcd(address)
                    print(f'\tAddress:        {address}')

                case 0x07 | 0x87: # Capability configuration parameters
                    pass
                case 0x08 | 0x88: # Subaddress
                    pass
                case 0x09 | 0x89: # SS string | BSSID | PLMN ID | (E-UTRAN/Satellite E-UTRAN Timing Advance
                    pass
                case 0x0A | 0x8a: # USSD string | HESSID
                    pass
                case 0x0B | 0x8b: # SMS TPDU | PDP/PDN/PDU type
 
                    print(f'\tSMS TPDU:       SMS-SUBMIT')
                    tpdu_idx = 2
                    da_len = ceil(value[tpdu_idx] / 2)

                    tpdu_idx += 2
                    dest_address = decode_bcd(value[tpdu_idx:tpdu_idx + da_len])
                    print(f'\tdest address:   {dest_address}')

                    tpdu_idx += da_len + 4 # jump straight to TP-UD
                    resp_code = 0x00
                    if [0x02, 0x71, 0x00] == value[tpdu_idx:tpdu_idx + 3]:
                        resp_code = value[tpdu_idx + 15]
                        print(f'\tResp status:    {resp_code:02x}')
                        if resp_code != por:
                            raise ValueError(f'\tSCP80 Command Packet failure:\nexpected {response_status[por]}\ngot      {response_status[resp_code]}')
                    
                    print(f'\tTP-UD:          {bytes_to_hex(value[tpdu_idx:])}')

                case 0x0C | 0x8c: # Cell Broadcast page | PDU session establishment parameters
                    pass
                case 0x0D | 0x8d: # Text string
                    # text_str = bytes_to_hex(value)
                    decoded = decode_ucs2(value)
                    print(f'\tMessage {value[0]:02x}: {decoded}')
                case 0x0E | 0x8e: # Tone | eCAT client profile
                    pass
                case 0x0F | 0x8f: # Item | eCAT client identity
                    item_str = bytes_to_hex(value[1:])
                    decoded = decode_ucs2(item_str)
                    print(f'\titem {value[0]:02x}: {decoded} ({bytes_to_hex(value)})')

                case 0x10 | 0x90: # Item identifier | Encapsulated envelope type
                    pass
                case 0x11 | 0x91: # Response length | Call control result
                    pass
                case 0x12 | 0x92: # File List | CAT service list | LSI numbers
                    pass
                case 0x13 | 0x93: # Location Information
                    pass
                case 0x14 | 0x94: # IMEI
                    pass
                case 0x15 | 0x95: # Help request
                    pass
                case 0x16 | 0x96: # Network Measurement Results
                    pass
                case 0x17 | 0x97: # Default Text
                    pass
                case 0x18:        # Items Next Action Indicator
                    pass
                case 0x19 | 0x99: # Event list (102 223, 8.25)
                    for v in value:
                        print(f'\tevent:          \'{events[v]}\'')
                case _ :
                    print(f'unknown tag \'{tag:02x}\' in proactive command')
        return command_type


    def _next(self):
        tag       = self.data[self.idx]
        self.idx += 1
        
        length    = self.data[self.idx]
        self.idx += 1
        
        value     = self.data[self.idx: self.idx + length]
        self.idx += length

        return tag, length, value

# taken from 102 223, clause 9.4
type_of_command = {
    0x01: 'REFRESH', 0x02: 'MORE TIME', 0x03: 'POLL INTERVAL',      0x04: 'POLLING OFF', 0x05: 'SET UP EVENT LIST', 0x10: 'SET UP CALL',
    0x11: 'SEND SS', 0x12: 'SEND USSD', 0x13: 'SEND SHORT MESSAGE', 0x14: 'SEND DTMF',   0x15: 'LAUNCH BROWSER',    0x16: 'GEOGRAPHICAL LOCATION REQUEST',
    
    0x20: 'PLAY TONE',     0x21: 'DISPLAY TEXT',              0x22: 'GET INKEY',           0x23: 'GET INPUT',             0x24: 'SELECT ITEM',
    0x25: 'SET UP MENU',   0x26: 'PROVIDE LOCAL INFORMATION', 0x27: 'TIMER MANAGEMENT',    0x28: 'SET UP IDLE MODE TEXT', 0x30: 'PERFORM CARD APDU',
    
    0x31: 'POWER ON CARD', 0x32: 'POWER OFF CARD',            0x33: 'GET READER STATUS',   0x34: 'RUN AT COMMAND',        0x35: 'LANGUAGE NOTIFICATION',
    0x40: 'OPEN CHANNEL',  0x41: 'CLOSE CHANNEL',             0x42: 'RECEIVE DATA',        0x43: 'SEND DATA',             0x44: 'GET CHANNEL STATUS',
    
    0x45: 'SERVICE SEARCH',              0x46: 'GET SERVICE INFORMATION',   0x47: 'DECLARE SERVICE',            0x50: 'SET FRAMES', 0x51: 'GET FRAMES STATUS',
    0x60: 'RETRIEVE MULTIMEDIA MESSAGE', 0x61: 'SUBMIT MULTIMEDIA MESSAGE', 0x62: 'DISPLAY MULTIMEDIA MESSAGE', 0x70: 'ACTIVATE',   0x71: 'CONTACTLESS STATE CHANGED',
    
    0x72: 'COMMAND CONTAINER', 0x73: 'ENCAPSULATED SESSION CONTROL', 0x74: 'Void', 0x75: 'RFU', 0x76: 'RFU', 0x77: 'RFU', 0x78: 'RFU',
    0x79: 'LSI COMMAND',       0x81: 'End of the proactive UICC session',
}

# Taken from 120 223, clause 8.25
events = {
    0x00:'MT call',                   0x01:'Call connected',            0x02:'Call disconnected',             0x03:'Location status',
    0x04:'User activity',             0x05:'Idle screen available',     0x06:'Card reader status',            0x07:'Language selection',
    0x08:'Browser termination',       0x09:'Data available',            0x0a:'Channel status',                0x0b:'Access Technology Change (single access technology)',
    0x0c:'Display parameters changed',0x0d:'Local connection',          0x0e:'Network Search Mode Change',    0x0f:'Browsing status',
    0x10:'Frames Information Change', 0x11:'I-WLAN Access Status',      0x12:'Network Rejection',             0x13:'HCI connectivity event',
    0x14:'Access Technology Change (multiple access technologies)',     0x15:'CSG cell selection',            0x16:'Contactless state request',
    0x17:'IMS Registration',          0x18:'IMS Incoming data',         0x19:'Profile Container',             0x1a:'Void',
    0x1b:'Secured Profile Container', 0x1c:'Poll Interval Negotiation', 0x1d:'Data Connection Status Change', 0x1e:'CAG cell selection',
    0x1f:'Slices Status Change',

    0x20:'RFU',
    0x21:'RFU',
    0x22:'RFU'
}

response_status = {
    0x00:'PoR OK',
    0x01:'CC failed',
    0x02:'CNTR Low',
    0x03:'CNTR High',
    0x04:'CNTR blocked',
    0x05:'Ciphering error',
    0x06:'Unidentified security error.',
    0x07:'Insufficient memory to process incoming message.',
    0x08:'Need more time to process the Command Packet',
    0x09:'TAR Unknown',
    0x0a:'Insufficient security level',
    0x0b:'Response data to be sent using SMS-SUBMIT',
    0x0c:'Response data to be sent using a ProcessUnstructuredSS-Request',
}