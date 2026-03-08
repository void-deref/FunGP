from fun_gp.utils import lv, hex_to_bytes, bytes_to_hex, len_asn, encode_bcd

class CH: # TP-Command-Header
    def __init__(self, cntr:str|list):

        if isinstance(cntr, str):
            cntr = hex_to_bytes(cntr)
        
        # Command Header params (ETSI 102 225)
        self.len   = 0x0d
        self.spi   = [0x12, 0x22]
        self.kic   = 0x49
        self.kid   = 0x49
        self.tar   = [0x00,0x00,0x00]
        self.cntr  = cntr  # Replay detection and Sequence Integrity counter
        self.pcntr = 0x00
        self.checksum = []
    
    def _build_list(self):
        return [self.len] + self.spi + [self.kic, self.kid] + self.tar + self.cntr + [self.pcntr] + self.checksum
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())


class CP: # TP-Command-Packet
    def __init__(self, cntr:str|list, data:str|list):

        if isinstance(data, str):
            data = hex_to_bytes(data)

        self.ch   = CH(cntr)
        self.data = data
        # '1' means take into account the CH.len field itself.
        cp_len    = len(data) + self.ch.len + 1
        self.len  = hex_to_bytes(f'{cp_len:04x}')
    
    def _build_list(self):
        return self.len + self.ch[0:] + self.data
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())


class IEIstk:
    def __init__(self):
        self.value   = 0x70 # see ETSI 123 040, 9.2.3.24
        self.len     = 0x00

    def _build_list(self):
        return [self.value, self.len]
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())


class IEIconcat:
    def __init__(self):
        self.value   = 0x00 # see ETSI 123 040, 9.2.3.24
        self.len     = 0x03
        self.ref_num = 0x01
        self.max_num = 0x02
        self.seq_num = 0x00
    
    def _build_list(self):
        return [self.value, self.len, self.ref_num, self.max_num, self.seq_num]
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())


class UDH: # TP-User-Data-Header
    def __init__(self, is_concat:bool=False, is_secured:bool=False):
        self.has_concat = is_concat
        self.has_secure = is_secured

        self.len = 0x00
        self.concat = IEIconcat()
        self.cpi    = IEIstk()

    def _build_list(self):
        total = [self.len]

        if self.has_concat == True:
            total += self.concat[0:]
        if self.has_secure == True:
            total += self.cpi[0:]

        return total

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())

    def __repr__(self):
        return bytes_to_hex(self._build_list())


class TP_UD:
    """
    TP-User Data (ETIS 123 040, 9.2.3.24)
    """
    def __init__(self, user_data:list|str=None, is_concat:bool=False, is_secured:bool=False):

        if isinstance(user_data, str):
            user_data = hex_to_bytes(user_data)

        self.len = 0
        self.udh = UDH(is_concat, is_secured)
        self.data = []

        if is_concat == True:
            self.udh.concat = IEIconcat()
            self.udh.len = len(self.udh.concat)
        
        if is_secured == True:
            self.udh.cpi = IEIstk()
            self.udh.len += len(self.udh.cpi)

        self.data = user_data
        
        if self.udh.len != 0x00:
            self.len = len(self.data[0:] + self.udh[0:])
        else:
            self.len = len(self.data[0:])
        
        # final check: the length of TP-UD can't exceed 140 bytes
        if self.len > 140:
            raise ValueError(f'TP-UDL (aka SMS length) is {self.len}, while 140 is the limit.')
    
    def _build_list(self):
        total = []
        if self.udh.len != 0x00:
            total = [self.len] + self.udh[0:] + self.data[0:]
        else:
            total = [self.len] + self.data
        return total
    
    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())


class SMS_TPDU:
    """
    As defined in ETSI 123 040, clause 9.2.2
    SMS-TPDU tag = '0B' or '8B' (ETSI 131 111, 9.3)

    Timestamp is prepresented in inversed semi-octets with the following structure:  
    [YYMMDD HHMMSS TZ] = 622042 219500 12 (24.02.2026, 12:59:00, +3h UTC)  
    TZ - '12'; 12 * 15 = 180 = +3 hours  
    Where '15' is a quarter of hour. Just set the eight bit to indicard '-3':
    12 = +3, where 92 = -3.
    """
    def __init__(self, user_data:list|str=None, is_concat:bool=False, is_secured:bool=False):
        self.tag          = 0x8B
        self.len          = [0x00] # Mind the ASN representation, i.e. '00-7F' or '8180-81FF'
        self.first_octet  = 0x60   # TPDU of type SMS-DELIVER, PoR on error
        self.orig_address = hex_to_bytes('0391 77f7')
        self.pid_dcs      = hex_to_bytes('7ff6') #[0x7F, 0xF6]

        # time_stamp = '407070 611535 00' - sample value taken from SCP80-manager
        # 2026.02.18 14:20:00, +3 UTC;
        self.timestamp = hex_to_bytes(encode_bcd('260218 142000 12'))
        self.ud  = TP_UD(user_data, is_concat, is_secured)
        
        self.len = hex_to_bytes(len_asn([self.first_octet] + self.orig_address +
                                    self.pid_dcs + self.timestamp + self.ud[0:]))

    def _build_list(self):
        return ([self.tag] + self.len + [self.first_octet] +
                self.orig_address + self.pid_dcs + self.timestamp + self.ud[0:])

    def __getitem__(self, index):
        return self._build_list()[index]
    
    def __len__(self):
        return len(self._build_list())
    
    def __repr__(self):
        return bytes_to_hex(self._build_list())


class SMSPP:
    """
    As defined ETSI 131 111, 7.1.2
    SMS-PP download tag = 'D1' (9.1)
    """
    def __init__(self, user_data:list|str=None, is_concat:bool=False, is_secured:bool=False):
        self.tag = 0xD1
        self.len = [0x00] # Mind the ASN representation, i.e. '00-7F' or '8180-81FF'

        # source - 83 (network), dest - 81 (UICC)
        self.device_identities = hex_to_bytes('8202 8381')
        
        # TON - international number; NPI - ISDN
        self.address    = hex_to_bytes('03' + lv('91' + '77f7'))
        
        self.tpdu = SMS_TPDU(user_data, is_concat, is_secured)

        self.len = hex_to_bytes(
                        len_asn(self.device_identities + self.address + self.tpdu[0:])
                    )

    def _build_list(self):
        return [self.tag] + self.len + self.device_identities + self.address + self.tpdu[0:]
    
    def __getitem__(self, index):
        return self._build_list()[index]
    
    def __len__(self):
        return len(self._build_list())
    
    def __repr__(self):
        return bytes_to_hex(self._build_list())