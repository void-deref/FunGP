from fun_gp import  Reader, SCP80, SCP80Params,  \
                    CardContentManagement, SMSPP, \
                    CP, ProParser, SW_list

from fun_gp.utils import decode_bcd, hex_to_bytes, bytes_to_hex, lv
from math import ceil

class UICC(Reader, SCP80, CardContentManagement):
    """
    ETSI 102 221, clauses 7.4.2 and 10.2  
        CAT application layer indicates:  
         - availability of a proactive command (91xx);  
         - the usage of a data returned to an envelope command (9000, warnings 62xx or 63xx, errors 6Fxx);  
         - unavailability of the CAT (9300, see clause 14.6.6);  
    """
    def __init__(self, known_readers:list, path_to_card_deck:str, iccid:str=None):
        
        Reader.__init__(self, known_readers)

        if iccid == None:
            iccid = self._get_iccid()
        
        SCP80.__init__(self, iccid, path_to_card_deck)
        CardContentManagement.__init__(self)

    # The structure of ENVELOPE SMS-PP DOWNLOAD is described in ETSI 131 111, 7.1.1.2
    def apdu_scp80(self, payload:str|list, params:SCP80Params, expected_sw:int=0, name:str=''):

        if isinstance(payload, str):
            payload = hex_to_bytes(payload)
        
        cmd_pkt = CP(self.cntr, payload)

        cmd_pkt.ch.spi = params.spi        
        cmd_pkt.ch.kic = params.kic
        cmd_pkt.ch.kid = params.kid
        cmd_pkt.ch.tar = params.tar

        # The following code looks weird because the authors of ETSI 102 225 and 131 111
        # were smoking gas and not even passing it! Here the recursion takes place:
        # - if CC is requested, then it must be calculated before ciphering; Mind that
        #   the 'PCNTR' and 'PCNTR padding bytes' are used in CC calculation and also
        #   the length of CH must take into account currently abcent CC field in advance!!!;

        # - if ciphering is requested too, then we need to discard CC, because the 'PCNTR'
        #   field isn't '00' anymore, and also there are 'PCNTR padding bytes' appended to payload,
        #   which must be passed over to CC calculation function too.

        if cmd_pkt.ch.spi[0] & 0x02 != 0x00: # checksum takes place. Add 8 bytes to length of CP and CH
            cmd_pkt.ch.len     += 8
            cp_len              = int.from_bytes(cmd_pkt.len)
            cmd_pkt.len         = hex_to_bytes(f'{(cp_len + 8):04x}')
        
        if cmd_pkt.ch.spi[0] & 0x04 != 0x00: # ciphering takes place. Count padding bytes
            cc_len           = (cmd_pkt.ch.len - 0x0d)
            cmd_pkt.ch.pcntr = self._count_padding(len(cmd_pkt[10:]) + cc_len, cmd_pkt.ch.kic)
            cmd_pkt.data    += [0] * cmd_pkt.ch.pcntr
            cp_len           = int.from_bytes(cmd_pkt.len)
            cmd_pkt.len      = hex_to_bytes(f'{(cp_len + cmd_pkt.ch.pcntr):04x}')
        
        # print(f'CP before: {cmd_pkt}')

        if cmd_pkt.ch.spi[0] & 0x02 != 0x00: # calculate checksum
            cmd_pkt.ch.checksum = self._checksum(cmd_pkt[0:], cmd_pkt.ch.kid)

        if cmd_pkt.ch.spi[0] & 0x04 != 0x00: # encipher Command Packet
            cipher_text         = self._encrypt(cmd_pkt[10:], cmd_pkt.ch.kic)
            cmd_pkt.ch.cntr     = cipher_text[0:5]
            cmd_pkt.ch.pcntr    = cipher_text[5]
            cmd_pkt.ch.checksum = cipher_text[6:14]
            cmd_pkt.data        = cipher_text[14:]
        
        # print(f'CP after:  {cmd_pkt}')

        total_length = len(cmd_pkt)
        chunk_size   = 132
        chunks_total = ceil(total_length / chunk_size)

        sms_seq_num  = 1
        is_concat    = True if chunks_total > 1 else False
        is_secured   = True
        sms_list = []

        for i in range(0, total_length, chunk_size):
            sms = SMSPP(user_data=cmd_pkt[i:i + chunk_size], is_concat=is_concat, is_secured=is_secured)
            sms.tpdu.ud.udh.concat.max_num = chunks_total
            sms.tpdu.ud.udh.concat.seq_num = sms_seq_num
            sms_seq_num += 1
            is_secured  = False # the 'IEI STK' must present in the first chunk only
            sms_list.append(sms)

        self._increment_cntr()

        name = '(SCP80) ' + name
        parser = ProParser()
        for sms in sms_list:
            print(f'{name}')
            response = self.envelope(sms[0:])
            self._print_scp80(sms)
            
            while response[-2] == 0x91:
                response = self.fetch(response[-1])
                # Trim last two bytes of SW.
                term_resp = parser.parse(response[0:-2], params.por)
                response = self.terminal_response('8103' + bytes_to_hex(term_resp[0]) + '82028281 030100' + bytes_to_hex(term_resp[1]))

        actual_sw = int.from_bytes(response[-2:], byteorder='big')
        if expected_sw != 0 and expected_sw != actual_sw:
            raise ValueError(f'expected {expected_sw:#04x} got {actual_sw:#04x} [{SW_list.get(actual_sw, "to be added to dictionary")}]')


    def terminal_profile(self, expected_sw:int=0):
        
        me_features = [0xFF]*6
        cmd         = [0x80,0x10,0x00,0x00, 0x00] + me_features
        cmd[4]      = len(me_features)

        print(f'Terminal Profile')
        response, duration = self._command_apdu(cmd)
        self._response_apdu(response, duration)
        
        actual_sw = int.from_bytes(response[-2:], byteorder='big')
        if expected_sw != 0 and expected_sw != actual_sw:
            
            raise ValueError(f'expected {expected_sw:#04x} got {actual_sw:#04x} [{SW_list.get(actual_sw, "to be added to dictionary")}]')

        parser = ProParser()
        while response[-2] == 0x91:
            response = self.fetch(response[-1])
            # Trim last two bytes of SW.
            command_type = parser.parse(response[0:-2])
            response = self.terminal_response('8103' + bytes_to_hex(command_type[0]) + '82028281 030100' + bytes_to_hex(command_type[1]))


    def envelope(self, payload:list|str, expected_sw:int=0):
        """
        ETSI 102 221, clause 7.4.2.2  
        Used to transmit a data to the CAT.  
        The status word 6Fxx, 62xx and 63xx considered as 'Negative acknowledgment'.  
        
        :param command: a data to be sent to the UICC.
        Must contain the CDATA field only, i.e. no APDU header bytes shall present.
        """
        if isinstance(payload, str):
            payload = hex_to_bytes(payload)
        
        cmd    = [0x80,0xC2,0x00,0x00, 0x00]
        cmd[4] = len(payload)
        cmd    = cmd + payload

        # print(f'Envelope: {bytes_to_hex(cmd)}')
        
        response, duration = self._command_apdu(cmd)
        self._response_apdu(response, duration)

        actual_sw = int.from_bytes(response[-2:], byteorder='big')
        if expected_sw != 0 and expected_sw != actual_sw:
            
            raise ValueError(f'expected {expected_sw:#04x} got {actual_sw:#04x} [{SW_list.get(actual_sw, "to be added to dictionary")}]')

        return response
        # return [0x90,00]


    def fetch(self, proactive_len:int, expected_sw:int=0):
        """
        ETSI 102 221, clause 7.4.2  
        Retrieves a proactive command being sent by the UICC.
        
        :returns proactive command: a byte string to be handled by ME. 
        """
        cmd = [0x80,0x12,0x00,0x00, 0x00]
        cmd[4] = proactive_len

        print(f'Fetch')
        response, duration = self._command_apdu(cmd)
        self._response_apdu(response, duration)

        actual_sw = int.from_bytes(response[-2:], byteorder='big')
        if expected_sw != 0 and expected_sw != actual_sw:
            
            raise ValueError(f'expected {expected_sw:#04x} got {actual_sw:#04x} [{SW_list.get(actual_sw, "to be added to dictionary")}]')

        return response


    def terminal_response(self, command_data:list|str, expected_sw:int=0):
        """
        ETSI 102 221, clause 7.4.2  
        Responds to proactive command.
        
        :param command: a response to a previously issued proactive command.
        Must contain the CDATA field only, i.e. no APDU header bytes shall present.
        """
        if isinstance(command_data, str):
            command_data = hex_to_bytes(command_data)
        
        cmd = [0x80,0x14,0x00,0x00, 0x00] + command_data
        cmd[4] = len(command_data)

        print(f'Terminal response')
        response, duration = self._command_apdu(cmd)
        self._response_apdu(response, duration)

        actual_sw = int.from_bytes(response[-2:], byteorder='big')
        if expected_sw != 0 and expected_sw != actual_sw:
            
            raise ValueError(f'expected {expected_sw:#04x} got {actual_sw:#04x} [{SW_list.get(actual_sw, "to be added to dictionary")}]')

        return response


    def _print_scp80(self, sms:SMSPP):

        sms_pp_len = sms.len if len(sms.len) == 1 else sms.len[1:]
        tpdu_len   = sms.tpdu.len if len(sms.tpdu.len) == 1 else sms.tpdu.len[1:]

        print(f'SMSPP:')
        print(f'    tag: {sms.tag:02x}')
        print(f'    len: {int.from_bytes(sms_pp_len)} (0x{bytes_to_hex(sms.len)})')
        print(f'    devices: {bytes_to_hex(sms.device_identities)}')
        print(f'    address: {bytes_to_hex(sms.address)}')

        print(f'    SMS TPDU:')
        print(f'        tag: {sms.tpdu.tag:02x}')
        print(f'        len: {int.from_bytes(tpdu_len)} (0x{bytes_to_hex(sms.tpdu.len)})')
        print(f'        first octet: {sms.tpdu.first_octet:02x}')
        print(f'        originating address: {bytes_to_hex(sms.tpdu.orig_address)}')
        print(f'        PID and DCS: {bytes_to_hex(sms.tpdu.pid_dcs)}')
        print(f'        Time stamp:  {bytes_to_hex(sms.tpdu.timestamp)}')
        
        print(f'        TP-UD:')
        print(f'            TP-UDL: {sms.tpdu.ud.len} (0x{sms.tpdu.ud.len:02x})')
        print(f'               UDH: {sms.tpdu.ud.udh}')
        print(f'              data: {bytes_to_hex(sms.tpdu.ud.data)}')


    def _get_iccid(self):
        self.apdu_plain('00A4 0000 02 3F00', expected_sw=0x9000)
        self.apdu_plain('00A4 000C 02 2FE2', expected_sw=0x9000)
        iccid = self.apdu_plain('00B0 0000 00', expected_sw=0x9000)
        iccid = decode_bcd(iccid[0:-2])
        print(f'Card\'s ICCID: {iccid}')
        return iccid


    def install_app_scp80(self, cap_path:str, scp80_params:SCP80Params, app_params:str='', sys_params: str = ''):
        """
        Installs an applet via SCP80 protocol.  
        Implementation details and requirementscan be found in ETSI 102 225, 102 226 and 131 111.
        """
        cap_bytes, package_aid, applet_aid = self._parse_cap_file(cap_path)
        
        # INSTALL[for load]
        for_load = self._compile_for_load(package_aid)
        self.apdu_scp80(for_load, scp80_params, name='INSTALL[for load]')

        # LOAD
        self.apdu_scp80(cap_bytes, scp80_params, expected_sw=0x9000, name='LOAD')
        
        # Note: 'LOAD.Lc1 + LOAD.Lc2 + LOAD.Ln' is greater than 'self.cap_file_size'.
        # The difference is C * N + T, where
        # C - the length of CMAC,
        # N - number of LOAD commands,
        # T = C4 BER-TLV object at the beginning of the very first LOAD CDATA field.
        print(f'***** CAP-file size *****')
        print(f'{self.cap_file_size} bytes.')

        for_install = self._compile_for_install(package_aid, applet_aid, app_params, sys_params)
        self.apdu_scp80(for_install, scp80_params, expected_sw = 0x9000, name = 'INSTALL[for install and make selectable]')