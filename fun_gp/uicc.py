from fun_gp import  SCP80, CCM, ProParser, InstallParams, EventDownload

from fun_gp import hex_to_bytes, lv_hex, lv_list


class GenResult:
    def __init__(self, res:int = 0x00, add_info:list[int] = []):
        self.result   = [0x83, 0x01] + [res]
        self.add_info = add_info

    def _build_list(self):
        return self.result + self.add_info

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())


class UICC:
    def __init__(self, plain_apdu:callable, scp80:SCP80 = None):
        self._plain_apdu = plain_apdu
        self.parser      = ProParser()
        self.gen_res     = GenResult()
        self.ccm         = CCM()
        self.scp80       = scp80
        self.sim_menu    = None


    def transmit(self, cmd:str|list, exp_sw1:int|None = None, exp_sw2 : int|None = None, cmd_name:str='', is_secured=True) -> tuple[list[int], int, int]:
        if not is_secured:
            return self._plain_apdu(cmd, exp_sw1, exp_sw2, cmd_name)
        
        sms_list = self.scp80.make_secured_packet(cmd)
        for sms in sms_list:
            resp, sw1, sw2 = self.envelope(sms[0:], cmd_name=cmd_name)
            while sw1 == 0x91:
                resp, _, _ = self.fetch(sw2)
                cmd_type      = self.parser.parse(resp, self.scp80.params.por)
                if cmd_type[3] == 0x13: # SEND SHORT MESSAGE
                    gen_res = GenResult()
                else:
                    gen_res = self.gen_res
                _, sw1, sw2   = self.terminal_response(cmd_type, gen_res)
        return resp, sw1, sw2


    def terminal_profile(self, sw1:int=None, sw2:int=None):
        me_features = [0xFF]*10
        cmd = '8010 0000' + lv_hex(me_features)

        resp, sw1, sw2 = self._plain_apdu(cmd, sw1, sw2, 'Terminal Profile')
        while sw1 == 0x91:
            resp,_,_ = self.fetch(sw2)
            cmd_type = self.parser.parse(resp)
            if cmd_type[3] == 0x03: # POLL INTERVAL
                self.gen_res.add_info = lv_list('0402 011E')
            else:
                self.gen_res.add_info = []
            resp, sw1, sw2 = self.terminal_response(cmd_type, self.gen_res)
        return resp, sw1, sw2


    def envelope(self, payload:list|str, sw1:int=None, sw2:int=None, cmd_name:str=''):
        """
        ETSI 102 221, clause 11.2.2
        Used to transmit a data to the CAT.  
        The status word 6Fxx, 62xx and 63xx considered as 'Negative acknowledgment'.  
        
        :param command: a data to be sent to the UICC.
        """
        
        cmd = '80C2 0000' + lv_hex(payload)
        resp, sw1, sw2 = self._plain_apdu(cmd, sw1, sw2, 'Envelope ' + cmd_name)
        return resp, sw1, sw2


    def fetch(self, expected_len:int, sw1:int=None, sw2:int=None):
        """
        ETSI 102 221, clause 7.4.2  
        Retrieves a proactive command being sent by the UICC.
        
        :returns proactive command: a byte string to be handled by ME. 
        """
        cmd = f'8012 0000 {expected_len:02x}'
        resp, sw1, sw2 = self._plain_apdu(cmd, sw1, sw2, 'Fetch')
        return resp, sw1, sw2


    def terminal_response(self, cmd_type:list|str, gen_res:GenResult, sw1:int=None, sw2:int=None):
        """
        ETSI 102 221, clause 11.2.4  
        Transfers from the Terminal to the UICC the responds to a previously fetched proactive
        command (e.g. CAT command).
        
        :param command: a response to a previously issued proactive command.
        """
        if isinstance(cmd_type, str):
            cmd_type = hex_to_bytes(cmd_type)

        cmd = '8014 0000' + lv_hex(cmd_type + [0x82,0x02 ,0x82,0x81] + gen_res[0:])
        resp, sw1, sw2 = self._plain_apdu(cmd, sw1, sw2, 'Terminal response')
        gen_res.add_info = []

        return resp, sw1, sw2


    def event_download(self, event:EventDownload, add_info:str='', cmd_name:str=''):
        resp, sw1, sw2 = self.envelope(event[0:], cmd_name=f'[EVENT DOWNLOAD] {cmd_name}')
        while sw1 == 0x91:
                resp, _, _ = self.fetch(sw2)
                cmd_type   = self.parser.parse(resp)
                
                if cmd_type[3] == 0x03: # POLL INTERVAL
                    self.gen_res.add_info = lv_list('0402 011E')
                elif cmd_type[3] == 0x26: # IMEI
                    self.gen_res.add_info = hex_to_bytes(add_info)
                
                _, sw1, sw2   = self.terminal_response(cmd_type, self.gen_res)
        return resp, sw1, sw2
        


    def install_app_scp80(self, install_params:InstallParams, path_to_applet:str, chunk_size: int):

        if self.scp80 == None:
            raise ValueError('\'self.scp80\' parameter not initialized.')
        
        sms_counter = 0
        cap_bytes, pkg_aid, app_aid = self.ccm.decomposite_cap_file(path_to_applet)

        # INSTALL[for load]
        cmd_for_load = self.ccm.make_cmd_install_for_load(pkg_aid)
        self.transmit(cmd_for_load + '00c0 0000 00', self.scp80, cmd_name='[SCP80] INSTALL(for load)')
        sms_counter += 1

        # LOAD
        cap_chunks  = self.ccm.make_cmd_load(cap_bytes, chunk_size, '00c0 0000 00')
        for chunk in cap_chunks:
            self.transmit(chunk, self.scp80, cmd_name='[SCP80] LOAD')
            sms_counter += 1

        # INSTALL[for install and make selectable]
        for_install = self.ccm.make_cmd_install_for_install(pkg_aid, app_aid, install_params)
        self.transmit(for_install + '00c0 0000 00', self.scp80, cmd_name='INSTALL[for install and make selectable]')
        
        # Note: 'LOAD.Lc1 + LOAD.Lc2 + LOAD.Ln' is greater than 'self.cap_file_size'.
        # The difference is C * N + T, where
        # C - the length of CMAC,
        # N - number of LOAD commands,
        # T = C4 BER-TLV object at the beginning of the very first LOAD CDATA field.
        print(f'\n***** CAP-file parameters *****\n'
            f'Package AID:    {pkg_aid}\n'
            f'Applet  AID:    {app_aid}\n'
            f'Applet  size:   {self.ccm.cap_file_size} bytes.\n'
            f'Total SMS sent: {sms_counter}\n')


    def remove_app_scp80(self, applet_aid:str):
        
        if self.scp80 == None:
            raise ValueError('\'self.scp80\' parameter not initialized.')
        
        cmd_delete = self.ccm.make_cmd_delete(applet_aid)
        self.transmit(cmd_delete + '00c0 0000 00', self.scp80, cmd_name=f'DELETE [{applet_aid}]')