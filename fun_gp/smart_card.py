from fun_gp import Reader, SCP02, CardContentManagement, SW_list
from fun_gp.utils import lv, hex_to_bytes

from Crypto.Cipher import DES3, DES

import os


class SmartCard(Reader, SCP02, CardContentManagement):
    def __init__(self, known_readers:list, key_set:list=['','','']):
        Reader.__init__(self, known_readers)
        SCP02.__init__(self, key_set)
        CardContentManagement.__init__(self)


    def apdu_scp02(self, cmd:list|str, expected_sw:int = 0, name:str = None):

        if isinstance(cmd, str): # transform hex string into byte array
            cmd = hex_to_bytes(cmd)
        
        cmd[0] &= 0xFC # clean channel indication
        cmd[0] |= 0x04 # set GP proprietary SM flag
        cmd[4] += 8
        if cmd[4] > 255:
            raise ValueError(f'The length of input data doesn\'t take into account the 8-byte C-MAC.'
                             + f'\n This causes the total length of CDATA equals {cmd[4]} bytes.')
        
        c_mac = self._retail_mac(cmd)

        cmd = cmd + c_mac
        name = '(SCP02) ' + name
        return self.apdu_plain(cmd, expected_sw, name)


    def mutual_auth(self):
        host_challenge = list(os.urandom(8))
        cmd_init_update = [0x80, 0x50, 0x00, 0x00, 0x08] + host_challenge
        response = self.apdu_plain(cmd_init_update, expected_sw = 0x9000, name = 'Initialize update')

        counter, card_challenge, host_challenge = self._init_update(response, host_challenge)
        ext_auth_cmd = self._external_authenticate(counter, card_challenge, host_challenge)

        response = self.apdu_plain(ext_auth_cmd, expected_sw = 0, name='External authenticate')
        expected_sw  = 0x9000
        actual_sw    = int.from_bytes(response[-2:], byteorder='big')
        if expected_sw != actual_sw:
            raise ValueError(
                f'Error: expected {expected_sw:#04x} got {actual_sw:#04x}\
                \n\t\t\t****************************** CAUTION! ******************************\
                \n\t\t\tFurther attempts with the same keys will irreversibly block the card!'
            )
        else:
            self.authenticated = True


    def install_app_scp02(self, cap_path:str, app_params:str='', sys_params: str = ''):
        """
        Install an applet through the SCP02 protocol.  
        
        :param cap_path: path to a cap file to be installed  
        :param install_params: by default passes applet's AID only. Additional params must
        be prepended with length value e.g.:  
        `lv(pin) + lv(secret)`
        so that the resulting string will have the following form:  
        `[len][AID] [len][pin] [len][secret]`
        
        """
        cap_bytes, package_aid, applet_aid = self._parse_cap_file(cap_path)

        # INSTALL[for load]
        for_load = self._compile_for_load(package_aid)
        self.apdu_scp02(for_load, expected_sw = 0x9000, name = 'INSTALL[for load]')
        
        # LOAD
        commands = self._compile_load(cap_bytes)
        for next in commands:
            self.apdu_scp02(next, expected_sw=0x9000, name='LOAD')

        # Note: 'LOAD.Lc1 + LOAD.Lc2 + LOAD.Ln' is greater than 'self.cap_file_size'.
        # The difference is C * N + T, where
        # C - the length of CMAC,
        # N - number of LOAD commands,
        # T = C4 BER-TLV object at the beginning of the very first LOAD CDATA field.
        print(f'***** CAP-file size *****')
        print(f'{self.cap_file_size} bytes.')
        
        # INSTALL[for install and make selectable]
        for_install = self._compile_for_install(package_aid, applet_aid, app_params, sys_params)
        self.apdu_scp02(for_install, expected_sw = 0x9000, name = 'INSTALL[for install and make selectable]')


    def uninstall_app_scp02(self, package_aid:str='', applet_aid:str='', sw:int = 0):
        """
        Uninstalls previously installed applet. Note that uninstalling a package will
        lead to removing all relative applets too.
        
        :param package_aid: AID of a packed to be deleted with all its dependent applets.
        :param applet_aid: AID of an applet to be delete.
        """

        if len(package_aid) == 0 and len(applet_aid) == 0:
            raise ValueError('define either package or applet AID')
        
        aid, cmd = self._compile_delete(package_aid, applet_aid, sw)
        self.apdu_scp02(cmd, expected_sw = sw, name = f'UNINSTALL [{aid}]')


    def get_data(self):
        if self.authenticated == True:
            pass


    def get_status(self):
        if self.authenticated == True:
            pass