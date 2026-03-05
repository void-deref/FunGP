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
            self.close_context()
            raise ValueError(f'The length of input data doesn\'t take into account the 8-byte C-MAC.'
                             + f'\n This causes the total length of CDATA equals {cmd[4]} bytes.')
        
        c_mac = self._retail_mac(cmd)

        cmd = cmd + c_mac
        name = '(SM) ' + name
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
            self.close_context()
            raise ValueError(
                f'Error: expected {expected_sw:#04x} got {actual_sw:#04x}\
                \n\t\t\t****************************** CAUTION! ******************************\
                \n\t\t\tFurther attempts with the same keys will irreversibly block the card!'
            )
        else:
            self.authenticated = True


    def install_app_scp02(self, cap_path:str, applet_params:str=''):
        """
        Install an applet through the SCP02 protocol.  
        
        :param cap_path: path to a cap file to be installed  
        :param applet_params: by default passes applet's AID. Additional params
        must be prepended with length value e.g. 'lv(pin) + lv(secret)' 
        so that the resulting string will have the following form  
        `[len][AID][len][pin][len][secret]`
        """

        cap_bytes, package_aid, applet_aid = self._parse_cap_file(cap_path)

        if len(applet_params) != 0:
            applet_params = lv(applet_aid) + applet_params
        else:
            applet_params = lv(applet_aid)

        self._install_for_load(self.apdu_scp02, package_aid)
        self._load(self.apdu_scp02, cap_bytes)
        self._install_for_install(self.apdu_scp02, package_aid, applet_aid, applet_params)


    def uninstall_app_scp02(self, package_aid:str='', applet_aid:str='', sw:int = 0):
        """
        Uninstalls previously installed applet. Note that uninstalling a package will
        lead to removing all relative applets too.
        
        :param package_aid: AID of a packed to be deleted with all its dependent applets.
        :param applet_aid: AID of an applet to be delete.
        """
        if len(package_aid) == 0 and len(applet_aid) == 0:
            self.close_context()
            raise ValueError('define either package or applet AID')
        
        self._delete(self.apdu_scp02, package_aid, applet_aid, sw)


    def get_data(self):
        if self.authenticated == True:
            pass


    def get_status(self):
        if self.authenticated == True:
            pass