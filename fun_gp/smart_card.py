from fun_gp import SCP02, CCM, LoadParams, InstallParams
import os

class SmartCard:
    def __init__(self, plain_apdu:callable, scp02:SCP02=None, ccm:CCM=None):
        self._plain_apdu = plain_apdu
        self._scp02      = scp02
        self._ccm        = ccm


    def transmit(self, cmd:str|list, exp_sw1:int|None = None, exp_sw2:int|None = None, cmd_name:str='', is_secured=False) -> tuple[list[int], int, int]:
        if is_secured:
            cmd = self._scp02.make_scp02_packet(cmd)
        return self._plain_apdu(cmd, exp_sw1, exp_sw2, cmd_name)


    def mutual_auth(self, exp_sw1:int|None = None, exp_sw2:int|None = None):
        host_challenge = list(os.urandom(8))
        cmd_init_update = [0x80, 0x50, 0x00, 0x00, 0x08] + host_challenge
        resp, sw1, sw2 = self.transmit(cmd_init_update, exp_sw1, exp_sw2, cmd_name = 'Initialize update')

        counter, card_challenge, host_challenge = self._scp02.init_update(resp, host_challenge)
        cmd_ext_auth = self._scp02.external_authenticate(counter, card_challenge, host_challenge)

        resp, sw1, sw2 = self.transmit(cmd_ext_auth, cmd_name='External authenticate')
        if sw1 != 0x90 or sw2 != 0x00:
            raise ValueError(
                f'Error: expected 0x9000 got {sw1:02x}{sw2:02x}\
                \n\t\t\t****************************** CAUTION! ******************************\
                \n\t\t\tFurther attempts with the same keys will irreversibly block the card!'
            )
        else:
            self._scp02.authenticated = True


    def install_app_scp02(self, cap_path:str, install_params:InstallParams, exp_sw1:int|None = None, exp_sw2:int|None = None, is_secured=True):
        """
        Install an applet through the SCP02 protocol.  
        
        :param cap_path: path to a cap file to be installed  
        :param install_params: by default passes applet's AID only. Additional params must
        be prepended with length value e.g.:  
        `lv(pin) + lv(secret)`
        so that the resulting string will have the following form:  
        `[len][AID] [len][pin] [len][secret]`
        
        """
        cap_bytes, pkg_aid, app_aid = self._ccm.decomposite_cap_file(cap_path)

        # INSTALL[for load]
        for_load = self._ccm.make_cmd_install_for_load(pkg_aid, None, LoadParams())
        self.transmit(for_load, exp_sw1, exp_sw2, 'INSTALL[for load]', is_secured=is_secured)
        
        # LOAD
        cap_chunks = self._ccm.make_cmd_load(cap_bytes)
        for chunk in cap_chunks:
            self.transmit(chunk, exp_sw1, exp_sw2, 'LOAD', is_secured=is_secured)

        # INSTALL[for install and make selectable]
        for_install = self._ccm.make_cmd_install_for_install(pkg_aid, app_aid, install_params)
        self.transmit(for_install, exp_sw1, exp_sw2, 'INSTALL[for install and make selectable]', is_secured=is_secured)
        
        # Note: 'LOAD.Lc1 + LOAD.Lc2 + LOAD.Lcn' is greater than 'self.cap_file_size'.
        # The difference is C * N + T, where
        # C - the length of CMAC,
        # N - number of LOAD commands,
        # T = C4 BER-TLV object at the beginning of the very first LOAD CDATA field.
        print(f'***** CAP-file size *****')
        print(f'\n***** CAP-file parameters *****\n'
            f'Package AID:    {pkg_aid}\n'
            f'Applet  AID:    {app_aid}\n'
            f'Applet  size:   {self._ccm.cap_file_size} bytes.\n')


    def uninstall_app_scp02(self, package_aid:str='', applet_aid:str='', exp_sw1:int|None = None, exp_sw2:int|None = None, is_secured=True):
        """
        Uninstalls previously installed applet. Note that uninstalling a package will
        lead to removing all relative applets too.
        
        :param package_aid: AID of a packed to be deleted with all its dependent applets.
        :param applet_aid: AID of an applet to be delete.
        """

        if len(package_aid) == 0 and len(applet_aid) == 0:
            raise ValueError('define either package or applet AID')
        else:
            aid_str = package_aid if len(package_aid) != 0 else applet_aid

        cmd = self._ccm.make_cmd_delete(package_aid, applet_aid)
        self.transmit(cmd, exp_sw2, exp_sw2, f'UNINSTALL [{aid_str}]', is_secured=is_secured)
