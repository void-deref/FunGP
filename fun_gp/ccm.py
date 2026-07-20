from fun_gp import bytes_to_hex, hex_to_bytes, lv_asn, lv_hex, lv_hex, lv_list
from zipfile import ZipFile


class LoadParams:
    """
    See GP Card specification 2.3, clause 11.5.2.3.7 'INSTALL Command Parameters' for more details.  
    
    :param nvm: optional string, if present its value must be within range '0000' to 'FFFF' 
    :param ram: optional string, if present its value must be within range '0000' to 'FFFF'  
    :param code: optional string, if present its value must be within range '0000' to 'FFFF'  
    """
    def __init__(self, nvm:str='FFFF', ram:str='FFFF', code:str='FFFF'):
        self.tag  = [0xef]
        self.nvm  = hex_to_bytes(f'c602 {nvm}')
        self.ram  = hex_to_bytes(f'c702 {ram}')
        self.code = hex_to_bytes(f'c802 {code}')

    def _build_list(self):
        return self.tag + lv_list(self.nvm + self.ram + self.code)

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())
    

class ForLoad:
    def __init__(self, package_aid:str, sd_aid:str=None, load_params:LoadParams=None):

        self.package_aid = lv_list(package_aid)
        self.sd_aid      = lv_list(sd_aid) if sd_aid != None else [0x00]
        self.lfdbh       = [0x00] # The length of Load File Data Block Hash is always '0'
        self.params      = lv_list(load_params[0:]) if load_params != None else []
        self.token       = [0x00]
    
    def _build_list(self):
        return  self.package_aid + self.sd_aid + self.lfdbh + self.params + self.token

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())


class InstallParams:
    def __init__(self, app_params:str=None):
        self.app_params  = [0xC9] + lv_list(app_params) if app_params != None else [0xC9, 0x00]
        self.sys_params = [0xEF, 0x00]

    def _build_list(self):
        return self.app_params + self.sys_params

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())
    

class ForInstall:
    def __init__(self, package_aid:str, applet_aid:str, install_params:InstallParams):
        self.package_aid = lv_list(package_aid)
        self.instace_aid = lv_list(applet_aid)
        self.applet_aid  = lv_list(applet_aid)

        self.privileges = [0x01, 0x00]

        self.params     = lv_list(install_params[0:])
        self.token      = [0x00]
    
    def _build_list(self):
        return  self.package_aid + self.instace_aid + self.applet_aid + \
                self.privileges + self.params + self.token

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())


class CCM:
    """ Card Content Management (see GlobalPlatfrom 2.3)"""
    def __init__(self):
        self.cap_file_size = 0
    

    def make_cmd_install_for_load(self, package_aid:str, sd_aid:str=None, load_params:LoadParams=LoadParams()) -> str:
        """
        GP 2.3, clause 11.5   
        
        Initiates various steps required for Card Content management.  
        More details can be found in README.md.
        """
        for_load = ForLoad(package_aid, sd_aid, load_params)
        compiled = '80E6 0200 ' + lv_hex(bytes_to_hex(for_load[0:]))
        return compiled


    def make_cmd_load(self, cap_bytes:list, chunk_size:int=247, add_cmd='') -> list[str]:
        """
        Transmits the Load File (.cap file).  
        More details can be found in README.md.
        """
        cap_bytes = 'C4' + lv_asn(cap_bytes) # mind the ASN format of the length field
        cap_bytes = hex_to_bytes(cap_bytes)
        total_len = len(cap_bytes)
        p2 = 0
        cmd_list = []
        for i in range(0, total_len, chunk_size):
            
            if i + chunk_size > total_len:
                cmd = f'80E8 80{p2:02x} '
            else:
                cmd = f'80E8 00{p2:02x} '
            cmd_list.append(cmd + lv_hex(cap_bytes[i:i+chunk_size]) + add_cmd)
            p2 += 1

        return cmd_list


    def make_cmd_install_for_install(self, package_aid:str, applet_aid:str, install_params:InstallParams):
        install_params = ForInstall(package_aid, applet_aid, install_params)
        cmd = '80E6 0C00' + lv_hex(install_params[0:])
        return cmd


    def make_cmd_delete(self, pkg_aid:str=None, app_aid:str=None):
        
        if pkg_aid is None and app_aid is None:
            raise ValueError(f'Either PKG AID or APPLET AID must be defined')
        
        # the package AID has priority over applet AID.
        target_aid, p2 = (pkg_aid, 0x80) if pkg_aid else (app_aid, 0x00)
        cmd = f'80E4 00{p2:02x}' + lv_hex('4F' + lv_hex(target_aid))
        return cmd


    def decomposite_cap_file(self, cap_path:str):
        raw_bytes = None
        cap_bytes = []
        package_aid = []

        with ZipFile(cap_path, 'r') as jar:

            for comp in Components:    
                for file in jar.namelist():

                    if not file.endswith(comp):
                        continue

                    with jar.open(file) as f:
                        raw_bytes = f.read()

                    if comp.lower() == "header.cap":
                        aid_len     = raw_bytes[12]
                        package_aid = raw_bytes[13:13 + aid_len]
                    
                    if comp.lower() == "applet.cap":
                        aid_len    = raw_bytes[4]
                        applet_aid = raw_bytes[5:5 + aid_len]
                    
                    cap_bytes.extend(raw_bytes)

        self.cap_file_size = len(cap_bytes)
        return cap_bytes, bytes_to_hex(package_aid), bytes_to_hex(applet_aid)


Components = [
    "Header.cap",
    "Directory.cap",
    "Import.cap",
    "Applet.cap", #(optional)
    "Class.cap",
    "Method.cap",
    "StaticField.cap",
    "Export.cap",
    "ConstantPool.cap",
    "RefLocation.cap", #(optional)
    # "Descriptor.cap", #(optional)
]