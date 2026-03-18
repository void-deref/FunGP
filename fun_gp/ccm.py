from fun_gp.utils import bytes_to_hex, hex_to_bytes, lv_hex, len_asn, lv_hex, lv_list
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
        self.params      = lv_list(load_params[0:]) if load_params != None else [0x00]
        self.token       = [0x00]
    
    def _build_list(self):
        return  self.package_aid + self.sd_aid + self.lfdbh + self.params + self.token

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())


class SIMParams:
    def __init__(self, msl:str='16', tar:str='544152'):
        """
        :param msl: exactly as SPI.1 byte, e.g. '16'
        :param tar: a TAR value represented as hex string
        """
        self.tag           = [0xCA]
        self.access_domain = [0x01, 0x00] # full access
        self.priority      = [0xFF]       # lowest priority
        self.timers        = [0x00]       # no timers needed for this applet
        self.text_length   = [0x00]       # Applet hasn't menu, thus there is no need for text length attribute
        self.menu_entries  = [0x00]       # No menu entries
        self.channels      = [0x01]       # one BIP channel required only
        self.msl           = lv_list('01' + msl) # Minimum SPI1
        self.tar           = lv_list(tar)
        
        self.tag = [0xEF] + lv_list(self.tag +
                                lv_list(self.access_domain + self.priority + self.timers + 
                                    self.text_length + self.menu_entries + self.channels + 
                                    self.msl + self.tar)
                                 + [0xCF, 0x00])
    def _build_list(self):
        return self.tag

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())
    

class UICCParams:
    def __init__(self, msl:str='16', tar:str='544152'):
        """
        :param msl: exactly as SPI.1 byte, e.g. '16'
        :param tar: a TAR value represented as hex string
        """
        self.priority      = [0xFF]       # lowest priority
        self.timers        = [0x00]       # no timers needed for this applet
        self.text_length   = [0x00]       # Applet hasn't menu, thus there is no need for text length attribute
        self.menu_entries  = [0x00]       # No menu entries
        self.channels      = [0x01]       # one BIP channel required only
        self.msl           = lv_list('01' + msl) # Minimum SPI1
        self.tar           = lv_list(tar)
        self.services      = [0x00]       # services

        self.toolkit_params = [0x80] + lv_list(self.priority + self.timers + self.text_length + self.menu_entries +
                                               self.channels + self.msl + self.tar + self.services)
        
        self.dap            = [0xC3, 0x00]
        self.access_params  = [0x81, 0x04, 0x00, 0x01, 0x00, 0x00] # full access
        self.admin_access   = [0x82, 0x04, 0x00, 0x01, 0x00, 0x00] # full access

        self. tag = [0xEA] + lv_list(self.toolkit_params + self.dap + self.access_params + self.admin_access)

    def _build_list(self):
        return self. tag

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())



class InstallParams:
    def __init__(self, app_params:str=None, sys_params:SIMParams|UICCParams|list[int]=None):
        self.app_params  = [0xC9] + lv_list(app_params) if app_params  != None else [0xC9, 0x00]
        self.sys_params  = sys_params[0:] if sys_params != None else []

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


class CardContentManagement:
    def __init__(self):
        self.cap_file_size = 0

    def _compile_for_load(self, package_aid:str, sd_aid:str=None) -> str:
        """
        GP 2.3, clause 11.5   
        
        Initiates various steps required for Card Content management.  
        More details can be found in README.md.
        """

        for_load = ForLoad(package_aid=package_aid, sd_aid=sd_aid, load_params=LoadParams())
        compiled = '80E6 0200 ' + lv_hex(bytes_to_hex(for_load[0:]))

        return compiled

    def _compile_load(self, cap_bytes:list) -> list[str]:
        """
        Transmits the Load File (.cap file).  
        More details can be found in README.md.
        """
        cap_len_asn = len_asn(cap_bytes)
        cap_len_asn = hex_to_bytes(cap_len_asn)

        cap_bytes = [0xC4] + cap_len_asn + cap_bytes
 
        chunk_size = 247
        total_len  = len(cap_bytes)
        p2 = 0
        compiled_chunk = []
        for i in range(0, total_len, chunk_size):
            
            if i + chunk_size > total_len:
                cmd = f'80E8 80{p2:02x} '
            else:
                cmd = f'80E8 00{p2:02x} '
            compiled_chunk.append(cmd + lv_hex(bytes_to_hex(cap_bytes[i:i+chunk_size])))
            p2 += 1

        return compiled_chunk

    def _compile_for_install(self, package_aid:str, applet_aid:str, install_params:InstallParams):

        install_params = ForInstall(package_aid, applet_aid, install_params)
        cmd = '80E6 0C00' + lv_hex(install_params[0:])
        return cmd

    def _compile_delete(self, package_aid:str='', applet_aid:str='', sw:int=0):
        aid = applet_aid
        p2  = 0x00
        if len(package_aid) != 0:
            aid = package_aid
            p2 =0x80
        
        cmd = f'80E4 00{p2:02x}' + lv_hex('4F' + lv_hex(aid))
        return aid, cmd

    def _parse_cap_file(self, cap_path:str):
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
    "Descriptor.cap", #(optional)
]