from fun_gp.utils import bytes_to_hex, hex_to_bytes, lv, len_asn
from zipfile import ZipFile

class ForLoadParams:
    """
    See GP Card specification 2.3, clause 11.5.2.3.7 'INSTALL Command Parameters' for more details.  
    
    :param nvm: optional string, if present its value must be within range '0000' to 'FFFF' 
    :param ram: optional string, if present its value must be within range '0000' to 'FFFF'  
    :param code: optional string, if present its value must be within range '0000' to 'FFFF'  
    """
    def __init__(self, nvm:str='FFFF', ram:str='FFFF', code:str='FFFF'):
        self.tag  = 0xef
        self.len  = 0
        self.nvm  = hex_to_bytes(f'c602 {nvm}')
        self.ram  = hex_to_bytes(f'c702 {ram}')
        self.code = hex_to_bytes(f'c802 {code}')

        self.len = len(self.nvm + self.ram + self.code)

    def _build_list(self):
        return [self.tag] + [self.len] + self.nvm + self.ram + self.code

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())
    

class ForLoadData:
    def __init__(self, package_aid:str, sd_aid:str=None, load_params:ForLoadParams=None):

        package_aid = hex_to_bytes(package_aid)
        sd_aid      = hex_to_bytes(sd_aid) if sd_aid != None else []
        
        self.package_len = len(package_aid)
        self.package = package_aid
        self.sd_len  = len(sd_aid)
        self.sd      = sd_aid
        self.lfdbh   = 0 # Length of Load File Data Block Hash, always 0
        self.params_len  = len(load_params) if load_params != None else 0
        self.params  = load_params if load_params != None else []
        self.lt      = 0 # Length of Load Token, always 0
    
    def _build_list(self):
        return  [self.package_len] + self.package    + \
                [self.sd_len]      + self.sd         + \
                [self.lfdbh]                         + \
                [self.params_len]  + self.params[0:] + \
                [self.lt]

    def __getitem__(self, index):
        return self._build_list()[index]

    def __len__(self):
        return len(self._build_list())
    

class CardContentManagement:
    def __init__(self):
        self.cap_file_size = 0


    def _compile_for_load(self, package_aid:str) -> str:
        """
        GP 2.3, clause 11.5   
        
        Initiates various steps required for Card Content management.  
        More details can be found in README.md.
        """

        for_load = ForLoadData(package_aid=package_aid, load_params=ForLoadParams())
        compiled = '80E6 0200 ' + lv(bytes_to_hex(for_load[0:]))

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
            compiled_chunk.append(cmd + lv(bytes_to_hex(cap_bytes[i:i+chunk_size])))
            p2 += 1

        return compiled_chunk


    def _compile_for_install(self, package_aid:str, applet_aid:str, app_params:str='', sys_params:str=''):

        cmd = '80E6 0C00' + lv(
            lv(package_aid) +
            lv(applet_aid) +
            lv(applet_aid) +
            '0100' +            # privileges
            lv(
                'C9' + lv(app_params)  +
                'EF' + lv(sys_params)) +
            '00'
        )
        # 84E60C00 37 05 A000000082 0BA00000008253696D706C65 0BA00000008253696D706C65 0100 C90C0BA00000008253696D706C6500E2D3AF0A2B4B20EC
        print(f'Package AID: {package_aid}\nApplet AID:  {applet_aid}\n')
        return cmd


    def _compile_delete(self, package_aid:str='', applet_aid:str='', sw:int=0):
        aid = applet_aid
        p2  = 0x00
        if len(package_aid) != 0:
            aid = package_aid
            p2 =0x80
        
        cmd = f'80E4 00{p2:02x}' + lv('4F' + lv(aid))
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