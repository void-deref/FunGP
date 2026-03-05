from fun_gp.utils import bytes_to_hex, hex_to_bytes, lv, len_asn
from zipfile import ZipFile

class CardContentManagement:
    def __init__(self):
        self.cap_file_size = 0


    def _install_for_load(self, apdu_tx:callable, package_aid:str):
        """
        GP 2.3, clause 11.5   
        
        Initiates various stepsrequired for Card Content management.  
        More details can be found in README.md.
        """
        # isd_aid = 'a000000151000000'
        isd_aid = ''
        cmd = '80E6 0200 ' + lv(lv(package_aid) + lv(isd_aid) + '000000')
        apdu_tx(cmd, expected_sw = 0x9000, name = 'INSTALL[for load]')
        # print('INSTALL[for load]: ' + cmd)


    def _load(self, apdu_tx:callable, cap_bytes:list):
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
        for i in range(0, total_len, chunk_size):
            
            if i + chunk_size > total_len:
                cmd = f'80E8 80{p2:02x} ' + lv(bytes_to_hex(cap_bytes[i:i+chunk_size]))
            else:
                cmd = f'80E8 00{p2:02x} ' + lv(bytes_to_hex(cap_bytes[i:i+chunk_size]))
            
            apdu_tx(cmd, expected_sw = 0x9000, name = 'LOAD')
            p2 += 1
        
        print(f'***** Uploaded {self.cap_file_size} bytes *****\n')


    def _install_for_install(self, apdu_tx:callable, package_aid:str, applet_aid:str, applet_params=''):
        cmd = '80E6 0C00' + lv(
            lv(package_aid) +
            lv(applet_aid) +
            lv(applet_aid) +
            '0100' +
            lv('C9' + lv(applet_params)) +
            '00'
        )
        # 84E60C00 37 05 A000000082 0BA00000008253696D706C65 0BA00000008253696D706C65 0100 C90C0BA00000008253696D706C6500E2D3AF0A2B4B20EC
        print(f'Package AID: {package_aid}\nApplet AID: {applet_aid}')
        apdu_tx(cmd, expected_sw = 0x9000, name = 'INSTALL[for install and make selectable]')


    def _delete(self, apdu_tx:callable, package_aid:str='', applet_aid:str='', sw:int=0):
        aid = ''
        if len(package_aid) != 0:
            aid = package_aid
            cmd = '80E4 0080' + lv('4F' + lv(package_aid))
        else:
            aid = applet_aid
            cmd = '80E4 0000' + lv('4F' + lv(applet_aid))
        

        apdu_tx(cmd, expected_sw = sw, name = f'UNINSTALL[{aid}]')


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
                    
                    cap_bytes = cap_bytes + list(raw_bytes)

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