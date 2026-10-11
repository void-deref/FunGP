from fun_gp import Reader, SmartCard, SCP02, CCM, InstallParams, SecurityLevel, hex_to_bytes, bytes_to_hex, lv_list, lv_hex
from params import isd_keyset, ssd_keyset, ssd_pkg, ssd_aid

def install_for_perso(isd:SmartCard, ssd_aid:str):
    isd.transmit(
        '80e6 2000' + lv_hex('0000' + lv_hex(ssd_aid) + '000000'),
        0x90, 0x00,
        'INSTALL [for personalization] my SSD'
    )


def encrypt_key(isd:SmartCard, ssd_key:str|list[int]) -> str:
    if isinstance(ssd_key, str):
        ssd_key = hex_to_bytes(ssd_key)

    key_encrypted = isd._scp02._apply_3des_ecb(ssd_key, isd._scp02.skey_dek)

    print(f'Original key : {bytes_to_hex(ssd_key)}')
    print(f'Encrypted Key: {bytes_to_hex(key_encrypted)}')

    return key_encrypted


def calculate_kcv(isd:SmartCard, ssd_key:str|list[int]) -> str:
    if isinstance(ssd_key, str):
        ssd_key = hex_to_bytes(ssd_key)
    
    kcv = isd._scp02._apply_3des_ecb(hex_to_bytes('00000000 00000000'), ssd_key)
    kcv = kcv[0:3]
    kcv = bytes_to_hex(kcv)

    print(f'KCV          : {kcv}')
    return kcv


def compile_key_crt(usage_qlfr:str, key_id:str, kvn:str, kcv:str) -> str:
    # GPCS 2.3, table 11-92
    key_crt = 'B9' + lv_hex(
        f'95 01 {usage_qlfr}'   # [Usage qualifier (clause 11.1.9)]
        '96 01 01'              # Key access: SSD is the only user. See clause 11.1.10, (0x00 if not present)
        '80 01 80'              # Key type:   DES mode (ECB/CBC) implicitly known. See clause 11.1.8.
        '81 01 10'              # key length: 16 bytes
        f'82 01 {key_id}'       # key ID (see GP CIC, clause 4, table 4-1)
        f'83 01 {kvn}'          # KVN    (see GP CIC, clause 4, table 4-1)
        f'84 03 {kcv}'          # Key check value. See appendix B.6
    )
    return key_crt


def personalize_ssd(isd:SmartCard):
    
    install_for_perso(isd, ssd_aid)

    key_enc = encrypt_key(isd, ssd_keyset[0])
    kcv_enc = calculate_kcv(isd, ssd_keyset[0])
    
    key_mac = encrypt_key(isd, ssd_keyset[1])
    kcv_mac = calculate_kcv(isd, ssd_keyset[1])

    key_dek = encrypt_key(isd, ssd_keyset[2])
    kcv_dek = calculate_kcv(isd, ssd_keyset[2])

    crt_enc = compile_key_crt('18', '01', '20', kcv_enc) # C-ENC: 18
    crt_mac = compile_key_crt('14', '02', '20', kcv_mac) # C-MAC: 14
    crt_dek = compile_key_crt('48', '03', '20', kcv_dek) # C-DEK: 48

    # GPCS 2.3, 11.11.4
    key_info_data = '00b9' + lv_hex(crt_enc + crt_mac + crt_dek) 

    # GPCS 2.3, 11.11.4.1.1
    sym_key_scheme = '8113' + lv_hex(key_enc) + '8113' + lv_hex(key_mac) + '8113' + lv_hex(key_dek)
    
    cmd = lv_hex(key_info_data + sym_key_scheme)
    # print(cmd)
    
    isd.transmit('80E2 8800' + cmd, 0x90, 0x00, 'Store data')


def install_ssd(isd:SmartCard):
    
    for_install = isd._ccm.make_cmd_install_for_install(
        load_file_aid  = 'A0000001515350',
        module_aid     = ssd_pkg,
        instance_aid   = ssd_aid, # my SSD
        install_params = InstallParams(
            # GP CIC, 3.3.1.3:
            # Tag '81' may be omitted only if the card supports only a single
            # SCP (i.e. obvious default value) or if the card otherwise supports a
            # default value or specific policy defined by the Card Issuer,
            # which remains out of scope of this document.
            '8102 0255' # SCP02, i=55
            '8201 20'   # accept extradition from ISD
        ),
        # the simulator accepts 800000, while real cards fail with SW 6A80.
        privileges = lv_list('80'),
    )

    isd.transmit(for_install, 0x90, 0x00, 'INSTALL[for install and make selectable]')


def main():
    sec_level = SecurityLevel.C_MAC
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth(security_level=sec_level)
        install_ssd(isd)
        personalize_ssd(isd)

main()