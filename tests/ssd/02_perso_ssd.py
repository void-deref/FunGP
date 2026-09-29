from fun_gp import Reader, SmartCard, SCP02, CCM, hex_to_bytes, bytes_to_hex, lv_hex
from Crypto.Cipher import DES3, DES
isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
ssd_keyset = ['505152535455565758595A5B5C5D5E5F','505152535455565758595A5B5C5D5E5F','505152535455565758595A5B5C5D5E5F']

ssd_pkg = 'A000000151535041'
ssd_aid = ssd_pkg + '6D7920535344'

def personalize_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()
        
        isd.transmit(
            '80e6 2000' + lv_hex('0000' + lv_hex(ssd_aid) + '000000'),
            0x90, 0x00,
            'INSTALL [for personalization] my SSD',
            is_secured=True
        )


        key_padded    = isd._scp02._padding(hex_to_bytes(ssd_keyset[0]))
        key_encrypted = isd._scp02._apply_3des_cbc(key_padded, isd._scp02.skey_dek)

        print(f'Key padded   : {bytes_to_hex(key_padded)}')
        print(f'Key encrypted: {bytes_to_hex(key_encrypted)}')

        padded_kcv    = isd._scp02._padding(hex_to_bytes('00000000 00000000'))
        kcv           = isd._scp02._apply_3des_cbc(padded_kcv, hex_to_bytes(ssd_keyset[0]))
        kcv = kcv[0:3]
        kcv = bytes_to_hex(kcv)

        print(f'KCV padded    : {bytes_to_hex(padded_kcv)}')
        print(f'KCV           : {kcv}')

        

        # GPCS 2.3, table 11-92
        crt_k1 = 'B9' + lv_hex(
            '95 01 18' # C-ENC,                [Usage qualifier (clause 11.1.9)]
            '96 01 01' # SSD is the only user. [Key access (clause 11.1.10)], (0x00 if not present)
            '80 01 80' # DES - mode (ECB/CBC) implicitly known [Key type (clause 11.1.8)], 
            '81 01 10' # key length in bytes
            '82 01 01' # key ID (see GP CIC, clause 4, table 4-1)
            '83 01 20' # KVN    (see GP CIC, clause 4, table 4-1)
            '84 03' + kcv # Key check value    [appendix B.6]
        )

        crt_k2 = 'B9' + lv_hex(
            '95 01 14' # C-MAC
            '96 01 01'
            '80 01 80'
            '81 01 10'
            '82 01 02' # 02
            '83 01 20'
            '84 03' + kcv
        )

        crt_k3 = 'B9' + lv_hex(
            '95 01 48' # C-DEK
            '96 01 01'
            '80 01 80'
            '81 01 10'
            '82 01 03' # 03
            '83 01 20'
            '84 03' + kcv
        )

        # GPCS 2.3, 11.11.4
        key_info_data = '00b9' + lv_hex(crt_k1 + crt_k2 + crt_k3)

        # GPCS 2.3, 11.11.4.1.1
        sym_scheme = '8113' + lv_hex(key_encrypted) + '8113' + lv_hex(key_encrypted) + '8113' + lv_hex(key_encrypted)
        
        cmd = lv_hex(key_info_data + sym_scheme)
        # print(cmd)
        isd.transmit('80E2 8800' + cmd, 0x90, 0x00, 'Store data', is_secured=True)


personalize_applet()