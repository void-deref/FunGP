from fun_gp import Reader, SmartCard, SCP02, CCM, hex_to_bytes, bytes_to_hex, lv_hex

isd_keyset = ['404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F','404142434445464748494A4B4C4D4E4F']
ssd_keyset = ['505152535455565758595A5B5C5D5E5F','505152535455565758595A5B5C5D5E5F','505152535455565758595A5B5C5D5E5F']

def install_applet():
    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(isd_keyset), CCM())
        isd.transmit('00a4 0400', 0x90, 0x00, 'Select ISD')
        isd.mutual_auth()
        cmd = lv_hex('00 00' + lv_hex('A0000001515350416D7920535344') + '000000')
        
        isd.transmit('80e4 2000' + cmd, 0x90, 0x00, 'INSTALL [for personalization] my SSD', is_secured=True)

        # dirty hacks: sharing a single value across all keys because they are identical
        key_encrypted = lv_hex(isd._scp02._apply_3des_cbc(hex_to_bytes(ssd_keyset[0]), isd._scp02.skey_dec))
        kcv = isd._scp02._apply_3des_cbc(hex_to_bytes('00000000 00000000'), hex_to_bytes(ssd_keyset[0]))[0:3]
        kcv = bytes_to_hex(kcv)

        b9_k1 = 'B9' + lv_hex(
            '95 01 18' # [Usage qualifier (clause 11.1.9)], C-ENC
            '96 01 01' # [Key access (clause 11.1.10)], SSD is the only user. (0x00 if not present)
            '80 01 80' # [Key type (clause 11.1.8)], DES - mode (ECB/CBC) implicitly known
            '81 01 10' # key length in bytes (unsigned int value)
            '82 01 01' # key ID
            '83 01 01' # KVN
            '84 03' + kcv # Key check value (appendix B.6)
        )

        b9_k2 = 'B9' + lv_hex(
            '95 01 14' # C-MAC
            '96 01 01'
            '80 01 80'
            '81 01 10'
            '82 01 02' # 02
            '83 01 01'
            '84 03' + kcv
        )

        b9_k3 = 'B9' + lv_hex(
            '95 01 48' # C-DEC
            '96 01 01'
            '80 01 80'
            '81 01 10'
            '82 01 03' # 03
            '83 01 01'
            '84 03' + kcv
        )
        
        _8113_k1 = '8113' + lv_hex(key_encrypted)
        _8113_k2 = '8113' + lv_hex(key_encrypted)
        _8113_k3 = '8113' + lv_hex(key_encrypted)

        cmd = '00b9' + lv_hex(b9_k1 + b9_k2 + b9_k3) + _8113_k1 + _8113_k2 + _8113_k3
        print(cmd)
        isd.transmit('00E2 8800' + lv_hex(cmd), 0x90, 0x00, 'Store data')


install_applet()