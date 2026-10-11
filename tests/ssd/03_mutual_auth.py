from fun_gp import Reader, SmartCard, SCP02, CCM, SecurityLevel, hex_to_bytes, bytes_to_hex, lv_hex
from Crypto.Cipher import DES3, DES
from params import isd_keyset, ssd_aid, ssd_keyset


def main():
    sec_level   = SecurityLevel.C_DECRYPTION

    with Reader() as reader:
        isd = SmartCard(reader.plain_apdu, SCP02(ssd_keyset), CCM())
        isd.transmit('00a4 0400' + lv_hex(ssd_aid), 0x90, 0x00, cmd_name='Select ISD secured applet')
        isd.mutual_auth(security_level=sec_level)

main()