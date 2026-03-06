from fun_gp import SmartCard
from fun_gp.utils import lv

known_readers = ['ACS ACR39U ICC Reader 0', 'ACS ACR39U ICC Reader 00 00']
isd_default_keys = ["404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F"]

isd = SmartCard(known_readers, isd_default_keys)

isd.apdu_plain('00A4 0400' + lv('A00000008253696D706C65'), expected_sw=0x9000, name='SELECT: SimpleApplet')
isd.apdu_plain('0000 0000' + lv('1122334455'), expected_sw=0x9000, name='XOR input')
