from fun_gp.smart_card import SmartCard
from fun_gp.utils import lv

known_readers = ['ACS ACR39U ICC Reader 0', 'ACS ACR39U ICC Reader 00 00']
isd_default_keys = ["404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F"]

isd = SmartCard(known_readers, isd_default_keys)

isd.apdu_plain('00A4 0400' + lv('a000000151000000'))
#

isd.apdu_plain('80CA 2F00 02 5C00')
isd.apdu_plain('80CA 00E0 00')

# GP Common Implementation Configuration 
isd.apdu_plain('80CA 0042 00')
isd.apdu_plain('80CA 0045 00')
isd.apdu_plain('80CA 5F50 00')
isd.apdu_plain('80CA 00CF 00')
isd.apdu_plain('80CA 00E0 00')
isd.apdu_plain('80CA 00C1 00')
isd.apdu_plain('80CA 00C2 00')
isd.apdu_plain('80CA 0066 00')
isd.apdu_plain('80CA 0067 00')
