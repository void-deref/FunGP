from fun_gp.smart_card import SmartCard
from fun_gp.utils import lv

known_readers = ['ACS ACR39U ICC Reader 0', 'ACS ACR39U ICC Reader 00 00']
isd_default_keys = ["404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F"]

isd = SmartCard(known_readers, isd_default_keys)

isd.connect_to_first_available()

isd.apdu_plain('00A4 0400' + lv('a000000151000000'), expected_sw=0x9000, name='SELECT: isd')
#

isd.apdu_plain('80CA 2F00 02 5C00', expected_sw=0x9000, name='GET DATA: list of applications')
isd.apdu_plain('80CA 00E0 00',      expected_sw=0x9000, name='GET DATA: Key info template')

# GP Common Implementation Configuration 
isd.apdu_plain('80CA 0042 00', expected_sw=0x6A88, name='GET DATA: Issuer Identification Number')
isd.apdu_plain('80CA 0045 00', expected_sw=0x6A88, name='GET DATA: Card or Security Domain Image Number')
isd.apdu_plain('80CA 5F50 00', expected_sw=0x6A88, name='GET DATA: Security Domain Manager URL')
isd.apdu_plain('80CA 00CF 00', expected_sw=0x9000, name='GET DATA: User Key Diversification Data')
isd.apdu_plain('80CA 00E0 00', expected_sw=0x9000, name='GET DATA: Key info template')
isd.apdu_plain('80CA 00C1 00', expected_sw=0x9000, name='GET DATA: Sequence Counter of the Default Key Set')
isd.apdu_plain('80CA 00C2 00', expected_sw=0x9000, name='GET DATA: Confirmation Counter')
isd.apdu_plain('80CA 0066 00', expected_sw=0x9000, name='GET DATA: Card or Security Domain Recognition Data')
isd.apdu_plain('80CA 0067 00', expected_sw=0x9000, name='GET DATA: Card capability information')

isd.close_context()