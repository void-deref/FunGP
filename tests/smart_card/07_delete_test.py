from fun_gp import SmartCard
from fun_gp.utils import lv_hex

known_readers    = ['ACS ACR39U ICC Reader 0', 'ACS ACR39U ICC Reader 00 00']
isd_default_keys = ["404142434445464748494A4B4C4D4E4F","404142434445464748494A4B4C4D4E4F","404142434445464748494A4B4C4D4E4F"]
package_aid      = 'A000000082', # 'SimpleApplet.cap'

isd = SmartCard(known_readers, isd_default_keys)
isd.apdu_plain('00A4 0400' + lv_hex('a000000151000000'), expected_sw=0x9000, name='SELECT: isd')
isd.mutual_auth()
isd.uninstall_app_scp02(package_aid=package_aid)
