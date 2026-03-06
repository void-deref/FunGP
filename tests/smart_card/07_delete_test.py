from fun_gp.smart_card import SmartCard
from fun_gp.utils import lv

known_readers = ['ACS ACR39U ICC Reader 0', 'ACS ACR39U ICC Reader 00 00']
isd_default_keys = ["404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F"]

packages = [  
    'A000000082', # 'SimpleApplet.cap'
]

isd = SmartCard(known_readers, isd_default_keys)

isd.apdu_plain('00A4 0400' + lv('a000000151000000'), expected_sw=0x9000, name='SELECT: isd')
isd.mutual_auth()

for aid in packages:
    isd.uninstall_app_scp02(package_aid=aid)
