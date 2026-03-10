from fun_gp import SmartCard
from fun_gp.utils import lv

known_readers = ['ACS ACR39U ICC Reader 0', 'ACS ACR39U ICC Reader 00 00']
isd_default_keys = ["404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F",
                    "404142434445464748494A4B4C4D4E4F"]

applets = [
    "../../resources/SimpleApplet.cap", # 'A000000082'
]
app_params = '00112233445566778899'
sys_params = 'C702FFFF C802FFFF'

isd = SmartCard(known_readers, isd_default_keys)

isd.apdu_plain('00A4 0400' + lv('a000000151000000'), expected_sw=0x9000, name='SELECT: isd')
isd.mutual_auth()

for cap in applets:
    isd.install_app_scp02(cap, app_params, sys_params)
