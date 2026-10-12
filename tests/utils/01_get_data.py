from fun_gp import Reader, lv_hex, parse_card_resources

param_list = [
    # ['FF 1F', 'Menu Parameters Tag |Described in [TS 102 226]'],
    # ['FF 20', 'Card Resources Tag Described in [TS 102 226]'],
    # ['FF 21', 'Extended Card Resources Tag Described in [TS 102 226]'],
    # ['7F 21', 'CASD certificate store (CASD only; see section 3.4) Described in section 3.3.2 of [Amd A].'],
    # ['BF 30', 'Forwarded CASD Data (if Confidential Setup of Secure Channel Keys is supported; see section 3.4). Described in section 3.3.4 of [Amd A].'],
    # ['00 42', 'Card Issuer or Security Domain Provider Identification Number'],
    # ['00 45', 'Card or Security Domain Image Number'],
    # ['5F 50', 'Security Domain Manager URL'],
    # ['00 CF', 'User Key Diversification Data'],
    # ['00 E0', 'Key Information Template'],
    # ['00 C1', 'Sequence Counter of the Default Key Set (if the SD supports SCP \'02\' or SCP \'03\' in pseudo random mode'],
    # ['00 C2', 'Confirmation Counter (if the SD has the Receipt Generation privilege)'],
    # ['00 66', 'Card or Security Domain Recognition Data'],
    # ['00 67', 'Card Capability Information (see section 3.2.3) (ISD only)'],
    ['9F 7F', 'CPLC']
]


def main():
    with Reader() as reader:
        reader.plain_apdu('00a4 0400', 0x90, 0x00, 'Select ISD')
        
        for params in param_list:
            p1p2 = params[0]
            desc = params[1]
            response, _, _ = reader.plain_apdu('80ca' + p1p2, cmd_name=desc)
            if p1p2 == 'FF 21':
                parse_card_resources(response)
main()