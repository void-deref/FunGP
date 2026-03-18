
def hex_to_bytes(hex_str:str) -> list[int]:
    """
    Converts an input HEX-string into bytes.\n
    Raises exception if the given string will contain a value other than [0-9][a-f][A-F].\n
    :param ascii_str: a string input.\n
    """
    clean_str = ''.join(c for c in hex_str if c.isalnum())
    if len(clean_str) % 2 != 0:
        raise ValueError(f'Input hex string has odd length ({len(clean_str)})')

    return list(bytes.fromhex(clean_str))

def bytes_to_hex(byte_data:list, uppercase=True) -> str:
    """
    Converts an input of [list of ]bytes into the HEX-string.
    """
    b = bytes(byte_data)
    fmt = '{:02X}' if uppercase else '{:02x}'
    return ''.join(fmt.format(x) for x in b)


def parse_tlv(target_tag:int, buffer:list) -> list[int]:
    tag    = 0
    length = 1
    idx = 2

    if buffer[0] != 0x61:
        return []
    
    while idx < buffer[1]:
        tag    = buffer[idx]
        idx += 1
        length = buffer[idx]
        idx += 1
        if tag == target_tag:
            return buffer[idx: idx + length]
        else:
            idx += length
    return []

def lv_list(hex_str:str|list) -> list[int]:

    if isinstance(hex_str, list):
        hex_str = bytes_to_hex(hex_str)
    
    clean_str = ''.join(c for c in hex_str if c.isalnum())
    if len(clean_str) % 2 != 0:
        raise ValueError(f'Input hex string has odd length ({len(clean_str)})')
    
    str_len = len(clean_str) // 2

    return list(bytes.fromhex(f'{str_len:02x}' + clean_str))


def lv_hex(hex_str:str|list) -> str:
    """
    lv stands for 'length-value' taken from TLV concept.  
    This function takes a hex string as an input and returns it without
    any transformation with its length (in hex) predended to it.
    
    :param hex_str: a string with hexadecimal values
    :returns: length + value string in hex
    """

    if isinstance(hex_str, list):
        hex_str = bytes_to_hex(hex_str)
    
    clean_str = ''.join(c for c in hex_str if c.isalnum())
    if len(clean_str) % 2 != 0:
        raise ValueError(f'Input hex string has odd length ({len(clean_str)})')
    
    str_len = len(clean_str) // 2
    return f'{str_len:02x}' + clean_str


def lv_asn(an_array:list|str) -> str:
    """
    Same as 'len_asn', but also appends data hex string:  
    00-7F         - as is [hex string]    
    80-FF         - 8180:81FF [hex string]  
    0100 - FFFF   - 820100:82FFFF [hex string]  
    010000 FFFFFF - 83010000:83FFFFFF [hex string]  
    """

    if not isinstance(an_array, str):
        an_array = bytes_to_hex(an_array)
    
    clean_str = ''.join(c for c in an_array if c.isalnum())
    if len(clean_str) % 2 != 0:
        raise ValueError(f'Input hex string has odd length ({len(clean_str)})')
    
    str_len = len(clean_str) // 2

    if str_len <= 127:
        return f'{str_len:02x}' + clean_str
    else:
        hex_val = hex(str_len)[2:] # trim '0x' prefix
        
        if len(hex_val) % 2 != 0:  # prepend '0' to values like AF6 (if any)
            hex_val = '0' + hex_val
        
        num_bytes  = len(hex_val) // 2 # 0AF6 // 2 = 2. Two bytes are used to encode the length
        first_byte = 0x80 | num_bytes  # 0x80 | 2 = 82. 
        return f'{first_byte:02x}' + hex_val + clean_str


def len_asn(an_array:list|str) -> str:
    """
    Returns a length value formatted in accordance with BER-TLV requirements:  
    00-7F         - as is  
    80-FF         - 8180:81FF  
    0100- FFFF    - 820100:82FFFF  
    010000 FFFFFF - 83010000:83FFFFFF  
    """
    if not isinstance(an_array, str):
        an_array = bytes_to_hex(an_array)
    
    clean_str = ''.join(c for c in an_array if c.isalnum())
    if len(clean_str) % 2 != 0:
        raise ValueError(f'Input hex string has odd length ({len(clean_str)})')
    
    str_len = len(clean_str) // 2

    if str_len <= 127:
        return f'{str_len:02x}'
    else:
        hex_val = hex(str_len)[2:] # trim '0x' prefix
        
        if len(hex_val) % 2 != 0:  # prepend '0' to values like AF6 (if any)
            hex_val = '0' + hex_val
        
        num_bytes  = len(hex_val) // 2 # 0AF6 // 2 = 2. Two bytes are used to encode the length
        first_byte = 0x80 | num_bytes  # 0x80 | 2 = 82. 
        return f'{first_byte:02x}' + hex_val



def decode_bcd(buffer:list|str):
    if isinstance(buffer, str):
        buffer = hex_to_bytes(buffer)
    
    # for each byte replace nibbles
    res = ''.join([f"{(b & 0xF):x}{(b >> 4):x}" for b in buffer])
    
    # truncate tailing 'f's and return
    return res.replace('f', '')


def encode_bcd(buffer:list|str):
    if isinstance(buffer, str):
        clean_str = ''.join(c for c in buffer if c.isalnum())

        if len(clean_str) % 2 != 0:
            clean_str = clean_str + 'f'

        buffer = hex_to_bytes(clean_str)
    
    # for each byte replace nibbles
    res = ''.join([f"{(b & 0xF):x}{(b >> 4):x}" for b in buffer])
    
    return res


def decode_ucs2(input:str|list) -> str:

    res = ''
    if len(input) == 0:
        return res
    
    if isinstance(input, str):
        input = hex_to_bytes(input)
    
    input      = bytearray(input)    
    first_byte = input[0]
    
    match first_byte:
        case 0x80 | 0x08:
            # UTF-16BE (ETSI 102 221 Annex A.1)
            res = input[1:].decode('utf-16-be')
        
        case 0x81:
            # Combined. Annex A.2
            length   = input[1]      # Number of chars in the string
            base_ptr = input[2] << 7 # Fetch the upper half of the 16-byte base pointer
            result   = []
            
            for i in range(3, 3 + length):
                char_byte = input[i]

                # if bit8 is set, then the remaining bits contain an offset value to be added to base pointer
                if char_byte & 0x80:
                    code_point = base_ptr + (char_byte & 0x7F)
                    result.append(chr(code_point))
                else:
                    # otherwise it's a regualr 7-bit GSM default alphabet character
                    result.append(chr(char_byte))
            res =  ''.join(result)
            
        case 0x82:
            res =  'Parsing for 0x82 (offset-based) not implemented'
            
        case _:
            # По умолчанию GSM 7/8 bit
            res =  input[1:].decode('latin-1')
    return res



def calculate_luhn_checksum(iccid_base):
    """
    Вычисляет контрольную цифру для ICCID (алгоритм Луна).
    iccid_base: строка с цифрами (обычно первые 18 цифр)
    """
    # Убеждаемся, что работаем только с цифрами
    digits = [int(d) for d in str(iccid_base) if d.isdigit()]
    
    # Итерируемся справа налево
    # Каждую ПЕРВУЮ цифру (если считать с конца перед добавлением чек-суммы) удваиваем
    # В алгоритме Луна для ICCID удваиваются цифры на нечетных позициях с конца
    total_sum = 0
    for i, val in enumerate(reversed(digits)):
        if i % 2 == 0:
            doubled = val * 2
            total_sum += doubled if doubled <= 9 else doubled - 9
        else:
            total_sum += val
            
    # Находим, сколько не хватает до ближайшего десятка
    checksum = (10 - (total_sum % 10)) % 10
    return checksum


def parse_card_resources(response:list):

    header_tag = int.from_bytes(response[0:2])
    if header_tag != 0xff21:
        raise ValueError(f'Expected \'FF21\', but got {header_tag:04x}')
    
    offset = 0
    total_length = response[2]
    value        = response[3:-2]

    while offset < total_length:
        tag     = value[offset]
        offset += 1
        length  = value[offset]
        offset += 1
        data    = value[offset: offset + length]
        match tag:
            case 0x81:
                print(f'total apps installed: {int.from_bytes(data)}')
            case 0x82:
                print(f'free NVM: {int.from_bytes(data)}')
            case 0x83:
                print(f'free RAM: {int.from_bytes(data)}')
        offset += length

lcs_dict = {
    '01':'OP_READY',
    '07':'INITIALIZED',
    '0F':'SECURED',
    '7F':'CARD_LOCKED',
    'FF':'TERMINATED',
}

aid_dict = {
    'A0000001510000'  :'ISD AID',
    'A000000151000000':'ISD AID',

    'A0000000620001':'java.lang',
    'A0000000620002':'java.io',
    'A0000000620003':'java.rmi',
    'A0000000620101':'javacard.framework',
    'A0000000620102':'javacard.security',
    'A0000000620201':'javacardx.crypto',
    
    'A0000000090003FFFFFFFF8910710001':'sim.access',
    'A0000000090003FFFFFFFF8910710002':'sim.toolkit',
    'A0000000090005FFFFFFFF8911000000':'uicc.access',
    'A0000000090005FFFFFFFF8912000000':'uicc.toolkit',
    'A0000000090005FFFFFFFF8913000000':'uicc.system',
    'A0000000090005FFFFFFFF8911010000':'uicc.access.fileadministration',
    'A0000000090005FFFFFFFF8911020000':'uicc.access.bertlvfile',
    'A0000000871005FFFFFFFF8913100000':'uicc.usim.access',
    'A0000000871005FFFFFFFF8913200000':'uicc.usim.toolkit',
    'A0000000871005FFFFFFFF8913300000':'uicc.usim.geolocation',
    'A0000000871005FFFFFFFF8913400000':'uicc.usim.suci',
}

def parse_status(data:list):
    
    offset = 0
    total_length = len(data)

    while offset < total_length:
        if data[offset] != 0xE3:
            raise ValueError(f'In Expect \'E3\' header tag, but got {data[0]:02x}')
        
        offset   += 1
        length_E3 = data[offset]

        offset  += 1
        content  = data[offset: offset + length_E3]
        content_len = len(content)
        sub_offset  = 0

        while sub_offset < content_len:
            tag = content[sub_offset]
            sub_offset += 1
            
            if tag == 0x9f:
                sub_offset += 1
            
            sub_length  = content[sub_offset]
            sub_offset += 1
            value       = bytes_to_hex(content[sub_offset: sub_offset + sub_length])
            match tag:
                case 0x4F:
                    print(f'\tAID: {value} ({aid_dict.get(value, '?')})')
                case 0x9F:
                    print(f'\tLCS: {lcs_dict.get(value, '?')}')
                case 0x84:
                    print(f'\tApplet AID: {value} ({aid_dict.get(value, '?')})')
                case 0xC4:
                    print(f'\tCAP file AID: {value} ({aid_dict.get(value, '?')})')
                case 0xC5:
                    print(f'\tPrivileges: {value}')
                case 0xCC:
                    print(f'\tAssociated Security Domain\'s AID: {value} ({aid_dict.get(value, '?')})')
                case 0xCE:
                    print(f'\tCAP file Version Number: {value}')
                case 0xCF:
                    print(f'\tImplicit Selection Parameter: {value}')
                case _ :
                        print(f'unknown tag \'{tag:02x}\'')
            sub_offset += sub_length
        offset += length_E3
    print('=================================\n')