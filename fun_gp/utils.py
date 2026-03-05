
def hex_to_bytes(ascii_str:str) -> list[int]:
    """
    Converts an input HEX-string into bytes.\n
    Raises exception if the given string will contain a value other than [0-9][a-f][A-F].\n
    :param ascii_str: a string input.\n
    """
    clean_str = ''.join(c for c in ascii_str if c.isalnum())
    if len(clean_str) % 2 != 0:
        raise ValueError(f'Input hex string has odd length ({len(clean_str)})')

    try:
        return list(bytes.fromhex(clean_str))
    except ValueError as e:
        raise ValueError(f'Non-hexadecimal character not allowed.')


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


def lv(hex_str:str) -> str:
    """
    lv stands for 'length-value' taken from TLV concept.  
    This function takes a hex string as an input and returns it without
    any transformation with its length (in hex) predended to it.
    
    :param hex_str: a string with hexadecimal values
    :returns: length + value string in hex
    """
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