
SW_list = {
    0x9000: "OK",
    0x6100: "Response bytes still available (ISO 7816)",
    0x6581: "Memory failure",
    0x6700: "Wrong length",
    0x6981: "Command incompatible with file structure",
    0x6982: "Security condition not satisfied",
    0x6985: "Conditions of use not satisfied",
    0x6a80: "The parameters in the data field are incorrect",
    0x6a82: "File not found",
    0x6a83: "Record not found",
    0x6a84: "Not enough memory space",
    0x6a86: "Incorrect P1 or P2 parameter",
    0x6a87: "Lc inconsistent with P1-P2",
    0x6a88: "Referenced data not found",
    0x6c00: "Response bytes still available (CAT)",
    0x6d00: "Instruction code not supported or invalid",
    0x6e00: "Class code not supported or invalid",
    0x6f00: "Command aborted more exact diagnosis not possible (e.g., operating system error)",

    ################# UICC (ETSI 102 221, clause 10.2)
    0x9100: "Normal ending, Proactive command is waiting",
    0x9200: "Extra information concerning an ongoing data transfer session",
    0x9300: "USAT is bisy",

    ################# Warnings
    0x6200: "Warining: NVM left unchanged",
    0x6281: "Warining: part of returned data may be corrupted",
    0x6282: "Warining: end of file/record reached before reading Le bytes or unsuccessful search",
    0x6283: "Warining: selected file invalidated",
    0x6285: "Warining: selected file in termination state",
    0x62f1: "Warining: more data available",
    0x62f2: "Warining: More data available and proactive command pending",
    0x62f3: "Warining: Response data available",
    0x63f1: "Warining: more data expected",
    0x63f2: "Warining: more data expected and proactive command pending",
    0x63c0: "Warining: Verification attemps left",
    ################# Errors
    0x6400: "state of NVM unchanged",
    0x6500: "state of NVM changed",

    0x6800: "CLA not supported: no further info",
    0x6881: "CLA not supported: logical channel not supported",
    0x6882: "CLA not supported: SM not supported",
    0x6b00: "wrong parameters P1-P2",
    
}