from smartcard.scard import SCARD_SCOPE_USER, SCARD_S_SUCCESS, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_UNPOWER_CARD, SCARD_RESET_CARD
from smartcard.scard import SCardEstablishContext, SCardGetErrorMessage,         \
                            SCardListReaders, SCardReleaseContext, SCardConnect, \
                            SCardStatus,SCardDisconnect, SCardTransmit,          \
                            SCardReconnect


from fun_gp         import SW_list
from fun_gp.utils   import bytes_to_hex, hex_to_bytes
import time

class Reader:
    def __init__(self, known_readers):
        self.readers = known_readers
        self.card = 0
        self.protocol = None
        self.context = None
        self.connect_to_first_available()

    def __del__(self):
        self.close_context()

    def apdu_plain(self, cmd:list|str, expected_sw:int = 0, name:str = None):
        if isinstance(cmd, str): # transform hex string into byte array
            cmd = hex_to_bytes(cmd)
        
        if len(cmd) < 5:
            cmd = cmd + [0x00]
        
        if name != None:
            print(f'{name}')
        
        response, duration = self._command_apdu(cmd)
        self._response_apdu(response, duration)
        
        sw1 = response[-2]
        if sw1 == 0x61:   # GET RESPONSE. See ISO 7816-3
            response = self._61_procedure(response)

        elif sw1 == 0x6C: # See ETSI 102 221, clause 7.3.1.1.5 and annex 'C'
            response = self._6c_procedure(cmd, response)
        
        actual_sw = int.from_bytes(response[-2:], byteorder='big')
        if expected_sw != 0 and expected_sw != actual_sw:
            raise ValueError(f'expected {expected_sw:#04x} got {actual_sw:#04x} [{SW_list.get(actual_sw, "to be added to dictionary")}]')

        return response
    

    def connect_to_first_available(self):
        available_readers = self._get_available_readers_list()

        for known in self.readers:
            for available in available_readers:
                if available == known:
                    self.protocol = self._connect_card(available)
                    break
            if self.card == 0:
                continue
            else:
                break


    def close_context(self):
        result = SCardDisconnect(self.card, SCARD_UNPOWER_CARD)
        if result != SCARD_S_SUCCESS:
            print(f'Failed to disconnect card: [{SCardGetErrorMessage(result)}]')
        else:
            print(f'\nCard have been disconnected.')
        
        result = SCardReleaseContext(self.context)
        if result != SCARD_S_SUCCESS:
            print(f'Context already released.')
            # raise ValueError(f'Failed to release context: [{SCardGetErrorMessage(result)}]')
        else:
            print(f'Context released.')


    def warm_reset(self):
        result, active_protocol = SCardReconnect(
            self.card, 
            SCARD_SHARE_SHARED,
            SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, 
            SCARD_RESET_CARD  # Warm Reset
        )

        if result != SCARD_S_SUCCESS:
            print(f'Failed to release context: [{SCardGetErrorMessage(result)}]')
        else:
            print('Warm reset.')
            self.protocol = active_protocol
            self._get_card_info(active_protocol)
    

# =================================================================================
# INTERNAL METHODS
# =================================================================================

    def _get_available_readers_list(self):
        self._open_context()
        result, readers = SCardListReaders(self.context, [])
        if result != SCARD_S_SUCCESS:
            raise ValueError(f'Failed to retrieve a list of available readers [{SCardGetErrorMessage(result)}]')
        elif len(readers) < 1:
            raise ValueError('There is no connected readers at all.')
        else:
            print('Available PCSC readers:')
            for r in readers:
                print(f'    {r}')
            
        return readers
    

    def _connect_card(self, reader):
        result, self.card, dwActiveProtocol = SCardConnect(self.context, reader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)
        if result != SCARD_S_SUCCESS:
            raise ValueError(f'Failed to connect to card: [{SCardGetErrorMessage(result)}]')
        else:
            self._get_card_info(dwActiveProtocol)
        return dwActiveProtocol


    def _open_context(self):
        result, self.context = SCardEstablishContext(SCARD_SCOPE_USER)
        if result != SCARD_S_SUCCESS:
            raise ValueError(f'Failed to establish context: [{SCardGetErrorMessage(result)}]')
        else:
            print('Context established.')
    
    
    def _get_card_info(self, dwActiveProtocol):
        result, reader, state, protocol, atr = SCardStatus(self.card)
        if result != SCARD_S_SUCCESS:
            print(f'failed to fetch card status: [{SCardGetErrorMessage(result)}]')
        else:
            print(f'    {reader} (T={str(dwActiveProtocol)})')
            # print(f'state: {state:#02x}')
            print(f'    ATR: {bytes_to_hex(atr)}')


    def _command_apdu(self, command:list) -> tuple[list[int], float]:
        s = bytes_to_hex(command[0:4]) # CLA INS P1 P2
        s = s + ' ' + bytes_to_hex(command[4:5]) # LC
        
        if len(command) > 5:
            s = s + ' ' + bytes_to_hex(command[5:])
        
        print(f'>> {s}')
        
        startTime = time.time()
        result, response = SCardTransmit(self.card, self.protocol, command)
        duration = time.time() - startTime
        
        if result != SCARD_S_SUCCESS:
            print(f'>> {s}')
            raise ValueError(f'Failed to transmit: [{SCardGetErrorMessage(result)}]')

        return response, duration


    def _response_apdu(self, response:list, duration:float):
        data = None
        sw_int = int.from_bytes(response[-2:], byteorder='big')
        sw_str = bytes_to_hex(response[-2:])

        # Special cases: SW1 61, 6C, 91 and 92 are accompained with SW2 of unknown value
        sw1 = response[-2]
        if sw1 == 0x61 or sw1 == 0x6C or \
           sw1 == 0x91 or sw1 == 0x92:
                sw_int = sw_int & 0xFF00

        if len(response) > 2:
            data = bytes_to_hex(response[:-2])            
            print(f'<< {data}')

        print(f'SW: {sw_str} [{SW_list.get(sw_int, "to be added to dictionary")}]')
        print(f'duration: {str(round(duration, 2))}\n')


    # GET RESPONSE. See ISO 7816-3
    def _61_procedure(self, response:list):
        accum = []
        while True:
            more_data = [0x00, 0xC0, 0x00, 0x00] + [response[-1]]

            response, duration = self._command_apdu(more_data)
            self._response_apdu(response, duration)
            
            accum = accum + response[:-2] # trim the SW bytes
            if response[-2] != 0x61: # quit if SW1 isn't equal 61
                break

        # append SW which follows the last data block
        # being fetched from the final GET RESPONSE
        accum    = accum + response[-2:]
        response = accum
        return response
