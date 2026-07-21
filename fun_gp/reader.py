from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnectionObserver import CardConnectionObserver
from smartcard.Exceptions import CardConnectionException, SmartcardException
from smartcard.CardConnection import CardConnection
import time

from fun_gp import SW_list, bytes_to_hex, hex_to_bytes


class SWMismatchException(SmartcardException):
    pass


class APDUTracer(CardConnectionObserver):
    def update(self, observable, handlers):
        match handlers.type:
            case 'connect':
                print(f"Connecting to '{observable.getReader()}' reader")
            case 'disconnect':
                print(f"Disconnecting from '{observable.getReader()}' reader")  # Исправлено
            case 'release':
                print(f"Releasing '{observable.getReader()}' reader")
            case 'command':
                raw_bytes = handlers.args[0]
                cmd = bytes_to_hex(raw_bytes[0:4])
                cmd += ' ' + bytes_to_hex(raw_bytes[4:5])
                if len(raw_bytes) > 5:
                    cmd += ' ' + bytes_to_hex(raw_bytes[5:])
                print(f'>> {cmd}')
            case 'response':
                sw1, sw2 = handlers.args[-2:]
                sw1sw2 = sw1 << 8 | sw2
                if sw1 in (0x61, 0x6C):
                    sw1sw2 = sw1sw2 & 0xFF00
                    attempts_left = f'({sw2} bytes remaining)'
                elif sw1 == 0x63:
                    sw1sw2 = sw1sw2 & 0xFFF0
                    attempts_left = f'({sw2 & 0x0F} attempts left)'
                else:
                    attempts_left = ''
                
                description = SW_list.get(sw1sw2, 'To be classified')
                if handlers.args[0]:
                    print(f'<< {bytes_to_hex(handlers.args[0])}')
                print(f'<< {sw1:02x}{sw2:02x} [ {description} {attempts_left}]')
            case _:
                print(f'Unknown event {handlers.type}')


class Reader:
    def __init__(self):
        self.card_req = CardRequest(timeout=None, cardType=AnyCardType())
        self.card_service = None
        self.tracer = APDUTracer()


    def connect(self):
        self.card_service = self.card_req.waitforcard()
        self.card_service.connection.addObserver(self.tracer)
        self.card_service.connection.connect()
        return self


    def disconnect(self):
        """Обычное закрытие соединения"""
        if self.card_service and self.card_service.connection:
            try:
                self.card_service.connection.deleteObserver(self.tracer)
                self.card_service.connection.release()
            except (CardConnectionException, SmartcardException) as e:
                # In the case of card ejection the release() method might throw an exception too.
                # Here we suppress it because there is nothing to release
                print(f"[Disconnect] Card already disconnected or removed: {e}")
            finally:
                self.card_service = None
                print('Reader: context has been released.')

 
    def plain_apdu(self, cmd:str|list, exp_sw1:int | None = None, exp_sw2 : int | None = None, cmd_name:str=None) -> tuple[list[int], int, int]:

        if isinstance(cmd, str):
            cmd = hex_to_bytes(cmd)

        if len(cmd) == 4:
            cmd.append(0)
        
        if cmd_name:
            print(f'\nCommand: {cmd_name}')
        
        startTime = time.time()
        resp, sw1, sw2 = self.card_service.connection.transmit(cmd)
        duration = time.time() - startTime

        if sw1 == 0x61:   # GET RESPONSE. See ISO 7816-3
            resp, sw1, sw2 =  self._61_procedure(sw2)
        elif sw1 == 0x6C: # See ETSI 102 221, clause 7.3.1.1.5 and annex 'C'
            resp, sw1, sw2 =  self._6c_procedure(cmd, sw2)
        print(f'duration: {str(round(duration, 2))}\n')
        
        is_sw1_mismatch = (exp_sw1 is not None and sw1 != exp_sw1)
        is_sw2_mismatch = (exp_sw2 is not None and sw2 != exp_sw2)
        if is_sw1_mismatch or is_sw2_mismatch:
            exp_sw1_str = f'{exp_sw1:02x}' if exp_sw1 is not None else 'xx'
            exp_sw2_str = f'{exp_sw2:02x}' if exp_sw2 is not None else 'xx'
            sw1sw2 = sw1 << 8 | sw2

            if sw1 == 0x63:
                attempts_left = sw2 & 0x0F
                sw1sw2 = sw1sw2 & 0xFFF0
            else:
                attempts_left = ''
            
            description = SW_list.get(sw1sw2, 'To be classified')
            raise SWMismatchException(f"\n\nCard response error: {description} {attempts_left}"
                                        f"\nexpected: {exp_sw1_str}{exp_sw2_str} "
                                        f"\ngot:      {sw1:02x}{sw2:02x} ")
        return resp, sw1, sw2


    def cold_reset(self) -> str:
        if not self.card_service or not self.card_service.connection:
            raise CardConnectionException("No active card connection to reset.")
        
        self.card_service.connection.reconnect(CardConnection.COLD_RESET)
        new_atr = bytes_to_hex(self.card_service.connection.getATR())
        print(f"[Cold reset] ATR: {new_atr}")
        return new_atr


    def warm_reset(self) -> str:
        if not self.card_service or not self.card_service.connection:
            raise CardConnectionException("No active card connection to reset.")
        
        self.card_service.connection.reconnect(CardConnection.WARM_RESET)
        new_atr = bytes_to_hex(self.card_service.connection.getATR())
        print(f"[Warm reset] ATR: {new_atr}")
        return new_atr


    def _61_procedure(self, sw2:int):
        """
        GET RESPONSE. See ISO 7816-3
        """
        accum = []
        while True:
            print(f'\nGet response: {sw2} more bytes')
            more_data = [0x00, 0xC0, 0x00, 0x00, sw2]
            resp, sw1, sw2 = self.card_service.connection.transmit(more_data)
            accum  += resp
            if sw1 != 0x61:
                break

        return accum, sw1, sw2


    def _6c_procedure(self, command:list, sw2:int):
        """
        ETSI 102 221, 7.3.1.1.5 and annex 'C'  
        Instructs to immediately resend the previous command header with Le set to SW2.
        
        :param command: a command to be resend with updated Le field
        :param response: used only to retrieve 6Cxx status word.
        """
        accum = []
        command[4] = sw2
        while True:
            print(f'\nRepeat command with Le set to {sw2:02x}')
            command, sw1, sw2 = self.card_service.connection.transmit(command)
            accum += command # trim the SW bytes
            if sw1 != 0x61:  # quit if SW1 isn't equal 61 (i.e, there is no more data to fetch)
                break
            command = [0x00, 0xC0, 0x00, 0x00, sw2]
        
        return accum, sw1, sw2
    

    def __enter__(self):
        self.connect()
        return self


    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
        return False



