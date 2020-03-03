from electrum.util import print_stderr, raw_input, _logger
from .ui import PIN_CURRENT, PIN_NEW, PIN_CONFIRM
from android.os import Handler

class CustomerUI:
    def __init__(self):
        pass

    pin = ''  # type: str
    passphrase = ''  # type: str
    state = 0  # type: int
    handler = None # type: Handler
    @classmethod
    def get_pin(cls, code) -> str:
        cls.code = code
        if cls.handler:
            if code == 'Enter a new PIN for your Trezor:':
                cls.handler.sendEmptyMessage(2)
            elif code == 'Enter your current Trezor PIN:':
                cls.handler.sendEmptyMessage(1)
        while True:
            if cls.pin != '':
                pin_current = cls.pin
                cls.pin = ''
                return pin_current

    @classmethod
    def set_state(cls, state):
        cls.state = state

    @classmethod
    def get_state(cls):
        state_current = cls.state
        cls.state = 0
        return state_current


    @classmethod
    def get_passphrase(cls) -> str:
        while True:
            if cls.passphrase != '':
                return cls.passphrase

    @classmethod
    def button_request(cls, code):
        return
    def finished(self):
        return
    def show_message(self, msg, on_cancel=None):
        return

    def prompt_auth(self, msg):
        import getpass
        print_stderr(msg)
        response = getpass.getpass('')
        if len(response) == 0:
            return None
        return response

    def yes_no_question(self, msg):
        print_stderr(msg)
        return False

    def stop(self):
        pass

    def show_error(self, msg, blocking=False):
        print_stderr(msg)

    def update_status(self, b):
        _logger.info(f'hw device status {b}')

