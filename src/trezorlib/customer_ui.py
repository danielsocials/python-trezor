import time

from electrum.util import print_stderr, raw_input, _logger

from android.os import Handler


class CustomerUI:
    def __init__(self):
        pass

    pin = ''  # type: str
    passphrase = ''  # type: str
    user_cancel = 0
    pass_state = 0
    handler = None  # type: Handler

    @classmethod
    def get_pin(cls, code) -> str:
        cls.code = code
        if cls.handler:
            if code == 'Enter a new PIN for your Trezor:':
                cls.handler.sendEmptyMessage(2)
            elif code == 'Enter your current Trezor PIN:':
                cls.handler.sendEmptyMessage(1)
        start = int(time.time())
        while True:
            wait_seconds = int(time.time()) - start
            if cls.user_cancel:
                cls.user_cancel = 0
                raise BaseException("user cancel")
            elif cls.pin != '':
                pin_current = cls.pin
                cls.pin = ''
                return pin_current
            elif wait_seconds >= 60:
                raise BaseException("waiting pin timeout")
            else:
                time.sleep(0.001)


    @classmethod
    def set_pass_state(cls, state):
        cls.pass_state = state

    @classmethod
    def get_pass_state(cls):
        pass_state_current = cls.pass_state
        cls.pass_state = 0
        return pass_state_current

    @classmethod
    def get_state(cls):
        state_current = cls.state
        cls.state = 0
        return state_current

    @classmethod
    def get_passphrase(cls, msg) -> str:
        cls.code = msg
        if cls.pass_state == 0:
            return ''
        cls.pass_state = 0
        if cls.handler:
            if msg == ("Enter a passphrase to generate this wallet.  Each time "
                       "you use this wallet your Trezor will prompt you for the "
                       "passphrase.  If you forget the passphrase you cannot "
                       "access the bitcoins in the wallet."):
                cls.handler.sendEmptyMessage(6)
            elif msg == 'Enter the passphrase to unlock this wallet:':
                cls.handler.sendEmptyMessage(3)
        start = int(time.time())
        while True:
            wait_seconds = int(time.time()) - start
            if cls.user_cancel:
                cls.user_cancel = 0
                raise BaseException("user cancel")
            elif cls.passphrase != '':
                passphrase_current = cls.passphrase
                cls.passphrase = ''
                return passphrase_current
            elif wait_seconds >= 60:
                raise BaseException("waiting passphrase timeout")
            else:
                time.sleep(0.001)
            #

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
