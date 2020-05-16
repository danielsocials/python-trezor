import binascii
import time

from typing import Iterable, Optional, cast

from .protocol import ProtocolBasedTransport, get_protocol, Handle, ProtocolV1
from cn.com.heaton.blelibrary.ble.callback import BleWriteCallback
from cn.com.heaton.blelibrary.ble import Ble
from cn.com.heaton.blelibrary.ble.model import BleDevice

WRITE_SUCCESS = True


class BlueToothHandler(Handle):
    BLE = None  # type: Ble
    BLE_DEVICE = None  # type: BleDevice
    BLE_ADDRESS = ""  # type: str
    CALL_BACK = None  # type: BleWriteCallback
    RESPONSE = ''  # type: str

    def __init__(self) -> None:
        pass

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def write_chunk(self, chunk: bytes) -> None:
        global WRITE_SUCCESS
        global RESPONSE
        assert self.BLE is not None, "the bluetooth device is not available"
        chunks = binascii.unhexlify(bytes(chunk).hex())
        while True:
            if WRITE_SUCCESS:
                WRITE_SUCCESS = False
                success = self.BLE.write(self.BLE_DEVICE, chunks, self.CALL_BACK)
                if success:
                    RESPONSE = ''
                    return
                else:
                    raise BaseException("send failed")

            else:
                time.sleep(0.0001)

    @classmethod
    def read_ble(cls) -> bytes:
        start = int(time.time())
        while True:
            wait_seconds = int(time.time()) - start
            if cls.RESPONSE:
                new_response = bytes(binascii.unhexlify(cls.RESPONSE))
                cls.RESPONSE = ''
                return new_response
            elif wait_seconds >= 30:
                raise BaseException("read ble response timeout")
            else:
                time.sleep(0.001)


class BlueToothTransport(ProtocolBasedTransport):
    PATH_PREFIX = "bluetooth"
    ENABLED = True

    def __init__(
            self, device: str, handle: BlueToothHandler = None) -> None:
        assert handle is not None, "bluetooth handler can not be None"
        self.device = device
        self.handle = handle
        super().__init__(protocol=ProtocolV1(handle))

    def get_path(self) -> str:
        return self.device

    @classmethod
    def enumerate(cls) -> Iterable["BlueToothTransport"]:
        return [BlueToothTransport(cls.PATH_PREFIX, BlueToothHandler())]
