import binascii
import time

from typing import Iterable, Optional, cast

from .protocol import ProtocolBasedTransport, get_protocol, Handle, ProtocolV1
from cn.com.heaton.blelibrary.ble.callback import BleWriteCallback
from cn.com.heaton.blelibrary.ble import Ble
from cn.com.heaton.blelibrary.ble.model import BleDevice



class BlueToothHandler(Handle):
    BLE = None  # type: Ble
    BLE_DEVICE = None  # type: BleDevice
    BLE_ADDRESS = ""  # type: str
    CALL_BACK = None  # type: BleWriteCallback
    RESPONSE = bytes()  # type: bytes

    def __init__(self) -> None:
        self.retry_count = 3
        pass

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def write_chunk(self, chunk: bytes) -> None:
        assert self.BLE is not None, "the bluetooth device is not available"
        chunks = binascii.unhexlify(bytes(chunk).hex())
        # if len(chunks) != 64:
        #     raise TransportException("Unexpected data length")
        count = 0
        success = False
        while count < self.retry_count and not success:
            success = self.BLE.write(self.BLE_DEVICE, chunks, self.CALL_BACK)
            if not success:
                count = count + 1
                time.sleep(1.15 * count)
        print(f"send {success}=====try: {count}")
        if not success:
            raise BaseException("send failed")

    @classmethod
    def read_ble(cls) -> bytes:
        start = int(time.time())
        while True:
            wait_seconds = int(time.time()) - start
            if cls.RESPONSE:
                new_response = bytes(cls.RESPONSE)
                cls.RESPONSE = bytes()
                return new_response
            elif wait_seconds >= 30:
                raise BaseException("read ble response timeout")


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
