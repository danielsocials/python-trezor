import binascii
from typing import Iterable, Optional, cast

from . import TransportException
from .protocol import ProtocolBasedTransport, get_protocol, Handle, ProtocolV1
from cn.com.heaton.blelibrary.ble.callback import BleWriteCallback
from cn.com.heaton.blelibrary.ble import Ble
from cn.com.heaton.blelibrary.ble.queue import RequestTask
from cn.com.heaton.blelibrary.ble.model import BleDevice

class BlueToothHandler(Handle):
    BLE = None  # type: Ble
    # READ_CHARACTERISTIC = None #type: BluetoothGattCharacteristic
    BLE_DEVICE = None # type: BleDevice
    BLE_ADDRESS = ""  # type: str
    CALL_BACK = None  # type: BleWriteCallback
    RESPONSE = bytes()  # type: bytes

    def __init__(self) -> None:
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
        # self.BLE.writeQueue(RequestTask.newWriteTask(self.BLE_ADDRESS, chunks))
        print(f"write chunk ====={bytes(chunk).hex()}")
        success = self.BLE.write(self.BLE_DEVICE, chunks, self.CALL_BACK)
        print(f"send {success}")
        if not success:
            raise BaseException("send failed")
    @classmethod
    def read_ble(cls) -> bytes:
        while True:
            if cls.RESPONSE:
                new_response = bytes(cls.RESPONSE)
                cls.RESPONSE = bytes()
                return new_response


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
