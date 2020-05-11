import binascii
import time

import logging
from typing import Iterable
from android.hardware.usb import UsbDevice, UsbDeviceConnection, UsbEndpoint, UsbInterface, UsbManager, UsbRequest
from java.nio import ByteBuffer
from . import TransportException
from .protocol import ProtocolBasedTransport, ProtocolV1, Handle

LOG = logging.getLogger(__name__)

INTERFACE = 0
ENDPOINT = 1
DEBUG_INTERFACE = 1
DEBUG_ENDPOINT = 2
Timeout = 100
forceClaim = True
USB_Manager = None
USB_DEVICE = None


class AndroidUsbHandle(Handle):
    USB_Manager = None
    USB_DEVICE = None

    def __init__(self) -> None:
        self.device = USB_DEVICE  # type: UsbDevice
        self.manger = USB_Manager  # type: UsbManager
        self.interface = None  # type: UsbInterface
        self.endpoint_in = None  # type: UsbEndpoint
        self.endpoint_out = None # type: UsbEndpoint
        self.handle = None  # type: UsbDeviceConnection

    def open(self) -> None:
        assert self.device is not None, "Android USB is not available"
        self.interface = self.device.getInterface(0)
        self.endpoint_in = self.interface.getEndpoint(0)
        self.endpoint_out = self.interface.getEndpoint(1)
        self.handle = self.manger.openDevice(self.device)
        success = self.handle.claimInterface(self.interface, forceClaim)
        if not success:
            raise BaseException("claimed failed")

    def close(self) -> None:
        if self.handle is not None:
            self.handle.releaseInterface(self.interface)
            self.handle.close()
        self.handle = None

    def write_chunk(self, chunk: bytes) -> None:
        assert self.handle is not None
        chunks = binascii.unhexlify(bytes(chunk).hex())
        if len(chunk) != 64:
            raise TransportException("Unexpected chunk size: %d" % len(chunk))
        request = UsbRequest()
        request.initialize(self.handle, self.endpoint_out)
        success = request.queue(ByteBuffer.wrap(chunks))
        if success:
            self.handle.requestWait()
        else:
            raise BaseException('android_usb send failed')

    def read_chunk(self) -> bytes:
        assert self.handle is not None
        response = ByteBuffer.allocate(64)
        request = UsbRequest()
        request.initialize(self.handle, self.endpoint_in)
        success = request.queue(response)
        if success:
            self.handle.requestWait()
        else:
            raise BaseException('android_usb read failed')
        return bytes(response.array())


class AndroidUsbTransport(ProtocolBasedTransport):
    """
    AndroidUsbTransport implements transport over WebUSB interface.
    """

    PATH_PREFIX = "android_usb"
    ENABLED = True

    def __init__(
            self, device: str, handle: AndroidUsbHandle = None) -> None:
        assert handle is not None, "android usb handler can not be None"
        self.device = device
        self.handle = handle

        super().__init__(protocol=ProtocolV1(handle))

    def get_path(self) -> str:
        return self.device

    @classmethod
    def enumerate(cls) -> Iterable["AndroidUsbTransport"]:
        return [AndroidUsbTransport(cls.PATH_PREFIX, AndroidUsbHandle())]
