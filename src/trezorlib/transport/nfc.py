import time

import logging
from typing import Iterable, Optional
from .protocol import ProtocolBasedTransport, ProtocolV1, Handle
from java.io import IOException
import binascii
LOG = logging.getLogger(__name__)

try:
    from android.nfc import NfcAdapter
    from android.nfc.tech import IsoDep
    from android.nfc import Tag
    from java import cast
except Exception as e:
    LOG.warning("NFC transport is Unavailable: {}".format(e))


class NFCHandle(Handle):
    device = None  # type:  Tag

    def __init__(self) -> None:
        self.device = cast(Tag, NFCHandle.device)
        self.handle = None  # type: Optional[IsoDep]
        self.transport = None
        self.sending = False

    def open(self) -> None:
        if self.device is not None:
            self.handle = IsoDep.get(self.device)
            try:
                self.handle.setTimeout(5000)
                self.handle.connect()
            except IOException as e:
                LOG.warning(f"NFC handler open exception {e.getMessage()}")
                raise BaseException(e)

    def close(self) -> None:
        while self.sending:
            time.sleep(0)
        if self.handle is not None:
            self.handle.close()
        self.handle = None

    def write_chunk_nfc(self, chunk: bytearray) -> bytes:
        assert self.handle is not None, "NFC handler is None"
        response = []
        chunks = binascii.unhexlify(bytes(chunk).hex())
        count = 0
        success = False
        self.sending = True
        while self.transport.running and count < 3 and not success:
            try:
                response =  bytes(self.handle.transceive(chunks))
                success = True
            except IOException as e:
                if  count < 2:
                    count = count + 1
                    print(f"send in nfc =====retry: {count}===={e.getMessage()}")
                    time.sleep(0.01)
                else:
                    self.sending = False
                    LOG.warning(f"NFC handler write exception {e.getMessage()}")
                    raise BaseException(e)
        self.sending = False
        return response


class NFCTransport(ProtocolBasedTransport):
    """
    """

    PATH_PREFIX = "nfc"
    ENABLED = True

    def __init__(
            self, device: str, handle: NFCHandle = None) -> None:
        assert handle is not None, "nfc handler can not be None"
        self.device = device
        self.handle = handle
        self.handle.transport = self
        super().__init__(protocol=ProtocolV1(handle))

    def get_path(self) -> str:
        return self.device

    @classmethod
    def enumerate(cls) -> Iterable["NFCTransport"]:
        return [NFCTransport(cls.PATH_PREFIX, NFCHandle(cls.client))]
