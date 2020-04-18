# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import logging
import os
import struct
import time
from io import BytesIO
from typing import Tuple
from typing_extensions import Protocol as StructuralType
from .. import mapping, protobuf, messages
from ..log import DUMP_BYTES
from . import Transport

REPLEN = 64
BLE_REPLEN = 192
REPLEN_NFC = 1024
V2_FIRST_CHUNK = 0x01
V2_NEXT_CHUNK = 0x02
V2_BEGIN_SESSION = 0x03
V2_END_SESSION = 0x04
PROCESS_REPORTER = None
HTTP = False
OFFSET = 0
TOTAL = 0

LOG = logging.getLogger(__name__)


class Handle(StructuralType):
    """PEP 544 structural type for Handle functionality.
    (called a "Protocol" in the proposed PEP, name which is impractical here)

    Handle is a "physical" layer for a protocol.
    It can open/close a connection and read/write bare data in 64-byte chunks.

    Functionally we gain nothing from making this an (abstract) base class for handle
    implementations, so this definition is for type hinting purposes only. You can,
    but don't have to, inherit from it.
    """

    def open(self) -> None:
        ...

    def close(self) -> None:
        ...

    def read_chunk(self) -> bytes:
        ...

    def write_chunk(self, chunk: bytes) -> None:
        ...

    def write_chunk_nfc(self, chunk: bytearray) -> bytes:
        ...

    def read_ble(self) -> bytes:
        ...


class Protocol:
    """Wire protocol that can communicate with a Trezor device, given a Handle.

    A Protocol implements the part of the Transport API that relates to communicating
    logical messages over a physical layer. It is a thing that can:
    - open and close sessions,
    - send and receive protobuf messages,
    given the ability to:
    - open and close physical connections,
    - and send and receive binary chunks.

    We declare a protocol version (we have implementations of v1 and v2).
    For now, the class also handles session counting and opening the underlying Handle.
    This will probably be removed in the future.

    We will need a new Protocol class if we change the way a Trezor device encapsulates
    its messages.
    """

    VERSION = None  # type: int

    def __init__(self, handle: Handle) -> None:
        self.handle = handle
        self.session_counter = 0

    # XXX we might be able to remove this now that TrezorClient does session handling
    def begin_session(self) -> None:
        if self.session_counter == 0:
            self.handle.open()
        self.session_counter += 1

    def end_session(self) -> None:
        if self.session_counter == 1:
            self.handle.close()
        self.session_counter -= 1

    def read(self) -> protobuf.MessageType:
        raise NotImplementedError

    def write(self, message: protobuf.MessageType) -> None:
        raise NotImplementedError

    def nfc_send(self, message: protobuf.MessageType) -> protobuf.MessageType:
        raise NotImplementedError

    def ble_read(self) -> protobuf.MessageType:
        raise NotImplementedError

    def write_ble(self, message):
        pass


class ProtocolBasedTransport(Transport):
    """Transport that implements its communications through a Protocol.

    Intended as a base class for implementations that proxy their communication
    operations to a Protocol.
    """

    def __init__(self, protocol: Protocol) -> None:
        self.protocol = protocol

    def write(self, message: protobuf.MessageType) -> None:
        self.protocol.write(message)

    def write_ble(self, message: protobuf.MessageType) -> None:
        self.protocol.write_ble(message)

    def send_nfc(self, message: protobuf.MessageType) -> protobuf.MessageType:
        return self.protocol.nfc_send(message)

    def read_ble(self) -> protobuf.MessageType:
        return self.protocol.ble_read()

    def read(self) -> protobuf.MessageType:
        return self.protocol.read()

    def begin_session(self) -> None:
        self.protocol.begin_session()

    def end_session(self) -> None:
        self.protocol.end_session()


class ProtocolV1(Protocol):
    """Protocol version 1. Currently (11/2018) in use on all Trezors.
    Does not understand sessions.
    """

    VERSION = 1

    def write(self, msg: protobuf.MessageType) -> None:
        global PROCESS_REPORTER
        LOG.debug(
            "sending message: {}".format(msg.__class__.__name__),
            extra={"protobuf": msg},
        )
        data = BytesIO()
        protobuf.dump_message(data, msg)
        ser = data.getvalue()
        LOG.log(DUMP_BYTES, "sending bytes: {}".format(ser.hex()))
        header = struct.pack(">HL", mapping.get_type(msg), len(ser))
        buffer = bytearray(b"##" + header + ser)
        origin = len(buffer)
        send_len = 0 - len(header) - 2
        while buffer:
            if PROCESS_REPORTER and origin >= 64:
                left = round(len(buffer) / origin, 2)
                PROCESS_REPORTER.publishProgress(int((1 - left) * 100))
                if len(buffer) <= 64:
                    PROCESS_REPORTER = None
                if send_len >= 64 * 1024:
                    # resp = self.ble_read()
                    # if isinstance(resp, messages.Success):
                    #     send_len = send_len - 64 * 1024
                    # else:
                    #     raise BaseException("update failed")
                    time.sleep(1)
                    send_len = send_len - 64 * 1024
            # Report ID, data padded to 63 bytes
            chunk = b"?" + buffer[: REPLEN - 1]
            chunk = chunk.ljust(REPLEN, b"\x00")
            time.sleep(0.002)
            self.handle.write_chunk(chunk)
            send_len = send_len + 63
            buffer = buffer[63:]

    def write_ble(self, msg: protobuf.MessageType) -> None:
        global PROCESS_REPORTER
        LOG.debug(
            "sending message: {}".format(msg.__class__.__name__),
            extra={"protobuf": msg},
        )
        data = BytesIO()
        protobuf.dump_message(data, msg)
        ser = data.getvalue()
        LOG.log(DUMP_BYTES, "sending bytes: {}".format(ser.hex()))
        header = struct.pack(">HL", mapping.get_type(msg), len(ser))
        buffer = bytearray(b"##" + header + ser)
        origin = len(buffer)
        send_len = 0 - len(header) - 2
        while buffer:
            if PROCESS_REPORTER and origin >= 64:
                left = round(len(buffer) / origin, 2)
                PROCESS_REPORTER.publishProgress(int((1 - left) * 100))
                if len(buffer) <= 64:
                    PROCESS_REPORTER = None
                if send_len >= 64 * 1024:
                    time.sleep(1)
                    send_len = send_len - 64 * 1024
            # Report ID, data padded to 63 bytes
            waiting_packets = buffer[:189]
            send_packets = []
            while waiting_packets:
                chunk = b"?" + waiting_packets[: REPLEN - 1]
                chunk = chunk.ljust(REPLEN, b"\x00")
                send_packets.extend(chunk)
                waiting_packets = waiting_packets[63:]
            time.sleep(0.005)
            print(f"send in ble =={bytes(send_packets).hex()}")
            self.handle.write_chunk(bytes(send_packets))
            send_len = send_len + 189
            buffer = buffer[189:]

    def nfc_send(self, msg: protobuf.MessageType) -> protobuf.MessageType:
        global PROCESS_REPORTER, HTTP, OFFSET
        LOG.debug(
            f"sending message: {msg.__class__.__name__}",
            extra={"protobuf": msg},
        )
        data = BytesIO()
        protobuf.dump_message(data, msg)
        ser = data.getvalue()
        header = struct.pack(">HL", mapping.get_type(msg), len(ser))
        buffer = bytearray(b"##" + header + ser)
        # split buffer into 64 bytes one package to send
        origin = len(buffer)
        send_len = 0 - len(header) - 2
        if HTTP and OFFSET:
            send_len = OFFSET
            origin = TOTAL
        while buffer:
            chunk = bytearray()
            # used for android update progress bar
            if PROCESS_REPORTER and origin >= 64:
                left = round(len(buffer) / origin, 2)
                PROCESS_REPORTER.publishProgress(int((1 - left) * 100))
                if len(buffer) <= 64:
                    PROCESS_REPORTER = None
                if send_len >= 64 * 1024:
                    send_len = send_len - 64 * 1024
                    time.sleep(1)
            # Report ID, data padded to 63 bytes
            chunk.extend(b"?" + buffer[: REPLEN - 1])
            chunk = chunk.ljust(REPLEN, b"\x00")
            print(f"send in nfc {bytes(chunk).hex()}")
            response = self.handle.write_chunk_nfc(chunk)
            print(f"receive ==== {response}")
            if response == b'\x90\x00':
                send_len = send_len + 63
                buffer = buffer[63:]
            else:
                print(f"unknown response {response}")
                raise BaseException("Unexpected response")
        print(f"send in nfc #**")
        response = b'#**'
        while response == b'#**':
            response = self.handle.write_chunk_nfc(bytearray(b'#**'))
        if response[:3] != b"?##":
            raise RuntimeError("Unexpected magic characters")
        try:
            headerlen = struct.calcsize(">HL")
            msg_type, data_len = struct.unpack(">HL", response[3: 3 + headerlen])
        except Exception:
            raise RuntimeError("Cannot parse header")
        print(f"receive response :{protobuf.load_message(BytesIO(response[3 + headerlen:]), mapping.get_class(msg_type))}")
        return protobuf.load_message(BytesIO(response[3 + headerlen:]), mapping.get_class(msg_type))

        """
        feitian do split but send onece
        """
        # buffer = bytearray(b"##" + header + ser)
        # chunk = bytearray()
        # while buffer:
        #     # Report ID, data padded to 63 bytes
        #     chunk.extend(b"?" + buffer[: REPLEN - 1])
        #     buffer = buffer[63:]
        # LOG.log(DUMP_BYTES, f"the final bytes sending to hardware: {chunk}")
        # response = self.handle.write_chunk_nfc(chunk)
        # if response[:3] != b"?##":
        #     raise RuntimeError("Unexpected magic characters")
        # try:
        #     headerlen = struct.calcsize(">HL")
        #     msg_type, data_len = struct.unpack(">HL", response[3: 3 + headerlen])
        # except Exception:
        #         raise RuntimeError("Cannot parse header")
        # clear_response = bytearray()
        # clear_response.extend(response[3+headerlen:64])
        # response = response[65:]
        # while response:
        #     clear_response.extend(response[:62])
        #     response = response[63:]
        # clear_response = clear_response[:data_len]
        # return protobuf.load_message(BytesIO(clear_response), mapping.get_class(msg_type))
        """
            old do not split
        """
        # buffer = bytearray(b"?##" + header + ser)
        # print(f"send in nfc ====={bytes(buffer).hex()}")
        # try:
        #     response = self.handle.write_chunk_nfc(buffer)
        # except BaseException as e:
        #     raise e
        # while response == b"#**":
        #     response = self.handle.write_chunk_nfc(bytearray(b"#**"))
        # if response[:3] != b"?##":
        #      raise RuntimeError("Unexpected magic characters")
        # try:
        #     print(f"receive response in nfc ==== {response}")
        #     headerlen = struct.calcsize(">HL")
        #     msg_type, _ = struct.unpack(">HL", response[3: 3 + headerlen])
        # except Exception:
        #     raise RuntimeError("Cannot parse header")
        # return protobuf.load_message(BytesIO(response[3+headerlen:]), mapping.get_class(msg_type))

    def ble_read(self) -> protobuf.MessageType:
        response = self.handle.read_ble()
        if response[:3] != b"?##":
             raise RuntimeError("Unexpected magic characters")
        try:
            headerlen = struct.calcsize(">HL")
            msg_type, _ = struct.unpack(">HL", response[3: 3 + headerlen])
        except Exception:
            raise RuntimeError("Cannot parse header")
        print(f"receive response in BLE ===={protobuf.load_message(BytesIO(response[3+headerlen:]), mapping.get_class(msg_type))}")
        return protobuf.load_message(BytesIO(response[3+headerlen:]), mapping.get_class(msg_type))

    def read(self) -> protobuf.MessageType:
        buffer = bytearray()
        # Read header with first part of message data
        msg_type, datalen, first_chunk = self.read_first()
        buffer.extend(first_chunk)

        # Read the rest of the message
        while len(buffer) < datalen:
            buffer.extend(self.read_next())

        # Strip padding
        ser = buffer[:datalen]
        data = BytesIO(ser)
        LOG.log(DUMP_BYTES, "received bytes: {}".format(ser.hex()))

        # Parse to protobuf
        msg = protobuf.load_message(data, mapping.get_class(msg_type))
        LOG.debug(
            "received message: {}".format(msg.__class__.__name__),
            extra={"protobuf": msg},
        )
        return msg

    def read_first(self) -> Tuple[int, int, bytes]:
        chunk = self.handle.read_chunk()
        if chunk[:3] != b"?##":
            raise RuntimeError("Unexpected magic characters")
        try:
            headerlen = struct.calcsize(">HL")
            msg_type, datalen = struct.unpack(">HL", chunk[3: 3 + headerlen])
        except Exception:
            raise RuntimeError("Cannot parse header")

        data = chunk[3 + headerlen:]
        return msg_type, datalen, data

    def read_next(self) -> bytes:
        chunk = self.handle.read_chunk()
        if chunk[:1] != b"?":
            raise RuntimeError("Unexpected magic characters")
        return chunk[1:]


class ProtocolV2(Protocol):
    """Protocol version 2. Currently (11/2018) not used.
    Intended to mimic U2F/WebAuthN session handling.
    """

    VERSION = 2

    def __init__(self, handle: Handle) -> None:
        self.session = None
        super().__init__(handle)

    def begin_session(self) -> None:
        # ensure open connection
        super().begin_session()

        # initiate session
        chunk = struct.pack(">B", V2_BEGIN_SESSION)
        chunk = chunk.ljust(REPLEN, b"\x00")
        self.handle.write_chunk(chunk)

        # get session identifier
        resp = self.handle.read_chunk()
        try:
            headerlen = struct.calcsize(">BL")
            magic, session = struct.unpack(">BL", resp[:headerlen])
        except Exception:
            raise RuntimeError("Cannot parse header")
        if magic != V2_BEGIN_SESSION:
            raise RuntimeError("Unexpected magic character")
        self.session = session

        LOG.debug("[session {}] session started".format(self.session))

    def end_session(self) -> None:
        if not self.session:
            return

        try:
            chunk = struct.pack(">BL", V2_END_SESSION, self.session)
            chunk = chunk.ljust(REPLEN, b"\x00")
            self.handle.write_chunk(chunk)
            resp = self.handle.read_chunk()
            (magic,) = struct.unpack(">B", resp[:1])
            if magic != V2_END_SESSION:
                raise RuntimeError("Expected session close")
            LOG.debug("[session {}] session ended".format(self.session))
        finally:
            self.session = None
            # close connection if appropriate
            super().end_session()

    def write(self, msg: protobuf.MessageType) -> None:
        if not self.session:
            raise RuntimeError("Missing session for v2 protocol")

        LOG.debug(
            "[session {}] sending message: {}".format(
                self.session, msg.__class__.__name__
            ),
            extra={"protobuf": msg},
        )
        # Serialize whole message
        data = BytesIO()
        protobuf.dump_message(data, msg)
        data = data.getvalue()
        dataheader = struct.pack(">LL", mapping.get_type(msg), len(data))
        data = dataheader + data
        seq = -1

        # Write it out
        while data:
            if seq < 0:
                repheader = struct.pack(">BL", V2_FIRST_CHUNK, self.session)
            else:
                repheader = struct.pack(">BLL", V2_NEXT_CHUNK, self.session, seq)
            datalen = REPLEN - len(repheader)
            chunk = repheader + data[:datalen]
            chunk = chunk.ljust(REPLEN, b"\x00")
            self.handle.write_chunk(chunk)
            data = data[datalen:]
            seq += 1

    def read(self) -> protobuf.MessageType:
        if not self.session:
            raise RuntimeError("Missing session for v2 protocol")

        buffer = bytearray()

        # Read header with first part of message data
        msg_type, datalen, chunk = self.read_first()
        buffer.extend(chunk)

        # Read the rest of the message
        while len(buffer) < datalen:
            next_chunk = self.read_next()
            buffer.extend(next_chunk)

        # Strip padding
        buffer = BytesIO(buffer[:datalen])

        # Parse to protobuf
        msg = protobuf.load_message(buffer, mapping.get_class(msg_type))
        LOG.debug(
            "[session {}] received message: {}".format(
                self.session, msg.__class__.__name__
            ),
            extra={"protobuf": msg},
        )
        return msg

    def read_first(self) -> Tuple[int, int, bytes]:
        chunk = self.handle.read_chunk()
        try:
            headerlen = struct.calcsize(">BLLL")
            magic, session, msg_type, datalen = struct.unpack(
                ">BLLL", chunk[:headerlen]
            )
        except Exception:
            raise RuntimeError("Cannot parse header")
        if magic != V2_FIRST_CHUNK:
            raise RuntimeError("Unexpected magic character")
        if session != self.session:
            raise RuntimeError("Session id mismatch")
        return msg_type, datalen, chunk[headerlen:]

    def read_next(self) -> bytes:
        chunk = self.handle.read_chunk()
        try:
            headerlen = struct.calcsize(">BLL")
            magic, session, sequence = struct.unpack(">BLL", chunk[:headerlen])
        except Exception:
            raise RuntimeError("Cannot parse header")
        if magic != V2_NEXT_CHUNK:
            raise RuntimeError("Unexpected magic characters")
        if session != self.session:
            raise RuntimeError("Session id mismatch")
        return chunk[headerlen:]


def get_protocol(handle: Handle, want_v2: bool) -> Protocol:
    """Make a Protocol instance for the given handle.

    Each transport can have a preference for using a particular protocol version.
    This preference is overridable through `TREZOR_PROTOCOL_V1` environment variable,
    which forces the library to use V1 anyways.

    As of 11/2018, no devices support V2, so we enforce V1 here. It is still possible
    to set `TREZOR_PROTOCOL_V1=0` and thus enable V2 protocol for transports that ask
    for it (i.e., USB transports for Trezor T).
    """
    force_v1 = int(os.environ.get("TREZOR_PROTOCOL_V1", 1))
    if want_v2 and not force_v1:
        return ProtocolV2(handle)
    else:
        return ProtocolV1(handle)
