# -*- coding: utf-8 -*-
"""Protocol message objects"""
import base64
import hashlib
import struct
import time
from abc import ABC, abstractmethod

from . import shared, structure


class IMessage(ABC):
    """A base for typical message"""
    @abstractmethod
    def __repr__(self):
        """Make a printable form"""

    @abstractmethod
    def to_bytes(self):
        """Serialize to bytes the full message"""

    @classmethod
    @abstractmethod
    def from_message(cls, m):
        """Parse from message"""


class Header(structure.IStructure):
    """Message header structure"""
    def __init__(self, command, payload_length, payload_checksum):
        self.command = command
        self.payload_length = payload_length
        self.payload_checksum = payload_checksum

    def __repr__(self):
        return (
            'type: header, command: "{}", payload_length: {},'
            ' payload_checksum: {}'
        ).format(
            self.command.decode(), self.payload_length,
            base64.b16encode(self.payload_checksum).decode())

    def to_bytes(self):
        b = b''
        b += shared.magic_bytes
        b += self.command.ljust(12, b'\x00')
        b += struct.pack('>L', self.payload_length)
        b += self.payload_checksum
        return b

    @classmethod
    def from_bytes(cls, b):
        magic_bytes, command, payload_length, payload_checksum = struct.unpack(
            '>4s12sL4s', b)

        if magic_bytes != shared.magic_bytes:
            raise ValueError('magic_bytes do not match')

        command = command.rstrip(b'\x00')

        return cls(command, payload_length, payload_checksum)


class Message(structure.IStructure):
    """Common message structure"""
    def __init__(self, command, payload):
        self.command = command
        self.payload = payload

        self.payload_length = len(payload)
        self.payload_checksum = hashlib.sha512(payload).digest()[:4]

    def __repr__(self):
        return '{}, payload_length: {}, payload_checksum: {}'.format(
            self.command.decode(), self.payload_length,
            base64.b16encode(self.payload_checksum).decode())

    def to_bytes(self):
        b = Header(
            self.command, self.payload_length, self.payload_checksum
        ).to_bytes()
        b += self.payload
        return b

    @classmethod
    def from_bytes(cls, b):
        h = Header.from_bytes(b[:24])

        payload = b[24:]
        payload_length = len(payload)

        if payload_length != h.payload_length:
            raise ValueError(
                'wrong payload length, expected {}, got {}'.format(
                    h.payload_length, payload_length))

        payload_checksum = hashlib.sha512(payload).digest()[:4]

        if payload_checksum != h.payload_checksum:
            raise ValueError(
                'wrong payload checksum, expected {}, got {}'.format(
                    h.payload_checksum, payload_checksum))

        return cls(h.command, payload)


def _payload_read_int(data):
    varint_length = structure.VarInt.length(data[0])
    return (
        structure.VarInt.from_bytes(data[:varint_length]).n,
        data[varint_length:])


class Version(IMessage):
    """The version message payload"""
    def __init__(
        self, host, port,
        nonce=shared.nonce, services=shared.services,
        *, streams=None, user_agent=shared.user_agent,
        protocol_version=shared.protocol_version,
    ):
        self.host = host
        self.port = port

        self.protocol_version = protocol_version
        self.services = services
        self.nonce = nonce
        self.user_agent = user_agent
        self.streams = streams or [shared.stream]
        if len(self.streams) > 160000:
            self.streams = self.streams[:160000]

    def __repr__(self):
        return (
            'version, protocol_version: {}, services: {}, host: {}, port: {},'
            ' nonce: {}, user_agent: {}').format(
                self.protocol_version, self.services, self.host, self.port,
                base64.b16encode(self.nonce).decode(), self.user_agent)

    def to_bytes(self):
        payload = b''
        payload += struct.pack('>I', self.protocol_version)
        payload += struct.pack('>Q', self.services)
        payload += struct.pack('>Q', int(time.time()))
        payload += structure.NetAddrNoPrefix(
            1, self.host, self.port).to_bytes()
        payload += structure.NetAddrNoPrefix(
            self.services, '127.0.0.1', 8444).to_bytes()
        payload += self.nonce
        payload += structure.VarInt(len(self.user_agent)).to_bytes()
        payload += self.user_agent
        payload += structure.VarInt(len(self.streams)).to_bytes()
        for stream in self.streams:
            payload += structure.VarInt(stream).to_bytes()

        return Message(b'version', payload).to_bytes()

    @classmethod
    def from_message(cls, m):
        payload = m.payload

        (  # unused: net_addr_local
            protocol_version, services, timestamp, net_addr_remote, _, nonce
        ) = struct.unpack('>IQQ26s26s8s', payload[:80])

        if abs(time.time() - timestamp) > 3600:
            raise ValueError('remote time offset is too large')

        net_addr_remote = structure.NetAddrNoPrefix.from_bytes(net_addr_remote)

        host = net_addr_remote.host
        port = net_addr_remote.port

        payload = payload[80:]

        user_agent_length, payload = _payload_read_int(payload)
        user_agent = payload[:user_agent_length]
        payload = payload[user_agent_length:]

        streams_count, payload = _payload_read_int(payload)
        if streams_count > 160000:
            raise ValueError('malformed Version message, to many streams')
        streams = []

        while payload:
            stream, payload = _payload_read_int(payload)
            streams.append(stream)

        if streams_count != len(streams):
            raise ValueError('malformed Version message, wrong streams_count')

        return cls(
            host, port, nonce, services, streams=streams,
            protocol_version=protocol_version, user_agent=user_agent)


class Inv(IMessage):
    """The inv message payload"""
    def __init__(self, vectors):
        self.vectors = set(vectors)

    def __repr__(self):
        return 'inv, count: {}'.format(len(self.vectors))

    def to_bytes(self):
        return Message(
            b'inv', structure.VarInt(len(self.vectors)).to_bytes()
            + b''.join(self.vectors)
        ).to_bytes()

    @classmethod
    def from_message(cls, m):
        payload = m.payload

        vector_count, payload = _payload_read_int(payload)

        vectors = set()

        while payload:
            vectors.add(payload[:32])
            payload = payload[32:]

        if vector_count != len(vectors):
            raise ValueError('malformed Inv message, wrong vector_count')

        return cls(vectors)


class GetData(IMessage):
    """The getdata message payload"""
    def __init__(self, vectors):
        self.vectors = set(vectors)

    def __repr__(self):
        return 'getdata, count: {}'.format(len(self.vectors))

    def to_bytes(self):
        return Message(
            b'getdata', structure.VarInt(len(self.vectors)).to_bytes()
            + b''.join(self.vectors)
        ).to_bytes()

    @classmethod
    def from_message(cls, m):
        payload = m.payload

        vector_count, payload = _payload_read_int(payload)

        vectors = set()

        while payload:
            vectors.add(payload[:32])
            payload = payload[32:]

        if vector_count != len(vectors):
            raise ValueError('malformed GetData message, wrong vector_count')

        return cls(vectors)


class Addr(IMessage):
    """The addr message payload"""
    def __init__(self, addresses):
        self.addresses = addresses

    def __repr__(self):
        return 'addr, count: {}'.format(len(self.addresses))

    def to_bytes(self):
        return Message(
            b'addr', structure.VarInt(len(self.addresses)).to_bytes()
            + b''.join({addr.to_bytes() for addr in self.addresses})
        ).to_bytes()

    @classmethod
    def from_message(cls, m):
        payload = m.payload

        # not validating addr_count
        _, payload = _payload_read_int(payload)

        addresses = set()

        while payload:
            addresses.add(structure.NetAddr.from_bytes(payload[:38]))
            payload = payload[38:]

        return cls(addresses)


class Error(IMessage):
    """The error message payload"""
    def __init__(self, error_text=b'', fatal=0, ban_time=0, vector=b''):
        self.error_text = error_text
        self.fatal = fatal
        self.ban_time = ban_time
        self.vector = vector

    def __repr__(self):
        return 'error, text: {}'.format(self.error_text)

    def to_bytes(self):
        return Message(
            b'error', structure.VarInt(self.fatal).to_bytes()
            + structure.VarInt(self.ban_time).to_bytes()
            + structure.VarInt(len(self.vector)).to_bytes() + self.vector
            + structure.VarInt(len(self.error_text)).to_bytes()
            + self.error_text
        ).to_bytes()

    @classmethod
    def from_message(cls, m):
        payload = m.payload
        fatal, payload = _payload_read_int(payload)
        ban_time, payload = _payload_read_int(payload)
        vector_length, payload = _payload_read_int(payload)
        vector = payload[:vector_length]
        payload = payload[vector_length:]
        error_text_length, payload = _payload_read_int(payload)
        error_text = payload[:error_text_length]

        return cls(error_text, fatal, ban_time, vector)
