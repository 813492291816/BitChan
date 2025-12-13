# -*- coding: utf-8 -*-
"""Protocol structures"""
import base64
import binascii
import hashlib
import logging
import re
import socket
import struct
import time
from abc import ABC, abstractmethod

from . import shared


class IStructure(ABC):
    """A base for typical structure"""
    @abstractmethod
    def to_bytes(self):
        """Serialize to bytes"""

    @classmethod
    @abstractmethod
    def from_bytes(cls, b):
        """Parse from bytes"""


class VarInt(IStructure):
    """varint object"""
    def __init__(self, n):
        self.n = n

    def to_bytes(self):
        if self.n < 0xfd:
            return struct.pack('>B', self.n)

        if self.n <= 0xffff:
            return b'\xfd' + struct.pack('>H', self.n)

        if self.n <= 0xffffffff:
            return b'\xfe' + struct.pack('>I', self.n)

        return b'\xff' + struct.pack('>Q', self.n)

    @staticmethod
    def length(b):
        """Get the varint length"""
        if b == 0xfd:
            return 3
        if b == 0xfe:
            return 5
        if b == 0xff:
            return 9
        return 1

    @classmethod
    def from_bytes(cls, b):
        if cls.length(b[0]) > 1:
            b = b[1:]
        n = int.from_bytes(b, 'big')
        return cls(n)


class Object():
    """The 'object' message payload"""
    def __init__(
        self, expires_time, object_type, version, stream_number,
        *, data=None, offset=None, object_payload=None,
        tag=None, nonce=b'\x00' * 8, vector=None
    ):
        self.nonce = nonce
        self.expires_time = expires_time
        self.object_type = object_type
        self.version = version
        self.stream_number = stream_number
        if not data:
            data, offset = self.to_bytes(object_payload)
        self.data = data
        self.offset = offset
        self.vector = vector or hashlib.sha512(hashlib.sha512(
            self.data).digest()).digest()[:32]

        self.tag = tag or (
            # broadcast from version 5 and pubkey/getpukey from version 4
            (object_payload or self.object_payload)[:32]
            if object_type == 3 and version == 5
            or (object_type in (0, 1) and version == 4)
            else None)

    def __repr__(self):
        return 'object, vector: {}'.format(
            base64.b16encode(self.vector).decode())

    @classmethod
    def from_message(cls, m):
        """Decode message payload"""
        data = m.payload
        nonce, expires_time, object_type = struct.unpack('>8sQL', data[:20])
        version_varint_length = VarInt.length(data[20])
        offset = 20 + version_varint_length
        version = VarInt.from_bytes(data[20:offset]).n
        stream_number_varint_length = VarInt.length(data[offset])
        stream_number = VarInt.from_bytes(
            data[offset:offset+stream_number_varint_length]).n
        offset += stream_number_varint_length
        return cls(
            expires_time, object_type, version, stream_number,
            data=data, offset=offset, nonce=nonce
        )

    @property
    def object_payload(self):
        return self.data[self.offset:]

    def to_bytes(self, object_payload):
        """Serialize to bytes"""
        payload = b''
        payload += self.nonce
        payload += struct.pack('>QL', self.expires_time, self.object_type)
        payload += (
            VarInt(self.version).to_bytes()
            + VarInt(self.stream_number).to_bytes())
        return payload + object_payload, len(payload)

    def is_expired(self):
        """Check if object's TTL is expired"""
        return self.expires_time + 3 * 3600 < time.time()

    def is_valid(self):
        """Checks the object validity"""
        if self.is_expired():
            logging.debug(
                'Invalid object %s, reason: expired',
                base64.b16encode(self.vector).decode())
            return False
        if self.expires_time > time.time() + 28 * 24 * 3600 + 3 * 3600:
            logging.warning(
                'Invalid object %s, reason: end of life too far in the future',
                base64.b16encode(self.vector).decode())
            return False
        if len(self.object_payload) > 2**18:
            logging.warning(
                'Invalid object %s, reason: payload is too long',
                base64.b16encode(self.vector).decode())
            return False
        if self.stream_number != shared.stream:
            logging.warning(
                'Invalid object %s, reason: not in stream %i',
                base64.b16encode(self.vector).decode(), shared.stream)
            return False

        pow_value = int.from_bytes(
            hashlib.sha512(hashlib.sha512(
                self.nonce + self.pow_initial_hash()
            ).digest()).digest()[:8], 'big')
        target = self.pow_target()
        if target < pow_value:
            logging.warning(
                'Invalid object %s, reason: insufficient pow',
                base64.b16encode(self.vector).decode())
            return False
        return True

    def pow_target(self):
        """Compute PoW target"""
        data = self.data[8:]
        length = len(data) + 8 + shared.payload_length_extra_bytes
        dt = max(self.expires_time - time.time(), 0)
        return int(
            2 ** 64 / (
                shared.nonce_trials_per_byte * (
                    length + (dt * length) / (2 ** 16))))

    def pow_initial_hash(self):
        """Compute the initial hash for PoW"""
        return hashlib.sha512(self.data[8:]).digest()


class NetAddrNoPrefix(IStructure):
    """Network address"""
    def __init__(self, services, host, port):
        self.services = services
        self.host = host
        self.port = port

    def __repr__(self):
        return 'net_addr_no_prefix, services: {}, host: {}, port {}'.format(
            self.services, self.host, self.port)

    def to_bytes(self):
        b = b''
        b += struct.pack('>Q', self.services)
        try:
            host = socket.inet_pton(socket.AF_INET, self.host)
            b += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF' + host
        except socket.error:
            b += socket.inet_pton(socket.AF_INET6, self.host)
        b += struct.pack('>H', int(self.port))
        return b

    @staticmethod
    def network_group(host):
        """A simplified network group identifier from pybitmessage protocol"""
        try:
            host = socket.inet_pton(socket.AF_INET, host)
            return host[:2]
        except socket.error:
            try:
                host = socket.inet_pton(socket.AF_INET6, host)
                return host[:12]
            except OSError:
                return host
        except TypeError:
            return host

    @classmethod
    def from_bytes(cls, b):
        services, host, port = struct.unpack('>Q16sH', b)
        if host.startswith(
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF'):
            host = socket.inet_ntop(socket.AF_INET, host[-4:])
        else:
            host = socket.inet_ntop(socket.AF_INET6, host)
        return cls(services, host, port)


class NetAddr(IStructure):
    """Network address with time and stream"""
    def __init__(self, services, host, port, stream=shared.stream):
        self.stream = stream
        self.services = services
        self.host = host
        self.port = port

    def __repr__(self):
        return 'net_addr, stream: {}, services: {}, host: {}, port {}'.format(
            self.stream, self.services, self.host, self.port)

    def to_bytes(self):
        b = b''
        b += struct.pack('>Q', int(time.time() - 5400))
        b += struct.pack('>I', self.stream)
        b += NetAddrNoPrefix(self.services, self.host, self.port).to_bytes()
        return b

    @classmethod
    def from_bytes(cls, b):
        stream, net_addr = struct.unpack('>QI26s', b)[1:]
        n = NetAddrNoPrefix.from_bytes(net_addr)
        return cls(n.services, n.host, n.port, stream)


class OnionPeer():
    """An object, containing onion peer info"""
    def __init__(self, host, port=8444, stream=None, dest_pub=None):
        self.stream = stream or shared.stream
        self.host = host
        self.port = port
        try:
            self.dest_pub = dest_pub or base64.b32decode(
                re.search(r'(.*)\.onion', host).groups()[0], True)
        except (AttributeError, binascii.Error) as e:
            raise ValueError('Malformed hostname') from e

    def __repr__(self):
        return 'onion_peer, stream: {}, host: {}, port {}'.format(
            self.stream, self.host, self.port)

    def to_object(self):
        """Encode the onion peer to the `Object`"""
        payload = b''
        payload += VarInt(self.port).to_bytes()
        payload += b'\xfd\x87\xd8\x7e\xeb\x43'
        payload += self.dest_pub
        return Object(
            int(time.time() + 8 * 3600), shared.onion_obj_type,
            shared.onion_obj_version, self.stream, object_payload=payload)

    @classmethod
    def from_object(cls, obj):
        """Decode the onion peer from an `Object` instance"""
        payload = obj.object_payload
        port_length = VarInt.length(payload[0])
        port = VarInt.from_bytes(payload[:port_length]).n
        if payload[port_length:port_length + 6] != b'\xfd\x87\xd8\x7e\xeb\x43':
            raise ValueError('Malformed onion peer object')
        dest_pub = payload[port_length + 6:]
        host = base64.b32encode(dest_pub).lower().decode() + '.onion'
        return cls(host, port, obj.stream_number, dest_pub)
