# -*- coding: utf-8 -*-
"""The logic and behaviour of a single connection"""
import base64
import errno
import logging
import math
import os
import random
import re
import select
import socket
import ssl
import threading
import queue
import time

from . import message, shared, structure


class ConnectionBase(threading.Thread):
    """
    Common code for the connection thread
    with minimum command handlers to reuse
    """
    def __init__(self, host, port, s=None, server=False):
        self.host = host
        self.port = port
        self.network = 'i2p' if port == 'i2p' else 'ip'

        self.host_print = (
            self.host[:8].decode() if self.network == 'i2p' else self.host)

        super().__init__(name='Connection to {}:{}'.format(host, port))

        self.s = s
        self.server = server

        self.send_queue = queue.Queue()

        self.vectors_to_get = set()
        self.vectors_to_send = set()

        self.vectors_requested = {}

        self.status = 'connected' if bool(s) else 'ready'

        self.verack_received = False
        self.verack_sent = False

        self.remote_version = None

        self.buffer_receive = b''
        self.buffer_send = b''

        self.next_message_size = shared.header_length
        self.next_header = True
        self.on_connection_fully_established_scheduled = False

        self.last_message_received = time.time()
        self.last_message_sent = time.time()
        self.wait_until = 0

    def run(self):
        if self.s is None:
            self._connect()
        if self.status != 'connected':
            return
        self.s.settimeout(0)
        if not self.server:
            if self.network == 'ip':
                version_kwargs = (
                    {'services': 1} if self.host.endswith('.onion') else {})
                self.send_queue.put(message.Version(
                    ('127.0.0.1' if shared.socks_proxy else self.host),
                    self.port, **version_kwargs))
            else:
                self.send_queue.put(message.Version(
                    '127.0.0.1', 7656, nonce=self._get_nonce()))
        while True:
            if (
                self.on_connection_fully_established_scheduled
                and not (self.buffer_send or self.buffer_receive)
            ):
                self._on_connection_fully_established()
            data = True
            try:
                if self.status == 'fully_established':
                    data = self.s.recv(4096)
                    self.buffer_receive += data
                    if data and len(self.buffer_receive) < 4000000:
                        continue
                else:
                    data = self.s.recv(
                        self.next_message_size - len(self.buffer_receive))
                    self.buffer_receive += data
            except ssl.SSLWantReadError:
                if self.status == 'fully_established':
                    self._request_objects()
                    self._send_objects()
            except socket.error as e:
                err = e.args[0]
                if err in (errno.EAGAIN, errno.EWOULDBLOCK):
                    if self.status == 'fully_established':
                        self._request_objects()
                        self._send_objects()
                else:
                    logging.debug(
                        'Disconnecting from %s:%s. Reason: %s',
                        self.host_print, self.port, e)
                    data = None

            self._process_buffer_receive()
            self._process_queue()
            self._send_data()
            if time.time() - self.last_message_received > shared.timeout:
                logging.debug(
                    'Disconnecting from %s:%s. Reason:'
                    ' time.time() - self.last_message_received'
                    ' > shared.timeout', self.host_print, self.port)
                self.status = 'disconnecting'
            if (
                time.time() - self.last_message_received > 30
                and self.status != 'fully_established'
                and self.status != 'disconnecting'
            ):
                logging.debug(
                    'Disconnecting from %s:%s. Reason:'
                    ' time.time() - self.last_message_received > 30'
                    ' and self.status != "fully_established"',
                    self.host_print, self.port)
                self.status = 'disconnecting'
            if (
                time.time() - self.last_message_sent > 300
                and self.status == 'fully_established'
            ):
                self.send_queue.put(message.Message(b'ping', b''))
            if self.status == 'disconnecting' or shared.shutting_down:
                data = None
            if not data:
                self.status = 'disconnected'
                self.s.close()
                logging.info(
                    'Disconnected from %s:%s', self.host_print, self.port)
                break
            time.sleep(0.2)

    def _get_nonce(self):
        nonce = shared.nonce_pool.get(('127.0.0.1', 8448))
        if nonce is None:
            nonce = os.urandom(8)
            shared.nonce_pool[('127.0.0.1', 8448)] = nonce

        return nonce

    def _connect(self):
        peer_str = '{0.host_print}:{0.port}'.format(self)
        logging.debug('Connecting to %s', peer_str)

        try:
            self.s = socket.create_connection((self.host, self.port), 10)
            self.status = 'connected'
            logging.debug('Established TCP connection to %s', peer_str)
        except socket.timeout:
            pass
        except OSError as e:
            # unreachable, refused, no route
            (logging.info if e.errno not in (101, 111, 113)
             else logging.debug)(
                     'Connection to %s failed. Reason: %s', peer_str, e)
        except Exception:
            logging.info(
                'Connection to %s failed.', peer_str, exc_info=True)

        if self.status != 'connected':
            self.status = 'failed'

    def _send_data(self):
        if self.buffer_send and self:
            try:
                amount = self.s.send(self.buffer_send)
                self.buffer_send = self.buffer_send[amount:]
            except (BlockingIOError, ssl.SSLWantWriteError):
                pass
            except (
                BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError
            ) as e:
                logging.debug(
                    'Disconnecting from %s:%s. Reason: %s',
                    self.host_print, self.port, e)
                self.status = 'disconnecting'

    def _do_tls_handshake(self):
        logging.debug(
            'Initializing TLS connection with %s:%s',
            self.host_print, self.port)

        context = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH if self.server
            else ssl.Purpose.SERVER_AUTH
        )
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        if (
            ssl.OPENSSL_VERSION_NUMBER >= 0x10100000
            and not ssl.OPENSSL_VERSION.startswith("LibreSSL")
        ):  # OpenSSL>=1.1
            context.set_ciphers('AECDH-AES256-SHA@SECLEVEL=0')
        else:
            context.set_ciphers('AECDH-AES256-SHA')

        context.set_ecdh_curve("secp256k1")
        context.options = (
            ssl.OP_ALL | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            | ssl.OP_SINGLE_ECDH_USE | ssl.OP_CIPHER_SERVER_PREFERENCE)
        # OP_NO_SSL* is deprecated since 3.6
        try:
            # TODO: ssl.TLSVersion.TLSv1 is deprecated
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            pass

        self.s = context.wrap_socket(
            self.s, server_side=self.server, do_handshake_on_connect=False)

        while True:
            try:
                self.s.do_handshake()
                break
            except ssl.SSLWantReadError:
                select.select([self.s], [], [])
            except ssl.SSLWantWriteError:
                select.select([], [self.s], [])
            except Exception as e:
                logging.debug(
                    'Disconnecting from %s:%s. Reason: %s',
                    self.host_print, self.port, e)
                self.status = 'disconnecting'
                if isinstance(e, ssl.SSLError):  # pylint: disable=no-member
                    logging.debug('ssl.SSLError reason: %s', e.reason)
                    shared.node_pool.discard((self.host, self.port))
                return

        logging.debug(
            'Established TLS connection with %s:%s (%s)',
            self.host_print, self.port, self.s.version())

    def _send_message(self, m):
        if isinstance(m, message.Message) and m.command == b'object':
            logging.debug(
                '%s:%s <- %s',
                self.host_print, self.port, structure.Object.from_message(m))
        else:
            logging.debug('%s:%s <- %s', self.host_print, self.port, m)
        self.buffer_send += m.to_bytes()

    def _on_connection_fully_established(self):
        logging.info(
            'Established Bitmessage protocol connection to %s:%s',
            self.host_print, self.port)
        self.on_connection_fully_established_scheduled = False
        if (  # NODE_SSL
            self.remote_version.services & 2 and self.network == 'ip'
            and not self.host.endswith('.onion')
            and not (self.server and shared.tor)
        ):
            self._do_tls_handshake()

        addr = {
            structure.NetAddr(c.remote_version.services, c.host, c.port)
            for c in shared.connections if c.network != 'i2p'
            and not c.host.endswith('.onion')
            and c.server is False and c.status == 'fully_established'}
        # pylint: disable=unsubscriptable-object
        # https://github.com/pylint-dev/pylint/issues/3637
        if len(shared.node_pool) > 10:
            addr.update({
                structure.NetAddr(1, a[0], a[1])
                for a in random.sample(tuple(shared.node_pool), 10)})
        if len(shared.unchecked_node_pool) > 10:
            addr.update({
                structure.NetAddr(1, a[0], a[1])
                for a in random.sample(tuple(shared.unchecked_node_pool), 10)})
        if len(addr) != 0:
            self.send_queue.put(message.Addr(addr))

        if shared.objects:
            for chunk in shared.objects.biginv_chunks(10000):
                # We limit size of inv messages to 10000 entries
                # because they might time out in very slow networks (I2P)
                self.send_queue.put(message.Inv(chunk))
        self.status = 'fully_established'

    def _process_queue(self):
        while not self.send_queue.empty():
            m = self.send_queue.get()
            if m:
                if m == 'fully_established':
                    self.on_connection_fully_established_scheduled = True
                else:
                    self._send_message(m)
                    self.last_message_sent = time.time()
            else:
                self.status = 'disconnecting'
                break

    def _process_buffer_receive(self):
        while len(self.buffer_receive) >= self.next_message_size:
            if self.next_header:
                self.next_header = False
                try:
                    h = message.Header.from_bytes(
                        self.buffer_receive[:shared.header_length])
                except ValueError as e:
                    self.status = 'disconnecting'
                    logging.warning(
                        'Received malformed message from %s:%s: %s',
                        self.host_print, self.port, e)
                    break
                self.next_message_size += h.payload_length
            else:
                try:
                    m = message.Message.from_bytes(
                        self.buffer_receive[:self.next_message_size])
                except ValueError as e:
                    self.status = 'disconnecting'
                    logging.warning(
                        'Received malformed message from %s:%s, %s',
                        self.host_print, self.port, e)
                    break
                self.next_header = True
                self.buffer_receive = self.buffer_receive[
                    self.next_message_size:]
                self.next_message_size = shared.header_length
                self.last_message_received = time.time()
                try:
                    self._process_message(m)
                except ValueError as e:
                    self.status = 'disconnecting'
                    logging.warning(
                        'Received malformed message from %s:%s: %s',
                        self.host_print, self.port, e)
                    break

    def _process_message(self, m):
        if m.command == b'verack':
            self.verack_received = True
            logging.debug(
                '%s:%s -> %s', self.host_print, self.port, 'verack')
            if self.server:
                self.send_queue.put('fully_established')

        elif m.command == b'ping':
            logging.debug('%s:%s -> ping', self.host_print, self.port)
            self.send_queue.put(message.Message(b'pong', b''))

        elif m.command == b'error':
            error = message.Error.from_message(m)
            logging.warning(
                '%s:%s -> %s', self.host_print, self.port, error)
            if error.fatal == 2:
                # reduce probability to connect soon
                shared.unchecked_node_pool.discard((self.host, self.port))

        else:
            try:
                getattr(self, '_process_msg_{}'.format(m.command.decode()))(m)
            except (AttributeError, UnicodeDecodeError):
                logging.debug('%s:%s -> %s', self.host_print, self.port, m)

    def _process_msg_version(self, m):
        version = message.Version.from_message(m)
        if shared.stream not in version.streams:
            raise ValueError('message not for stream %i' % shared.stream)
        logging.debug('%s:%s -> %s', self.host_print, self.port, version)
        nonce_print = base64.b16encode(version.nonce).decode()
        if (
            version.protocol_version != shared.protocol_version
            or version.nonce == shared.nonce
            or version.nonce in shared.nonce_pool.values()
        ):
            logging.warning(
                'Disconnecting v%s node %s with nonce %s',
                version.protocol_version, self.host_print, nonce_print)
            shared.unchecked_node_pool.discard((self.host, self.port))
            self.status = 'disconnecting'
            self.send_queue.put(None)
        else:
            shared.nonce_pool[(self.host, self.port)] = version.nonce
            logging.info(
                '%s:%s claims to be %s (%s)',
                self.host_print, self.port, version.user_agent, nonce_print)
            self.send_queue.put(message.Message(b'verack', b''))
            self.verack_sent = True
            self.remote_version = version
            if not self.server:
                self.send_queue.put('fully_established')
                if self.network == 'ip':
                    if self.host.endswith('.onion'):
                        shared.onion_pool.add((self.host, self.port))
                    else:
                        shared.address_advertise_queue.put(structure.NetAddr(
                            version.services, self.host, self.port))
                        shared.node_pool.add((self.host, self.port))
                elif self.network == 'i2p':
                    shared.i2p_node_pool.add((self.host, 'i2p'))
            if (
                self.network == 'ip' and shared.listen_for_connections
                and version.host != '127.0.0.1'
            ):
                shared.address_advertise_queue.put(structure.NetAddr(
                    shared.services, version.host, shared.listening_port))
            if self.server:
                if self.network == 'ip':
                    version_kwargs = {'services': 1} if shared.tor else {}
                    self.send_queue.put(message.Version(
                        self.host, self.port, **version_kwargs))
                else:
                    self.send_queue.put(message.Version(
                        '127.0.0.1', 7656, nonce=self._get_nonce()))

    def _process_msg_addr(self, m):
        addr = message.Addr.from_message(m)
        logging.debug('%s:%s -> %s', self.host_print, self.port, addr)
        for a in addr.addresses:
            if not a.host or a.port == 0:
                continue
            if (a.host, a.port) not in shared.core_nodes:
                shared.unchecked_node_pool.add((a.host, a.port))

    def _request_objects(self):
        if self.vectors_to_get and len(self.vectors_requested) < 100:
            self.vectors_to_get = shared.objects.select(self.vectors_to_get)
            if not self.wait_until:
                nodes_count = (
                    len(shared.node_pool) + len(shared.unchecked_node_pool))
                logging.debug('Nodes count is %i', nodes_count)
                delay = math.ceil(math.log(nodes_count + 2, 20)) * 5.2
                self.wait_until = time.time() + delay
                logging.debug('Skip sending getdata for %.2fs', delay)
            if self.vectors_to_get and self.wait_until < time.time():
                logging.info(
                    'Queued %s vectors to get', len(self.vectors_to_get))
                if len(self.vectors_to_get) > 64:
                    pack = random.sample(tuple(self.vectors_to_get), 64)
                    self.send_queue.put(message.GetData(pack))
                    self.vectors_requested.update({
                        vector: time.time() for vector in pack
                    })
                    self.vectors_to_get.difference_update(pack)
                else:
                    self.send_queue.put(message.GetData(self.vectors_to_get))
                    self.vectors_requested.update({
                        vector: time.time() for vector in self.vectors_to_get
                    })
                    self.vectors_to_get.clear()
        if self.vectors_requested:
            self.vectors_requested = {
                vector: t for vector, t in self.vectors_requested.items()
                if vector not in shared.objects and t > time.time() - 15 * 60}
            to_re_request = {
                vector for vector, t in self.vectors_requested.items()
                if t < time.time() - 10 * 60}
            if to_re_request:
                self.vectors_to_get.update(to_re_request)
                logging.info(
                    'Re-requesting %i objects from %s:%s',
                    len(to_re_request), self.host_print, self.port)

    def _send_objects(self):
        if self.vectors_to_send:
            logging.info(
                'Preparing to send %s objects', len(self.vectors_to_send))
            if len(self.vectors_to_send) > 16:
                to_send = random.sample(tuple(self.vectors_to_send), 16)
                self.vectors_to_send.difference_update(to_send)
            else:
                to_send = self.vectors_to_send.copy()
                self.vectors_to_send.clear()
            for vector in to_send:
                obj = shared.objects.get(vector)
                if obj:
                    self.send_queue.put(message.Message(b'object', obj.data))


class Connection(ConnectionBase):
    """The connection with all commands implementation"""
    def _process_msg_inv(self, m):
        inv = message.Inv.from_message(m)
        logging.debug('%s:%s -> %s', self.host_print, self.port, inv)
        self.vectors_to_get.update(shared.objects.select(inv.vectors))
        # Do not send objects they already have.
        self.vectors_to_send.difference_update(inv.vectors)

    def _process_msg_object(self, m):
        obj = structure.Object.from_message(m)
        logging.debug('%s:%s -> %s', self.host_print, self.port, obj)
        self.vectors_requested.pop(obj.vector, None)
        self.vectors_to_get.discard(obj.vector)
        if obj.is_valid():
            shared.objects[obj.vector] = obj
            if (
                obj.object_type == shared.i2p_dest_obj_type
                and obj.version == shared.i2p_dest_obj_version
            ):
                dest = base64.b64encode(obj.object_payload, altchars=b'-~')
                logging.debug(
                    'Received I2P destination object,'
                    ' adding to i2p_unchecked_node_pool')
                logging.debug(dest)
                shared.i2p_unchecked_node_pool.add((dest, 'i2p'))
            elif (
                obj.object_type == shared.onion_obj_type
                and obj.version == shared.onion_obj_version
            ):
                peer = structure.OnionPeer.from_object(obj)
                logging.debug('Received onion peer object: %s', peer)
                shared.onion_unchecked_pool.add((peer.host, peer.port))
            shared.vector_advertise_queue.put(obj.vector)
        shared.objects.check(obj.vector)

    def _process_msg_getdata(self, m):
        getdata = message.GetData.from_message(m)
        logging.debug('%s:%s -> %s', self.host_print, self.port, getdata)
        self.vectors_to_send.update(getdata.vectors)


class Bootstrapper(ConnectionBase):
    """A special type of connection to find IP nodes"""
    def _process_msg_addr(self, m):
        super()._process_msg_addr(m)
        shared.node_pool.discard((self.host, self.port))
        self.status = 'disconnecting'
        self.send_queue.put(None)


class SocksConnection(Connection):
    """The socks proxied connection"""
    def _connect(self):
        peer_str = '{0.host_print}:{0.port}'.format(self)
        logging.debug('Connecting to %s', peer_str)

        import socks  # pylint: disable=import-outside-toplevel

        proxy_type = socks.PROXY_TYPES[shared.socks_proxy.scheme.upper()]

        try:
            self.s = socks.create_connection(
                (self.host, self.port), 30, None, proxy_type,
                shared.socks_proxy.hostname, shared.socks_proxy.port, True,
                shared.socks_proxy.username, shared.socks_proxy.password, None)
            self.status = 'connected'
            logging.debug('Established SOCKS connection to %s', peer_str)
        except socket.timeout:
            pass
        except socks.GeneralProxyError as e:
            e = e.socket_err
            if isinstance(e, socket.timeout) or (
                # general failure, unreachable, refused
                not e.errno and re.match(r'^0x0[1,4,5].*', e.msg)
            ):
                logcall = logging.debug
            else:
                logcall = logging.info
            logcall('Connection to %s failed. Reason: %s', peer_str, e)
        except OSError as e:
            # unreachable, refused, no route
            (logging.info if e.errno not in (0, 101, 111, 113)
             else logging.debug)(
                     'Connection to %s failed. Reason: %s', peer_str, e)
        except Exception:
            logging.info(
                'Connection to %s failed.', peer_str, exc_info=True)

        if self.status != 'connected':
            self.status = 'failed'


shared.connection = Connection
