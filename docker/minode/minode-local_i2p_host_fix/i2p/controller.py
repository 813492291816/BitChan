# -*- coding: utf-8 -*-
import base64
import logging
import os
import socket
import time

from .util import I2PThread, pub_from_priv


class I2PController(I2PThread):
    def __init__(self, state, host='127.0.0.1', port=7656, dest_priv=b''):
        super().__init__(state, name='I2P Controller')

        self.host = host
        self.port = port
        self.nick = b'MiNode_' + base64.b16encode(os.urandom(4)).lower()

        while True:
            if state.shutting_down:
                return
            try:
                self.s = socket.create_connection((self.host, self.port))
                break
            except ConnectionRefusedError:
                logging.error(
                    'Error while connecting to I2P SAM bridge. Retrying.')
                time.sleep(10)

        self.version_reply = []

        self.init_connection()

        if dest_priv:
            self.dest_priv = dest_priv
            self.dest_pub = pub_from_priv(dest_priv)
        else:
            self.dest_priv = b''
            self.dest_pub = b''
            self.generate_destination()

        self.create_session()

    def init_connection(self):
        self._send(b'HELLO VERSION MIN=3.0 MAX=3.3\n')
        self.version_reply = self._receive_line().split()
        assert b'RESULT=OK' in self.version_reply

    def generate_destination(self):
        if b'VERSION=3.0' in self.version_reply:
            # We will now receive old DSA_SHA1 destination :(
            self._send(b'DEST GENERATE\n')
        else:
            self._send(b'DEST GENERATE SIGNATURE_TYPE=EdDSA_SHA512_Ed25519\n')

        reply = self._receive_line().split()
        for par in reply:
            if par.startswith(b'PUB='):
                self.dest_pub = par.replace(b'PUB=', b'')
            if par.startswith(b'PRIV='):
                self.dest_priv = par.replace(b'PRIV=', b'')
        assert self.dest_priv

    def create_session(self):
        self._send(
            b'SESSION CREATE STYLE=STREAM ID=' + self.nick
            + b' inbound.length=' + str(self.state.i2p_tunnel_length).encode()
            + b' outbound.length=' + str(self.state.i2p_tunnel_length).encode()
            + b' DESTINATION=' + self.dest_priv + b'\n')
        reply = self._receive_line().split()
        if b'RESULT=OK' not in reply:
            logging.warning(reply)
            logging.warning(
                'We could not create I2P session, retrying in 5 seconds.')
            time.sleep(5)
            self.create_session()

    def run(self):
        self.s.settimeout(1)
        while True:
            if not self.state.shutting_down:
                try:
                    msg = self._receive_line().split(b' ')
                    if msg[0] == b'PING':
                        self._send(b'PONG ' + msg[1] + b'\n')
                except socket.timeout:
                    pass
            else:
                logging.debug('Shutting down I2P Controller')
                self.s.close()
                break
