# -*- coding: utf-8 -*-
import logging
import socket

from .util import I2PThread


class I2PListener(I2PThread):
    def __init__(self, state, nick, host='127.0.0.1', port=7656):
        super().__init__(state, name='I2P Listener')

        self.host = host
        self.port = port
        self.nick = nick

        self.version_reply = []

    def new_socket(self):
        self.s = socket.create_connection((self.host, self.port))
        self._send(b'HELLO VERSION MIN=3.0 MAX=3.3\n')
        self.version_reply = self._receive_line().split()
        assert b'RESULT=OK' in self.version_reply

        self._send(b'STREAM ACCEPT ID=' + self.nick + b'\n')
        reply = self._receive_line().split(b' ')
        assert b'RESULT=OK' in reply

        self.s.settimeout(1)

    def run(self):
        while not self.state.shutting_down:
            self.new_socket()
            duplicate = False
            try:
                destination = self._receive_line().split()[0]
                logging.info(
                    'Incoming I2P connection from: %s', destination.decode())
            except socket.timeout:
                continue

            for c in self.state.connections.copy():
                if c.host == destination:
                    duplicate = True
                    break
            else:
                for d in self.state.i2p_dialers.copy():
                    if d.destination == destination:
                        duplicate = True
                        break
            if duplicate:
                logging.info('Rejecting duplicate I2P connection.')
                self.s.close()
            else:
                c = self.state.connection(destination, 'i2p', self.s, True)
                c.start()
                self.state.connections.add(c)
                c = None

        logging.debug('Shutting down I2P Listener')
