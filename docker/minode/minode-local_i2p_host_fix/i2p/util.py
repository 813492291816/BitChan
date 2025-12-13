# -*- coding: utf-8 -*-
"""Common reusable code for all the I2P entities"""
import base64
import hashlib
import threading


def receive_line(s):
    """Receive a line from the socket *s*"""
    data = b''
    while b'\n' not in data:
        d = s.recv(4096)
        if not d:
            raise ConnectionResetError
        data += d
    data = data.splitlines()
    return data[0]


class I2PThread(threading.Thread):
    """
    Abstract I2P thread with _receive_line() and _send() methods,
    reused in I2PDialer, I2PListener and I2PController
    """
    def __init__(self, state, name=''):
        super().__init__(name=name)
        self.state = state
        self.s = None

    def _receive_line(self):
        line = receive_line(self.s)
        # logging.debug('I2PListener <- %s', line)
        return line

    def _send(self, command):
        # logging.debug('I2PListener -> %s', command)
        self.s.sendall(command)


def pub_from_priv(priv):
    """Returns the public key for the private key *priv*"""
    priv = base64.b64decode(priv, altchars=b'-~')
    # 256 for public key + 128 for signing key + 3 for certificate header
    # + value of bytes priv[385:387]
    pub = priv[:387 + int.from_bytes(priv[385:387], byteorder='big')]
    return base64.b64encode(pub, altchars=b'-~')


def b32_from_pub(pub):
    """Converts the public key *pub* to base32 host name"""
    return base64.b32encode(
        hashlib.sha256(base64.b64decode(pub, b'-~')).digest()
    ).replace(b'=', b'').lower() + b'.b32.i2p'
