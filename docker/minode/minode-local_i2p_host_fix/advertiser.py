"""
Advertiser thread advertises new addresses and objects among all connections
"""
import logging
import threading
import time

from . import message, shared


class Advertiser(threading.Thread):
    """The advertiser thread"""
    def __init__(self):
        super().__init__(name='Advertiser')

    def run(self):
        while True:
            time.sleep(0.4)
            if shared.shutting_down:
                logging.debug('Shutting down Advertiser')
                break
            self._advertise_vectors()
            self._advertise_addresses()

    @staticmethod
    def _advertise_vectors():
        vectors_to_advertise = set()
        while not shared.vector_advertise_queue.empty():
            vectors_to_advertise.add(shared.vector_advertise_queue.get())
        if len(vectors_to_advertise) > 0:
            for c in shared.connections.copy():
                if c.status == 'fully_established':
                    c.send_queue.put(message.Inv(vectors_to_advertise))

    @staticmethod
    def _advertise_addresses():
        addresses_to_advertise = set()
        while not shared.address_advertise_queue.empty():
            addr = shared.address_advertise_queue.get()
            if addr.port == 'i2p':
                # We should not try to construct Addr messages
                # with I2P destinations (yet)
                continue
            addresses_to_advertise.add(addr)
        if len(addresses_to_advertise) > 0:
            for c in shared.connections.copy():
                if c.status == 'fully_established':
                    c.send_queue.put(message.Addr(addresses_to_advertise))
