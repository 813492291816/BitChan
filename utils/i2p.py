import logging

import requests

from config import I2P_PROXIES

logger = logging.getLogger('bitchan.i2p')


def get_i2p_session():
    session = requests.session()
    session.proxies = I2P_PROXIES
    return session
