import logging

import requests

import config

logger = logging.getLogger('bitchan.tor')


if config.DOCKER:
    str_bm_enabled = f"HiddenServiceDir {config.TOR_HS_BM}\nHiddenServicePort 8444 172.28.1.3:8444"
else:
    str_bm_enabled = f"HiddenServiceDir {config.TOR_HS_BM}\nHiddenServicePort 8444 127.0.0.1:8444"

str_custom_enabled = f"HiddenServiceDir {config.TOR_HS_CUS}\nHiddenServicePort 80 unix:/run/nginx.sock"
str_custom_disabled = f"#HiddenServiceDir {config.TOR_HS_CUS}\n#HiddenServicePort 80 unix:/run/nginx.sock"

str_random_enabled = f"HiddenServiceDir {config.TOR_HS_RAND}\nHiddenServicePort 80 unix:/run/nginx.sock"
str_random_disabled = f"#HiddenServiceDir {config.TOR_HS_RAND}\n#HiddenServicePort 80 unix:/run/nginx.sock"


def get_tor_session():
    session = requests.session()
    session.proxies = config.TOR_PROXIES
    return session


def enable_custom_address(enable):
    with open(config.TORRC) as f:
        s = f.read()
        if enable and str_custom_enabled in s:
            print("Already enabled")
            return
        if not enable and str_custom_disabled in s:
            print("Already disabled")
            return

    with open(config.TORRC, 'w') as f:
        if enable:
            s = s.replace(str_custom_disabled, str_custom_enabled)
            print("Enabled")
        if not enable:
            s = s.replace(str_custom_enabled, str_custom_disabled)
            print("Disabled")
        f.write(s)


def enable_random_address(enable):
    with open(config.TORRC) as f:
        s = f.read()
        if enable and str_random_enabled in s:
            print("Already enabled")
            return
        if not enable and str_random_disabled in s:
            print("Already disabled")
            return

    with open(config.TORRC, 'w') as f:
        if enable:
            s = s.replace(str_random_disabled, str_random_enabled)
            print("Enabled")
        if not enable:
            s = s.replace(str_random_enabled, str_random_disabled)
            print("Disabled")
        f.write(s)
