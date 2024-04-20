import logging

import requests

import config

logger = logging.getLogger('bitchan.tor')


if config.DOCKER:
    str_bm_enabled = f"HiddenServiceDir {config.TOR_HS_BM}\nHiddenServicePort 8444 172.28.1.3:8444"
else:
    str_bm_enabled = f"HiddenServiceDir {config.TOR_HS_BM}\nHiddenServicePort 8444 127.0.0.1:8444"

str_custom_enabled = (f"HiddenServiceDir {config.TOR_HS_CUS}\n"
                      f"HiddenServicePort 80 unix:/run/nginx.sock\n"
                      f"HiddenServicePoWDefensesEnabled {config.TOR_POW_ENABLE}\n"
                      f"HiddenServicePoWQueueRate {config.TOR_POW_QUEUE_RATE}\n"
                      f"HiddenServicePoWQueueBurst {config.TOR_POW_QUEUE_BURST}\n")

str_custom_disabled = (f"#HiddenServiceDir {config.TOR_HS_CUS}\n"
                       f"#HiddenServicePort 80 unix:/run/nginx.sock\n"
                       f"#HiddenServicePoWDefensesEnabled {config.TOR_POW_ENABLE}\n"
                       f"#HiddenServicePoWQueueRate {config.TOR_POW_QUEUE_RATE}\n"
                       f"#HiddenServicePoWQueueBurst {config.TOR_POW_QUEUE_BURST}\n")

str_random_enabled = (f"HiddenServiceDir {config.TOR_HS_RAND}\n"
                      f"HiddenServicePort 80 unix:/run/nginx.sock\n"
                      f"HiddenServicePoWDefensesEnabled {config.TOR_POW_ENABLE}\n"
                      f"HiddenServicePoWQueueRate {config.TOR_POW_QUEUE_RATE}\n"
                      f"HiddenServicePoWQueueBurst {config.TOR_POW_QUEUE_BURST}\n")

str_random_disabled = (f"#HiddenServiceDir {config.TOR_HS_RAND}\n"
                       f"#HiddenServicePort 80 unix:/run/nginx.sock\n"
                       f"#HiddenServicePoWDefensesEnabled {config.TOR_POW_ENABLE}\n"
                       f"#HiddenServicePoWQueueRate {config.TOR_POW_QUEUE_RATE}\n"
                       f"#HiddenServicePoWQueueBurst {config.TOR_POW_QUEUE_BURST}\n")


def get_tor_session():
    session = requests.session()
    session.proxies = config.TOR_PROXIES
    return session


def enable_custom_address(enable):
    with open(config.TORRC) as f:
        s = f.read()

    with open(config.TORRC, 'w') as f:
        str_start = "# Custom Hidden Service Start\n"
        str_end = "# Custom Hidden Service End\n"

        left, _, rest = s.partition(str_start)
        block, _, right = rest.partition(str_end)

        if enable:
            s = left + str_start + str_custom_enabled + str_end + right
            print("Enabled")
        if not enable:
            s = left + str_start + str_custom_disabled + str_end + right
            print("Disabled")
        f.write(s)


def enable_random_address(enable):
    with open(config.TORRC) as f:
        s = f.read()

    with open(config.TORRC, 'w') as f:
        str_start = "# Random Hidden Service Start\n"
        str_end = "# Random Hidden Service End\n"

        left, _, rest = s.partition(str_start)
        block, _, right = rest.partition(str_end)

        if enable:
            s = left + str_start + str_random_enabled + str_end + right
            print("Enabled")
        if not enable:
            s = left + str_start + str_random_disabled + str_end + right
            print("Disabled")
        f.write(s)
