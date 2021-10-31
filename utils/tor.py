import logging

logger = logging.getLogger('bitchan.tor')

path_torrc = "/etc/tor/torrc"
str_custom_enabled = "HiddenServiceDir /usr/local/tor/cus/\nHiddenServicePort 80 unix:/usr/local/nginx/nginx.sock"
str_custom_disabled = "#HiddenServiceDir /usr/local/tor/cus/\n#HiddenServicePort 80 unix:/usr/local/nginx/nginx.sock"

str_random_enabled = "HiddenServiceDir /usr/local/tor/rand/\nHiddenServicePort 80 unix:/usr/local/nginx/nginx.sock"
str_random_disabled = "#HiddenServiceDir /usr/local/tor/rand/\n#HiddenServicePort 80 unix:/usr/local/nginx/nginx.sock"


def enable_custom_address(enable):
    with open(path_torrc) as f:
        s = f.read()
        if enable and str_custom_enabled in s:
            print("Already enabled")
            return
        if not enable and str_custom_disabled in s:
            print("Already disabled")
            return

    with open(path_torrc, 'w') as f:
        if enable:
            s = s.replace(str_custom_disabled, str_custom_enabled)
            print("Enabled")
        if not enable:
            s = s.replace(str_custom_enabled, str_custom_disabled)
            print("Disabled")
        f.write(s)


def enable_random_address(enable):
    with open(path_torrc) as f:
        s = f.read()
        if enable and str_random_enabled in s:
            print("Already enabled")
            return
        if not enable and str_random_disabled in s:
            print("Already disabled")
            return

    with open(path_torrc, 'w') as f:
        if enable:
            s = s.replace(str_random_disabled, str_random_enabled)
            print("Enabled")
        if not enable:
            s = s.replace(str_random_enabled, str_random_disabled)
            print("Disabled")
        f.write(s)
