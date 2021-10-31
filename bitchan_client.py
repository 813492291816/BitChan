import logging

from Pyro5.api import Proxy

import config

logger = logging.getLogger('bitchan.client')


class DaemonCom:
    def __init__(self, pyro_uri=config.PYRO_URI):
        self.pyro_timeout = 45
        self.uri = pyro_uri

    def proxy(self):
        try:
            proxy = Proxy(self.uri)
            proxy._pyroTimeout = self.pyro_timeout
            proxy._pyroSerializer = "msgpack"
            return proxy
        except Exception as e:
            logger.error("Pyro5 proxy error: {}".format(e))

    def bitmessage_restarting(self):
        return self.proxy().bitmessage_restarting()

    def bm_sync_complete(self):
        return self.proxy().bm_sync_complete()

    def bulk_join(self, list_address, join_bulk_list):
        return self.proxy().bulk_join(list_address, join_bulk_list)

    def check_sync(self):
        return self.proxy().check_sync()

    def clear_bm_inventory(self):
        return self.proxy().clear_bm_inventory()

    def delete_and_vacuum(self):
        return self.proxy().delete_and_vacuum()

    def get_address_book(self):
        return self.proxy().get_address_book()

    def get_address_labels(self):
        return self.proxy().get_address_labels()

    def get_all_chans(self):
        return self.proxy().get_all_chans()

    def get_api_status(self):
        return self.proxy().get_api_status()

    def get_bm_sync_complete(self):
        return self.proxy().get_bm_sync_complete()

    def get_board_by_chan(self, chan_address=None):
        return self.proxy().get_board_by_chan(chan_address=chan_address)

    def get_chans_board_info(self):
        return self.proxy().get_chans_board_info()

    def get_chans_list_info(self):
        return self.proxy().get_chans_list_info()

    def get_from_list(self, chan_address, only_owner_admin=False):
        return self.proxy().get_from_list(
            chan_address, only_owner_admin=only_owner_admin)

    def get_identities(self):
        return self.proxy().get_identities()

    def get_last_post_ts(self):
        return self.proxy().get_last_post_ts()

    def get_start_download(self):
        return self.proxy().get_start_download()

    def get_subscriptions(self):
        return self.proxy().get_subscriptions()

    def get_timer_clear_inventory(self):
        return self.proxy().get_timer_clear_inventory()

    def get_utc(self):
        return self.proxy().get_utc()

    def join_chan(self, passphrase, clear_inventory=False):
        return self.proxy().join_chan(passphrase, clear_inventory=clear_inventory)

    def leave_chan(self, chan_address):
        return self.proxy().leave_chan(chan_address)

    def refresh_address_book(self):
        return self.proxy().refresh_address_book()

    def refresh_identities(self):
        return self.proxy().refresh_identities()

    def refresh_settings(self):
        return self.proxy().refresh_settings()

    def remove_start_download(self, message_id):
        return self.proxy().remove_start_download(message_id)

    def restart_bitmessage(self):
        return self.proxy().restart_bitmessage()

    def set_board_by_chan(self, chan_address, board):
        return self.proxy().set_board_by_chan(chan_address, board)

    def set_last_post_ts(self, ts):
        return self.proxy().set_last_post_ts(ts)

    def set_start_download(self, message_id):
        return self.proxy().set_start_download(message_id)

    def update_unread_mail_count(self, ident_address):
        return self.proxy().update_unread_mail_count(ident_address)

    def signal_clear_inventory(self):
        return self.proxy().signal_clear_inventory()

    def signal_generate_post_numbers(self):
        return self.proxy().signal_generate_post_numbers()

    def tor_enable_custom_address(self):
        return self.proxy().tor_enable_custom_address()

    def tor_disable_custom_address(self):
        return self.proxy().tor_disable_custom_address()

    def tor_enable_random_address(self):
        return self.proxy().tor_enable_random_address()

    def tor_disable_random_address(self):
        return self.proxy().tor_disable_random_address()

    def tor_get_new_random_address(self):
        return self.proxy().tor_get_new_random_address()

    def tor_restart(self):
        return self.proxy().tor_restart()

    def trash_message(self, message_id):
        return self.proxy().trash_message(message_id)

    def update_timer_clear_inventory(self, seconds):
        return self.proxy().update_timer_clear_inventory(seconds)

    def update_timer_send_lists(self, seconds):
        return self.proxy().update_timer_send_lists(seconds)
