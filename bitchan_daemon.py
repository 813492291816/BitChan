import base64
import datetime
import fileinput
import grp
import hashlib
import html
import json
import logging
import os
import pwd
import random
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from binascii import hexlify
from collections import OrderedDict
from logging import handlers
from threading import Thread

import bleach
import gnupg
import ntplib
import qbittorrentapi
from Pyro5.api import expose
from Pyro5.api import serve
from daemonize import Daemonize
from sqlalchemy import and_
from sqlalchemy import func
from sqlalchemy import or_
from stem import Signal
from stem.control import Controller

import config
from database.models import AddressBook
from database.models import AdminMessageStore
from database.models import Captcha
from database.models import Chan
from database.models import Command
from database.models import DeletedMessages
from database.models import EndpointCount
from database.models import Games
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import PostCards
from database.models import PostDeletePasswordHashes
from database.models import SessionInfo
from database.models import Threads
from database.models import UploadProgress
from database.models import UploadTorrents
from database.utils import session_scope
from utils.database import get_db_table_daemon
from utils.download import allow_download
from utils.download import check_banned_file_hashes
from utils.download import generate_hash
from utils.download import validate_file
from utils.encryption_decrypt import decrypt_safe_size
from utils.files import LF
from utils.files import data_file_multiple_insert
from utils.files import delete_file
from utils.files import human_readable_size
from utils.game import initialize_game
from utils.gateway import api
from utils.gateway import chan_auto_clears_and_message_too_old
from utils.gateway import get_msg_address_from
from utils.gateway import log_age_and_expiration
from utils.gateway import timeout
from utils.general import get_random_alphanumeric_string
from utils.general import process_passphrase
from utils.general import set_clear_time_to_future
from utils.general import version_checker
from utils.message_admin_command import send_commands
from utils.parse_message import decrypt_and_process_attachments
from utils.parse_message import parse_message
from utils.parse_message import process_admin
from utils.posts import delete_post
from utils.replacements import replace_dict_keys_with_values
from utils.replacements import replace_lt_gt
from utils.shared import add_mod_log_entry
from utils.shared import diff_list_added_removed
from utils.shared import get_access
from utils.shared import get_msg_expires_time
from utils.shared import get_post_id
from utils.shared import regenerate_card_popup_post_html
from utils.tor import enable_custom_address
from utils.tor import enable_random_address


class BitChan:
    def __init__(self):
        self.logger = logging.getLogger('bitchan.daemon')

        self.running = True
        self.view_counter = {}
        self.reset_view_counter()

        self._non_bitchan_message_ids = []
        self._all_chans = {}
        self._address_book_dict = {}
        self._identity_dict = {}
        self._subscription_dict = {}
        self._refresh = True
        self._refresh_identities = False
        self._refresh_address_book = True

        # periodically-updated dictionaries
        self.chans_boards_info = {}

        self.maintenance_mode = False
        self.last_post_ts = 0
        self.message_threads = {}
        self.utc_offset = None
        self.time_last = 0
        self.is_restarting_bitmessage = False
        self.list_stats = []
        self.first_run = True
        self.update_ntp = False
        self.update_post_numbers = False

        # Bitmessage
        self.api_status = None
        self.bm_onion_address = None
        self.bm_connected = False
        self.bm_connected_timer = None
        self.bm_sync_complete = False
        self.bm_pending_download = True
        self.bm_pending_download_timer = None
        self.bm_number_messages_processed_last = 0

        # Timers
        now = time.time()
        self.timer_check_bm_alive = now
        self.timer_time_server = now
        self.timer_board_info = now
        self.timer_check_downloads = now
        self.timer_addresses = now
        self.timer_queue_messages = now
        self.timer_stats = now
        self.timer_clear_inventory = now
        self.timer_message_threads = now
        self.timer_clear_uploads = now
        self.timer_unread_mail = now
        self.timer_non_bitchan_message_ids = now
        self.timer_safe_send = now
        self.timer_update_post_numbers = now
        self.timer_new_tor_identity = now + random.randint(10800, 28800)
        self.timer_check_onion_address = now
        self.timer_check_torrents = now
        self.timer_remove_old_torrents = now

        self.timer_delete_and_vacuum = now + (60 * 60)     # 1 hour
        self.timer_check_locked_threads = now + (60 * 20)  # 20 minutes
        self.timer_delete_msgs = now + (60 * 10)           # 10 minutes
        self.timer_delete_captchas = now + (60 * 10)       # 10 minutes
        self.timer_get_msg_expires_time = now + (60 * 10)  # 10 minutes
        self.timer_remove_deleted_msgs = now + (60 * 10)   # 10 minutes
        self.timer_send_lists = now + (60 * 5)             # 5 minutes
        self.timer_send_commands = now + (60 * 5)          # 5 minutes
        self.timer_clear_session_info = now + (60 * 5)     # 5 minutes
        self.timer_wipe = now + 120                        # 2 minutes
        self.timer_sync = now + (60 * 2)                   # 2 minutes
        self.timer_game = now + (60 * 1)                   # 1 minutes

        # Start timer at next top of the hour
        t = datetime.datetime.now()
        epoch_next_hour = t.replace(second=0, microsecond=0, minute=0, hour=t.hour) + datetime.timedelta(hours=1)
        self.timer_top_of_hour = int(epoch_next_hour.strftime('%s'))

        # Net disable settings
        self.allow_net_file_size_check = False
        self.allow_net_ntp = False

    def refresh_settings(self):
        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            try:
                self._non_bitchan_message_ids = json.loads(settings.discard_message_ids)
            except:
                self._non_bitchan_message_ids = "[]"
            self.allow_net_file_size_check = settings.allow_net_file_size_check
            self.allow_net_ntp = settings.allow_net_ntp

    @staticmethod
    def reset_all_auto_downloads():
        with session_scope(config.DB_PATH) as new_session:
            messages = new_session.query(Messages).filter(
                Messages.start_download.is_(True),
                Messages.file_currently_downloading.is_(True)).all()
            for msg in messages:
                msg.file_currently_downloading = False
                new_session.commit()

    def run(self):
        self.logger.info("Starting BitChan v{}".format(config.VERSION_BITCHAN))
        self.refresh_settings()
        self.reset_all_auto_downloads()
        time.sleep(3)
        self.process_stored_messages()  # Process messages that were already processed and stored in the database
        self.logger.debug("Initialization complete. Starting daemon.")

        while self.running:
            if not self.is_restarting_bitmessage:
                try:
                    self.run_periodic()
                except:
                    self.logger.exception("Error executing run_periodic()")
                    time.sleep(5)
            time.sleep(1)

        self.logger.info("Daemon shutting down")

    def run_periodic(self):
        now = time.time()

        #
        # Check settings
        #
        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            if settings.maintenance_mode:
                self.logger.info("Maintenance mode enabled. Pausing daemon operation.")
                self.maintenance_mode = True

        #
        # Maintenance Mode
        #
        while self.maintenance_mode:
            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                if not settings.maintenance_mode:
                    self.logger.info("Maintenance mode disabled. Resuming daemon operation.")
                    self.maintenance_mode = False
            time.sleep(1)

        #
        # Update the time
        #
        if self.allow_net_ntp:
            self.update_ntp = False
            if abs(self.time_last - now) > 600:
                self.logger.info("Time changed? Update NTP.")
                self.update_ntp = True
            self.time_last = now

            if self.timer_time_server < now or self.update_ntp:
                while self.timer_time_server < now:
                    self.timer_time_server += (60 * 6 * random.randint(40, 70))
                ntp = Thread(target=self.update_utc_offset)
                ntp.daemon = True
                ntp.start()

        #
        # Check Bitmessage onion address
        #
        if self.timer_check_onion_address < now:
            try:
                self.logger.debug("Run check_onion_address()")
                self.check_onion_address()
                self.logger.debug("End check_onion_address()")
            except:
                self.logger.exception("Could not complete check_onion_address()")
            self.timer_check_onion_address = time.time() + 60 * 60 * 12  # 12 hours

        #
        # Update Chans Board Info
        #
        if self.timer_board_info < now or self.update_ntp:
            try:
                self.logger.debug("Run generate_chans_board_info()")
                self.generate_chans_board_info()
                self.logger.debug("End generate_chans_board_info()")
            except:
                self.logger.exception("Could not complete generate_chans_board_info()")
            self.timer_board_info = time.time() + config.REFRESH_BOARD_INFO

        #
        # Check if downloads initiated
        #
        if self.timer_check_downloads < now or self.update_ntp:
            try:
                self.logger.debug("Run check_downloads()")
                self.check_downloads()
                self.logger.debug("End check_downloads()")
            except:
                self.logger.exception("Could not complete check_downloads()")
            self.timer_check_downloads = time.time() + config.REFRESH_CHECK_DOWNLOAD

        #
        # Check if BM sync is complete
        #
        if self.timer_sync < now or self.update_ntp:
            try:
                self.logger.debug("Run check_sync()")
                lf = LF()
                if lf.lock_acquire("/var/lock/bm_sync_check.lock", to=60):
                    try:
                        self.check_sync_locked()
                    except Exception as err:
                        self.logger.error("Error check_sync(): {}".format(err))
                    finally:
                        lf.lock_release("/var/lock/bm_sync_check.lock")
                self.logger.debug("End check_sync()")
            except:
                self.logger.exception("Could not complete check_sync()")
            self.timer_sync = time.time() + config.REFRESH_CHECK_SYNC

        #
        # Check if BM is alive
        #
        if not self.is_restarting_bitmessage and self.timer_check_bm_alive < time.time():
            try:
                self.logger.debug("Run bitmessage_monitor()")
                self.bitmessage_monitor()
                self.logger.debug("End bitmessage_monitor()")
            except:
                self.logger.exception("Could not complete bitmessage_monitor()")
            self.timer_check_bm_alive = time.time() + config.API_CHECK_FREQ

        #
        # New tor Identity
        #
        if self.timer_new_tor_identity < now:
            try:
                self.logger.debug("Run new_tor_identity()")
                self.new_tor_identity()
                self.logger.debug("End new_tor_identity()")
            except:
                self.logger.exception("Could not complete new_tor_identity()")
            self.timer_new_tor_identity = time.time() + random.randint(10800, 28800)

        #
        # Update addresses periodically
        #
        if self.timer_addresses < now or self._refresh:
            self._refresh = False
            try:
                self.logger.debug("Run update_identities()")
                self.update_identities()
                # self.update_subscriptions()  # Currently not used
                self.logger.debug("Run update_address_book()")
                self.update_address_book()
                self.logger.debug("Run update_chans()")
                self.update_chans()
            except Exception:
                self.logger.exception("Updating addresses")
            self.timer_addresses = time.time() + config.REFRESH_ADDRESSES

        #
        # Update messages periodically
        #
        if self.timer_queue_messages < now:
            try:
                self.logger.debug("Run queue_new_messages()")
                self.queue_new_messages()
                self.logger.debug("End queue_new_messages()")
            except Exception:
                self.logger.exception("Updating messages")
            self.timer_queue_messages = time.time() + config.REFRESH_MSGS

        #
        # Update stats
        #
        if self.timer_stats < now:
            try:
                self.logger.debug("Run queue_new_messages()")
                self.queue_new_messages()
                self.logger.debug("End queue_new_messages()")
                with session_scope(config.DB_PATH) as new_session:
                    post_count = new_session.query(Messages).count()
                    board_count = new_session.query(Chan).filter(Chan.type == "board").count()
                    list_count = new_session.query(Chan).filter(Chan.type == "list").count()
                    list_stats = [
                        post_count,
                        board_count,
                        list_count,
                        len(self._identity_dict),
                        len(self._address_book_dict)
                    ]
                    if self.list_stats != list_stats:
                        msg = str(post_count)
                        msg += " post, " if post_count == 1 else " posts, "
                        msg += str(board_count)
                        msg += " board, " if board_count == 1 else " boards, "
                        msg += str(list_count)
                        msg += " list, " if list_count == 1 else " lists, "
                        msg += str(len(self._identity_dict))
                        msg += " identity, " if len(self._identity_dict) == 1 else " identities, "
                        msg += str(len(self._address_book_dict))
                        if len(self._address_book_dict) == 1:
                            msg += " address book entry"
                        else:
                            msg += " address book entries"
                        self.logger.info(msg)
                        self.list_stats = list_stats
            except Exception:
                self.logger.exception("Updating stats")
            self.timer_stats = time.time() + config.REFRESH_STATS

        #
        # Update message thread queue
        #
        if self.timer_message_threads < now:
            try:
                self.logger.debug("Run check_message_threads()")
                self.check_message_threads()
                self.logger.debug("End check_message_threads()")
            except:
                self.logger.exception("Could not complete check_message_threads()")
            self.timer_message_threads = time.time() + config.REFRESH_THREAD_QUEUE

        #
        # Clear upload progress table
        #
        if self.timer_clear_uploads < now:
            self.logger.debug("Run clear upload progress table")
            try:
                with session_scope(config.DB_PATH) as new_session:
                    if self.first_run:
                        upl = new_session.query(UploadProgress).all()
                    else:
                        upl = new_session.query(UploadProgress).filter(and_(
                            UploadProgress.progress_percent == 100,
                            UploadProgress.uploading.is_(False))).all()
                    for each_upl in upl:
                        new_session.delete(each_upl)
            except:
                self.logger.exception("Could not complete clearing upload progress table")
            self.timer_clear_uploads = time.time() + config.REFRESH_CLEAR_PROGRESS

        #
        # Clear inventory 10 minutes after last board/list join
        #
        if self.timer_clear_inventory < now:
            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                if settings and settings.clear_inventory:
                    if not self.message_threads and self.bm_sync_complete:
                        # Only clear inventory if no messages are being processed and sync is complete
                        self.logger.debug("Run clear_bm_inventory()")
                        self.is_pow_sending()
                        if self.timer_safe_send < now:  # Ensure BM isn't restarted while sending
                            settings.clear_inventory = False
                            new_session.commit()
                            try:
                                self.clear_bm_inventory()
                                self.bm_sync_complete = False
                                self.update_post_numbers = True
                            except:
                                self.logger.exception("Could not complete clear_bm_inventory()")
                    else:
                        self.timer_clear_inventory += 60  # Wait additional 60 seconds if messages are being processed

        #
        # Get message expires time if not currently set
        #
        if self.timer_get_msg_expires_time < now:
            try:
                self.logger.debug("Run get_message_expires_times()")
                self.get_message_expires_times()
                self.logger.debug("End get_message_expires_times()")
            except:
                self.logger.exception("Could not complete get_message_expires_times()")
            self.timer_get_msg_expires_time = time.time() + config.REFRESH_EXPIRES_TIME

        #
        # Delete messages from sent box
        #
        if self.timer_delete_msgs < now:
            try:
                self.logger.debug("Run delete_msgs()")
                self.delete_msgs()
                self.logger.debug("End delete_msgs()")
            except:
                self.logger.exception("Could not complete delete_msgs()")
            self.timer_delete_msgs = time.time() + config.REFRESH_DELETE_SENT

        #
        # Delete entries in deleted message database 1 day after they expire
        #
        if self.timer_remove_deleted_msgs < now:
            self.logger.debug("Run delete entries in deleted message database")
            try:
                self.logger.info("Checking for expired message entries")
                with session_scope(config.DB_PATH) as new_session:
                    expired = time.time() - (24 * 60 * 60 * 5)  # 5 days in the past (expired 5 days ago)
                    for each_msg in new_session.query(DeletedMessages).all():
                        if each_msg.expires_time and expired and each_msg.expires_time < expired:
                            self.logger.info("DeletedMessages table: delete: {}, {}".format(
                                each_msg.expires_time, each_msg.message_id))
                            new_session.delete(each_msg)
                    new_session.commit()
            except:
                self.logger.exception("remove_deleted_msgs")
            self.timer_remove_deleted_msgs = time.time() + config.REFRESH_REMOVE_DEL

        #
        # Check lists that may be expiring and resend
        #
        if self.timer_send_lists < now and self.bm_sync_complete:
            try:
                self.logger.info("Run send_lists()")
                self.send_lists()
                self.logger.info("End send_lists()")
            except:
                self.logger.exception("Could not complete send_lists()")
            self.timer_send_lists = time.time() + config.REFRESH_CHECK_LISTS

        #
        # Check commands that may be expiring and resend
        #
        if self.timer_send_commands < now and self.bm_sync_complete:
            try:
                self.logger.debug("Run send_commands()")
                send_commands()
                self.logger.debug("End send_commands()")
            except:
                self.logger.exception("Could not complete send_commands()")
            self.timer_send_commands = time.time() + config.REFRESH_CHECK_CMDS

        #
        # Get unread mail counts
        #
        if self.timer_unread_mail < now:
            try:
                self.logger.debug("Run check_unread_mail()")
                self.check_unread_mail()
                self.logger.debug("End check_unread_mail()")
            except:
                self.logger.exception("Could not complete check_unread_mail()")
            self.timer_unread_mail = time.time() + config.REFRESH_UNREAD_COUNT

        #
        # Rule: Automatically Wipe Board/List
        #
        if self.timer_wipe < now:
            try:
                with session_scope(config.DB_PATH) as new_session:
                    for each_chan in new_session.query(Chan).all():
                        if not each_chan.rules:
                            continue
                        try:
                            rules = json.loads(each_chan.rules)
                            if ("automatic_wipe" in rules and
                                    rules["automatic_wipe"]["wipe_epoch"] < now):
                                self.clear_list_board_contents(each_chan.address)
                                while rules["automatic_wipe"]["wipe_epoch"] < now:
                                    rules["automatic_wipe"]["wipe_epoch"] += rules["automatic_wipe"]["interval_seconds"]
                                each_chan.rules = json.dumps(rules)
                                new_session.commit()
                        except Exception as err:
                            self.logger.error("Error clearing board/list: {}".format(err))
            except:
                self.logger.exception("Could not complete check_unread_mail()")
            self.timer_wipe = time.time() + config.REFRESH_WIPE

        #
        # Update post numbers
        #
        if (self.timer_update_post_numbers < now and
                self.update_post_numbers and
                self.bm_sync_complete):
            try:
                self.logger.debug("Run generate_post_numbers()")
                self.update_post_numbers = False
                self.generate_post_numbers()
                self.logger.debug("End generate_post_numbers()")
            except:
                self.logger.exception("Could not complete generate_post_numbers()")
            self.timer_update_post_numbers = time.time() + (60 * 5)  # 5 minutes

        #
        # Delete and Vacuum
        #
        if self.timer_delete_and_vacuum < now:
            self.timer_delete_and_vacuum = time.time() + (60 * 60 * 6)  # 6 hours
            # Check for expire times before deleting and vacuuming
            try:
                self.logger.debug("Run get_message_expires_times()")
                self.get_message_expires_times()
                self.logger.debug("End get_message_expires_times()")
            except:
                self.logger.exception("Could not complete get_message_expires_times()")
            self.timer_get_msg_expires_time = time.time() + config.REFRESH_EXPIRES_TIME

            try:
                self.logger.debug("Run delete_and_vacuum()")
                self.delete_and_vacuum()
                self.logger.debug("End delete_and_vacuum()")
            except:
                self.logger.exception("Could not complete delete_and_vacuum()")

            # Set any expire times still None to 0
            self.logger.debug("Setting message expire times to 0")
            try:
                with session_scope(config.DB_PATH) as new_session:
                    msg_inbox = new_session.query(Messages).filter(
                        Messages.expires_time.is_(None)).all()
                    for each_msg in msg_inbox:
                        self.logger.info("{}: Setting message expire time to 0".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper()))
                        each_msg.expires_time = 0
                    msg_deleted = new_session.query(DeletedMessages).filter(
                        DeletedMessages.expires_time.is_(None)).all()
                    for each_msg in msg_deleted:
                        self.logger.info("{}: Setting deleted message expire time to 0".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper()))
                        each_msg.expires_time = 0
                    new_session.commit()
            except:
                self.logger.exception("Could not set message expire times to 0")

        #
        # Clear flask session info
        #
        if self.timer_clear_session_info < now:
            try:
                self.logger.debug("Run clear_session_info()")
                self.clear_session_info()
                self.logger.debug("End clear_session_info()")
            except:
                self.logger.exception("Could not complete clear_session_info()")
            finally:
                self.timer_clear_session_info = time.time() + (60 * 60 * 12)  # 12 hours

        #
        # Check that no posts exist past lock on locked threads
        #
        if self.timer_check_locked_threads < now:
            with session_scope(config.DB_PATH) as new_session:
                admin_store = new_session.query(AdminMessageStore).count()
                if self.bm_sync_complete and not admin_store:
                    try:
                        self.logger.debug("Run scan_locked_threads()")
                        self.scan_locked_threads()
                        self.logger.debug("End scan_locked_threads()")
                    except:
                        self.logger.exception("Could not complete scan_locked_threads()")
                    self.timer_check_locked_threads = time.time() + (60 * 60)
                else:
                    self.timer_check_locked_threads = time.time() + 60

        #
        # Periodically delete stale captchas
        #
        if self.timer_delete_captchas < now:
            try:
                self.logger.debug("Run delete_old_captchas()")
                self.delete_old_captchas()
                self.logger.debug("End delete_old_captchas()")
            except:
                self.logger.exception("Could not complete delete_old_captchas()")
            finally:
                self.timer_delete_captchas = time.time() + (60 * 60 * 3)  # 3 Hours

        #
        # Periodically check games
        #
        if self.timer_game < now:
            try:
                self.logger.debug("Run check_games()")
                self.check_games()
                self.logger.debug("End check_games()")
            except:
                self.logger.exception("Could not complete check_games()")
            finally:
                self.timer_game = time.time() + 20  # 20 seconds

        #
        # Periodically check every hour (at the top of the hour)
        #
        if self.timer_top_of_hour < now:
            try:
                self.logger.debug("Run hourly_run()")
                self.hourly_run(self.timer_top_of_hour)
                self.logger.debug("End hourly_run()")
            except:
                self.logger.exception("Could not complete hourly_run()")
            finally:
                self.timer_top_of_hour = time.time() + (60 * 60 * 3)  # 1 hour

        #
        # Check for completed torrents (and process their downloaded data)
        #
        if self.timer_check_torrents < now:
            try:
                self.logger.debug("Run check_torrents()")
                self.check_torrents()
                self.logger.debug("End check_torrents()")
            except:
                self.logger.exception("Could not complete check_torrents()")
            finally:
                while self.timer_check_torrents < now:
                    self.timer_check_torrents += 10  # 10 seconds

        #
        # Remove torrents/data more than 28 days old
        #
        if self.timer_remove_old_torrents < now:
            try:
                self.logger.debug("Run remove_old_torrents()")
                self.remove_old_torrents()
                self.logger.debug("End remove_old_torrents()")
            except:
                self.logger.exception("Could not complete remove_old_torrents()")
            finally:
                self.timer_remove_old_torrents = time.time() + (60 * 60)  # 60 minutes

        self.first_run = False

    def hourly_run(self, timestamp_hour):
        try:
            thread_hashes = {}
            new_posts = {}
            chan_addresses = {}
            rss_threads = {}
            rss_boards = {}
            with session_scope(config.DB_PATH) as new_session:
                for category, each_data in self.view_counter.items():
                    for endpoint in each_data:
                        if endpoint in ["index", "verify_wait", "verify_test", "verify_success"]:
                            count = EndpointCount()
                            count.timestamp_epoch = timestamp_hour
                            count.category = category
                            count.endpoint = endpoint
                            count.requests = self.view_counter[category][endpoint]
                            new_session.add(count)
                        if category in ["boards", "lists"] and endpoint:
                            if endpoint not in chan_addresses:
                                chan_addresses[endpoint] = 0
                            chan_addresses[endpoint] += self.view_counter[category][endpoint]
                        if category == "threads" and endpoint:
                            if endpoint not in thread_hashes:
                                thread_hashes[endpoint] = 0
                            thread_hashes[endpoint] += self.view_counter[category][endpoint]
                        if category == "new_posts" and endpoint:
                            if endpoint not in new_posts:
                                new_posts[endpoint] = 0
                            new_posts[endpoint] += self.view_counter[category][endpoint]
                        if category == "rss_thread" and endpoint:
                            if endpoint not in rss_threads:
                                rss_threads[endpoint] = 0
                            rss_threads[endpoint] += self.view_counter[category][endpoint]
                        if category == "rss_board" and endpoint:
                            if endpoint not in rss_boards:
                                rss_boards[endpoint] = 0
                            rss_boards[endpoint] += self.view_counter[category][endpoint]

                # Add DB entry for board loads
                for each_address, views in chan_addresses.items():
                    count = EndpointCount()
                    count.timestamp_epoch = timestamp_hour
                    count.chan_address = each_address
                    count.category = "requests"
                    count.requests = views
                    new_session.add(count)

                # Add DB entry for thread loads
                for thread_hash, views in thread_hashes.items():
                    count = EndpointCount()
                    count.timestamp_epoch = timestamp_hour
                    count.thread_hash = thread_hash
                    count.category = "requests"
                    count.requests = views
                    new_session.add(count)

                new_session.commit()

                # Add DB entry for rss board loads
                for board_address, views in rss_boards.items():
                    test_count = new_session.query(EndpointCount).filter(and_(
                        EndpointCount.timestamp_epoch == timestamp_hour,
                        EndpointCount.chan_address == board_address,
                        EndpointCount.category == "rss_board")).first()
                    if test_count:
                        test_count.rss = views
                    else:
                        count = EndpointCount()
                        count.timestamp_epoch = timestamp_hour
                        count.chan_address = board_address
                        count.category = "rss_board"
                        count.rss = views
                        new_session.add(count)
                new_session.commit()

                # Add DB entry for rss thread loads
                for thread_hash, views in rss_threads.items():
                    test_count = new_session.query(EndpointCount).filter(and_(
                        EndpointCount.timestamp_epoch == timestamp_hour,
                        EndpointCount.thread_hash == thread_hash,
                        EndpointCount.category == "rss_thread")).first()
                    if test_count:
                        test_count.rss = views
                    else:
                        count = EndpointCount()
                        count.timestamp_epoch = timestamp_hour
                        count.thread_hash = thread_hash
                        count.category = "rss_thread"
                        count.rss = views
                        new_session.add(count)
                new_session.commit()

                # Add DB entry for thread updates
                for thread_hash, views in new_posts.items():
                    test_count = new_session.query(EndpointCount).filter(and_(
                        EndpointCount.timestamp_epoch == timestamp_hour,
                        EndpointCount.thread_hash == thread_hash,
                        EndpointCount.category == "requests")).first()
                    if test_count:
                        test_count.new_posts = views
                    else:
                        count = EndpointCount()
                        count.timestamp_epoch = timestamp_hour
                        count.thread_hash = thread_hash
                        count.category = "requests"
                        count.new_posts = views
                        new_session.add(count)
                new_session.commit()

            self.reset_view_counter()
        except:
            self.logger.error("Could not import view_counter")

    def check_torrents(self):
        """Check torrents that need to be paused or processed after download completes"""
        skip_size_check = False

        with session_scope(config.DB_PATH) as new_session:
            torrents = new_session.query(UploadTorrents).filter(
                UploadTorrents.torrent_completed.is_(False)).all()
            for torrent in torrents:
                if not torrent.message_id:
                    continue  # Don't initiate if message ID absent

                message = new_session.query(Messages).filter(
                    Messages.message_id == torrent.message_id).first()
                if not message:
                    continue  # Don't initiate if message absent

                # Check if torrent is present in torrent client
                conn_info = dict(host=config.QBITTORRENT_HOST, port=8080)
                qbt_client = qbittorrentapi.Client(**conn_info)
                qbt_client.auth_log_in()
                try:
                    torrent_prop = qbt_client.torrents_info(
                        torrent_hashes=torrent.torrent_hash)[0]
                except:
                    torrent_prop = None

                if not torrent_prop:
                    # Torrent not found in client, prevent processing this torrent again
                    self.logger.error(
                        f"{message.message_id[-config.ID_LENGTH:].upper()}: Torrent {torrent.file_hash} "
                        f"with hash {torrent.torrent_hash} not found in client. Download Disabled.")
                    message.file_do_not_download = True
                    message.file_currently_downloading = False
                    message.file_progress = "Torrent not found in client. Download disabled."
                    message.regenerate_post_html = True
                    new_session.commit()
                    continue

                # Check if torrent should be prevented from starting
                if message.file_do_not_download and not message.start_download:
                    continue  # Don't initiate if file prevented from being downloaded

                # Pause if total size is greater than max size permitted to be auto-downloaded
                elif not message.file_do_not_download and not message.start_download:
                    settings = new_session.query(GlobalSettings).first()
                    max_size_bytes = settings.max_download_size * 1024 * 1024
                    if torrent_prop and torrent_prop.total_size > max_size_bytes:
                        # Torrent exists and size is too large, pause torrent
                        qbt_client.torrents_pause(torrent_hashes=torrent.torrent_hash)
                        msg = (
                            f"Attachments too large. "
                            f"Max download size allowed is {human_readable_size(max_size_bytes)}. "
                            f"Pausing torrent.")
                        self.logger.info(msg)
                        message.file_do_not_download = True
                        message.file_currently_downloading = False
                        message.file_progress = msg
                        message.regenerate_post_html = True
                        new_session.commit()
                        continue

                # User manually allowed download, so skip file size check
                elif message.start_download:
                    skip_size_check = True

                #
                # Torrent exists and size is not too large, allow processing downloaded files
                #
                try:
                    # Torrent is paused
                    if torrent_prop and torrent_prop.state in ['pausedDL', 'pausedDL']:
                        self.logger.info(
                            f"Torrent {torrent.file_hash} paused when it's allowed to be downloaded. Resuming.")
                        qbt_client.torrents_resume(torrent_hashes=torrent.torrent_hash)
                        time.sleep(1)

                    # Torrent is seeding
                    elif torrent_prop and torrent_prop.state in ['stalledUP', 'uploading']:
                        self.logger.info(
                            f"Torrent {torrent.file_hash} seeding when it hasn't been processed. Processing.")

                        # Check only the seeding directory for torrents that are completed and are seeding
                        path_downloaded_file = os.path.join('/i2p_qb/Downloads', torrent.file_hash)
                        path_downloaded_file_zip = os.path.join('/i2p_qb/Downloads', f"{torrent.file_hash}.zip")
                        if torrent.message_id and torrent.file_hash and os.path.isfile(path_downloaded_file):
                            self.logger.info(f"Found completed torrent data {path_downloaded_file}")
                            path_downloaded = path_downloaded_file
                        elif torrent.message_id and torrent.file_hash and os.path.isfile(path_downloaded_file_zip):
                            self.logger.info(f"Found completed torrent data {path_downloaded_file_zip}")
                            path_downloaded = path_downloaded_file_zip
                        else:
                            continue  # Couldn't find completed torrent data, move to next torrent file

                        self.logger.info("{}: Message with torrent data hash {} found, decrypting...".format(
                            message.message_id[-config.ID_LENGTH:].upper(), torrent.file_hash))

                        # Add missing parts back into encrypted file
                        path_enc_file = f'/tmp/{torrent.file_hash}'
                        try:
                            file_extracts_start_base64 = json.loads(message.file_extracts_start_base64)
                        except:
                            file_extracts_start_base64 = None
                        if file_extracts_start_base64:
                            self.logger.info(f"extracts: {file_extracts_start_base64}")
                            size_before = os.path.getsize(path_downloaded)
                            data_file_multiple_insert(
                                path_downloaded,
                                file_extracts_start_base64,
                                chunk=4096,
                                copy_file_path=path_enc_file)
                            self.logger.info("{}: File data insertion. Before: {}, After: {}".format(
                                message.message_id[-config.ID_LENGTH:].upper(),
                                size_before,
                                os.path.getsize(path_enc_file)))
                        else:
                            shutil.copy(path_downloaded, path_enc_file)

                        # Compare encrypted file hash to expected hash
                        if message.file_sha256_hash:
                            if not validate_file(path_enc_file, message.file_sha256_hash):
                                message.file_progress = "Attachment hash ({}) doesn't match expected hash ({}).".format(
                                    generate_hash(path_enc_file), message.file_sha256_hash)
                                message.file_sha256_hashes_match = False
                                message.regenerate_post_html = True
                                new_session.commit()
                                return
                            else:
                                message.file_sha256_hashes_match = True

                        # Hashes match, decrypt and extract attachments
                        status, media_info, message_steg = decrypt_and_process_attachments(
                            message.message_id,
                            message.file_enc_cipher,
                            message.file_enc_key_bytes,
                            message.file_enc_password,
                            path_enc_file,
                            skip_size_check=skip_size_check)

                        if not status:  # Success
                            message.file_download_successful = True
                            message.file_currently_downloading = False
                            message.file_progress = ""
                            message.media_info = json.dumps(media_info)
                            message.message_steg = json.dumps(message_steg)
                            torrent.torrent_completed = True  # No longer include this torrent in this search function
                        else:  # Failure
                            message.file_currently_downloading = False
                            message.file_download_successful = False
                            message.file_do_not_download = True

                        new_session.commit()

                        regenerate_card_popup_post_html(message_id=torrent.message_id)

                        check_banned_file_hashes(torrent.message_id, media_info)

                    # Torrent is in some unpaused state but not completed downloading
                    elif torrent_prop and torrent_prop.state in [
                            'checkingUP', 'allocating', 'downloading', 'queuedDL',
                            'stalledDL', 'checkingDL', 'checkingResumeData']:
                        pass

                    # Torrent is in some unknown state. Record to logs to diagnose the issue.
                    else:
                        self.logger.error(f"Torrent {torrent.file_hash} in unknown state '{torrent_prop.state}'")
                except:
                    self.logger.exception(f"Checking torrent {torrent.file_hash} for completion")

                qbt_client.auth_log_out()

    def remove_old_torrents(self):
        """Remove torrents and data if more than 28 days old"""
        now = time.time()
        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            torrents_old = new_session.query(UploadTorrents).all()
            for torrent in torrents_old:
                # Find post to determine if OP or reply
                message = new_session.query(Messages).filter(
                    Messages.message_id == torrent.message_id).first()
                if not message:
                    continue
                if message.is_op:
                    seed_days = settings.ttl_seed_i2p_torrent_op_days
                else:
                    seed_days = settings.ttl_seed_i2p_torrent_reply_days
                epoch_start_time = now - (60 * 60 * 24 * seed_days)  # Oldest epoch to allow seeding

                if torrent.timestamp_started > epoch_start_time:
                    continue  # Torrent hasn't been seeding long enough

                # Torrent seeding long enough, delete torrent and data
                conn_info = dict(host=config.QBITTORRENT_HOST, port=8080)
                qbt_client = qbittorrentapi.Client(**conn_info)

                try:
                    qbt_client.auth_log_in()

                    # Get torrent hash
                    torrent_hash = None
                    if torrent.torrent_hash:
                        torrent_hash = torrent.torrent_hash
                    else:
                        # find torrent hash
                        for torrent_info in qbt_client.torrents_info():
                            if torrent_info.name == torrent.file_hash:
                                torrent_hash = torrent.hash
                                break

                    if not torrent_hash:
                        self.logger.error(f"Could not find torrent hash for {torrent.file_hash}")
                        continue

                    # Add torrent
                    with qbittorrentapi.Client(**conn_info) as qbt_client:
                        if qbt_client.torrents_delete(delete_files=True, torrent_hashes=torrent_hash) != "Ok.":
                            self.logger.error("Failed to add torrent.")
                            continue
                except:
                    self.logger.exception(f"qBittorrent error")
                    continue
                finally:
                    qbt_client.auth_log_out()

                self.logger.info(f"Removed torrent {torrent.file_hash} for message {torrent.message_id}")
                new_session.delete(torrent)

    def reset_view_counter(self):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_ENDPOINT_COUNTER, to=10):
            try:
                self.view_counter = OrderedDict({
                    "time": {
                        "epoch": int(time.time()),
                        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
                    }
                })
            except Exception as err:
                self.logger.error("Error reset_view_counter(): {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_ENDPOINT_COUNTER)

    def check_games(self):
        with session_scope(config.DB_PATH) as new_session:
            games = new_session.query(Games).filter(or_(
                Games.game_initiated == "uninitiated",
                Games.game_initiated == "player_a_chosen",
                Games.game_initiated == "player_b_chosen")).all()
            for each_game in games:
                self.logger.info("Initiating game {}".format(each_game.game_type))
                try:
                    initialize_game(each_game.id)
                except:
                    self.logger.exception("Could not initiate game: {}".format(each_game.game_type))

    def bm_change_connection_settings(self, restart_bm=True):
        # stop BM, edit keys.dat, start bitmessage
        try:
            if restart_bm:
                timer_waiting = time.time()
                while self.is_restarting_bitmessage and time.time() - timer_waiting < 360:
                    self.logger.info("Already restarting bitmessage. Please wait.")
                    time.sleep(2)

                self.is_restarting_bitmessage = True
                self.bitmessage_stop()

            # Get owner/group before modification
            try:
                uid = pwd.getpwnam("bitchan").pw_uid
                gid = grp.getgrnam("bitchan").gr_gid
            except:
                try:
                    uid = os.stat(config.BM_KEYS_DAT).st_uid
                    gid = os.stat(config.BM_KEYS_DAT).st_gid
                except:
                    uid = None
                    gid = None

            # Ensure all options exist in keys.dat
            socksproxytype = False
            sockslisten = None
            onionhostname = False
            onionport = None
            onionbindip = None

            with open(config.BM_KEYS_DAT, 'r') as f:
                for line in f.readlines():
                    if line.startswith("socksproxytype"):
                        socksproxytype = True
                    elif line.startswith("sockslisten"):
                        sockslisten = True
                    elif line.startswith("onionhostname"):
                        onionhostname = True
                    elif line.startswith("onionport"):
                        onionport = True
                    elif line.startswith("onionbindip"):
                        onionbindip = True

            if not socksproxytype:
                os.system(f'crudini --set {config.BM_KEYS_DAT} bitmessagesettings socksproxytype none')
            if not sockslisten:
                os.system(f'crudini --set {config.BM_KEYS_DAT} bitmessagesettings sockslisten False')
            if not onionhostname:
                os.system(f'crudini --set {config.BM_KEYS_DAT} bitmessagesettings onionhostname none')
            if not onionport:
                os.system(f'crudini --set {config.BM_KEYS_DAT} bitmessagesettings onionport 8444')
            if not onionbindip:
                os.system(f'crudini --set {config.BM_KEYS_DAT} bitmessagesettings onionbindip {config.BM_HOST}')

            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                self.logger.info(f"Changing keys.dat settings to: {settings.bm_connections_in_out}")

                # Change settings in keys.dat to the user-selected choices
                for line in fileinput.input(config.BM_KEYS_DAT, inplace=True):
                    if settings.bm_connections_in_out in ["in_clear_out_clear",
                                                          "in_tor+clear_out_clear",
                                                          "in_tor_out_clear"]:
                        if line.startswith("socksproxytype"):
                            line = "socksproxytype = none\n"
                            self.logger.info(f"Setting in keys.dat: {line}".rstrip())
                    if settings.bm_connections_in_out in ["in_clear_out_tor",
                                                          "in_tor+clear_out_tor",
                                                          "in_tor_out_tor"]:
                        if line.startswith("socksproxytype"):
                            line = "socksproxytype = SOCKS5\n"
                            self.logger.info(f"Setting in keys.dat: {line}".rstrip())
                    if settings.bm_connections_in_out in ["in_clear_out_clear",
                                                          "in_clear_out_tor"]:
                        if line.startswith("onionhostname"):
                            line = "onionhostname = none\n"
                            self.logger.info(f"Setting in keys.dat: {line}".rstrip())
                    if settings.bm_connections_in_out in ["in_clear_out_tor",
                                                          "in_tor+clear_out_clear",
                                                          "in_tor+clear_out_tor"]:
                        if line.startswith("sockslisten"):
                            line = "sockslisten = True\n"
                            self.logger.info(f"Setting in keys.dat: {line}".rstrip())
                    if settings.bm_connections_in_out in ["in_tor+clear_out_clear",
                                                          "in_tor_out_clear",
                                                          "in_tor+clear_out_tor",
                                                          "in_tor_out_tor"]:
                        if line.startswith("onionhostname"):
                            self.get_bm_onion_address()
                            if self.bm_onion_address:
                                line = f"onionhostname = {self.bm_onion_address}\n"
                                self.logger.info(f"Setting in keys.dat: {line}".rstrip())
                        if line.startswith("onionport"):
                            line = "onionport = 8444\n"
                            self.logger.info(f"Setting in keys.dat: {line}".rstrip())
                    if settings.bm_connections_in_out in ["in_tor_out_clear",
                                                          "in_tor_out_tor"]:
                        if line.startswith("onionbindip"):
                            line = f"onionbindip = {config.BM_HOST}\n"
                            self.logger.info(f"Setting in keys.dat: {line}".rstrip())
                        if line.startswith("sockslisten"):
                            line = "sockslisten = False\n"
                            self.logger.info(f"Setting in keys.dat: {line}".rstrip())

                    sys.stdout.write(line)

            # Set owner/group after modification
            if uid and pwd:
                os.chown(config.BM_KEYS_DAT, uid, gid)

            if restart_bm:
                self.bitmessage_start()
        except:
            self.logger.exception("bm_change_connection_settings()")
        finally:
            if restart_bm:
                self.is_restarting_bitmessage = False

    def enable_onion_services_only(self, enable):
        # stop BM, edit keys.dat, start bitmessage
        try:
            timer_waiting = time.time()
            while self.is_restarting_bitmessage and time.time() - timer_waiting < 360:
                self.logger.info("Already restarting bitmessage. Please wait.")
                time.sleep(2)

            self.is_restarting_bitmessage = True
            self.bitmessage_stop()
            line_found = False

            # Get owner/group before modification
            try:
                uid = pwd.getpwnam("bitchan").pw_uid
                gid = grp.getgrnam("bitchan").gr_gid
            except:
                try:
                    uid = os.stat(config.BM_KEYS_DAT).st_uid
                    gid = os.stat(config.BM_KEYS_DAT).st_gid
                except:
                    uid = None
                    gid = None

            for line in fileinput.input(config.BM_KEYS_DAT, inplace=True):
                if line.startswith("onionservicesonly"):
                    line_found = True
                    val_set = "true" if enable else "false"
                    self.logger.info("'onionservicesonly' found, setting to {}".format(val_set))
                    line = "onionservicesonly = {}\n".format(val_set)
                sys.stdout.write(line)

            # Set owner/group after modification
            if uid and pwd:
                os.chown(config.BM_KEYS_DAT, uid, gid)

            if not line_found:
                self.logger.info("'onionservicesonly' not found. Check keys.dat configuration.")
            self.bitmessage_start()
        finally:
            self.is_restarting_bitmessage = False

    def regenerate_bitmessage_onion_address(self):
        paths_remove = [
            f"{config.TOR_HS_BM}/hostname",
            f"{config.TOR_HS_BM}/hs_ed25519_public_key",
            f"{config.TOR_HS_BM}/hs_ed25519_secret_key"
        ]
        for each_path in paths_remove:
            if os.path.exists(each_path):
                try:
                    os.remove(each_path)
                except:
                    self.logger.error("Could not remove {}".format(each_path))

        self.tor_restart()
        self.timer_check_onion_address = time.time() + 60

    def get_bm_onion_address(self):
        self.bm_onion_address = None
        try:
            if os.path.exists(config.TOR_HS_BM):
                with open(f'{config.TOR_HS_BM}/hostname', 'r') as f:
                    self.bm_onion_address = f.read().rstrip()
        except:
            self.logger.exception("get_bm_onion_address()")
        if not self.bm_onion_address:
            self.logger.info("Could not get hidden service onion address for bitmessage")

    def check_onion_address(self):
        # Log tor hidden onion service addresses
        self.get_bm_onion_address()
        try:
            self.logger.info("Bitmessage onion address: {}".format(self.bm_onion_address))
            if os.path.exists(config.TOR_HS_RAND):
                with open(f'{config.TOR_HS_RAND}/hostname', 'r') as f:
                    self.logger.info("BitChan onion address (random): {}".format(f.read().rstrip()))
            if os.path.exists(config.TOR_HS_CUS):
                with open(f'{config.TOR_HS_CUS}/hostname', 'r') as f:
                    self.logger.info("BitChan onion address (custom): {}".format(f.read().rstrip()))
        except:
            pass

        try:
            if self.bm_onion_address:
                self.logger.info("tor onion address found for Bitmessage. "
                                 "Checking if 'onionhostname' set in keys.dat...")
                set_onionhostname = False
                with open(config.BM_KEYS_DAT, 'r') as f:
                    for each_line in f.readlines():
                        if each_line.startswith("onionhostname"):
                            self.logger.info("Found line: '{}'".format(each_line.rstrip()))
                            try:
                                check_address = each_line.split(" = ")[1].rstrip()
                            except:
                                check_address = ""
                            self.logger.info("keys.dat: '{}'".format(check_address))
                            self.logger.info("tor: '{}'".format(self.bm_onion_address))
                            with session_scope(config.DB_PATH) as new_session:
                                settings = new_session.query(GlobalSettings).first()
                                if (check_address != self.bm_onion_address and
                                        settings.bm_connections_in_out not in ["in_clear_out_clear",
                                                                               "in_clear_out_tor"]):  # settings require onionhostname = none
                                    self.logger.info(
                                        "Invalid keys.dat onion address. Updating and restarting Bitmessage")
                                    set_onionhostname = True
                                else:
                                    self.logger.info("Valid onionhostname setting in keys.dat.")

                if set_onionhostname:
                    # stop BM, edit keys.dat, start bitmessage
                    try:
                        timer_waiting = time.time()
                        while self.is_restarting_bitmessage and time.time() - timer_waiting < 360:
                            self.logger.info("Already restarting bitmessage. Please wait.")
                            time.sleep(2)

                        self.is_restarting_bitmessage = True
                        self.bitmessage_stop()
                        time.sleep(15)
                        line_found = False

                        # Get owner/group before modification
                        try:
                            uid = pwd.getpwnam("bitchan").pw_uid
                            gid = grp.getgrnam("bitchan").gr_gid
                        except:
                            try:
                                uid = os.stat(config.BM_KEYS_DAT).st_uid
                                gid = os.stat(config.BM_KEYS_DAT).st_gid
                            except:
                                uid = None
                                gid = None

                        for line in fileinput.input(config.BM_KEYS_DAT, inplace=True):
                            if line.startswith("onionhostname") and self.bm_onion_address:
                                line_found = True
                                self.logger.info("'onionhostname' found, setting to onion address.")
                                line = f"onionhostname = {self.bm_onion_address}\n"
                            sys.stdout.write(line)
                        if not line_found:
                            self.logger.info("'onionhostname' not found. Check keys.dat configuration.")

                        # Set owner/group after modification
                        if uid and pwd:
                            os.chown(config.BM_KEYS_DAT, uid, gid)

                        self.bm_change_connection_settings(restart_bm=False)

                        self.bitmessage_start()
                        time.sleep(15)
                    finally:
                        self.is_restarting_bitmessage = False
                else:
                    self.logger.info("Bitmessage onion address correctly set in keys.dat.")
            else:
                self.logger.info("tor onion address not found for Bitmessage. Check torrc configuration.")
        except:
            pass

    @staticmethod
    def delete_old_captchas():
        with session_scope(config.DB_PATH) as new_session:
            captchas = new_session.query(Captcha).filter(
                Captcha.timestamp_utc < (time.time() - (60 * 60 * 24 * 4))).all()
            for each_captcha in captchas:
                new_session.delete(each_captcha)
                new_session.commit()

    def scan_locked_threads(self):
        with session_scope(config.DB_PATH) as new_session:
            admin_cmd = new_session.query(Command).filter(and_(
                Command.action == "set",
                Command.action_type == "thread_options")).all()
            for each_adm in admin_cmd:
                # Find locked threads and check for consistency
                if (each_adm.thread_id and
                        each_adm.thread_lock and
                        each_adm.thread_lock_ts):
                    thread = new_session.query(Threads).filter(
                        Threads.thread_hash == each_adm.thread_id).first()
                    if not thread:
                        continue

                    access = get_access(thread.chan.address)

                    messages = new_session.query(Messages).filter(and_(
                        Messages.thread_id == thread.id,
                        Messages.timestamp_sent > each_adm.thread_lock_ts)).all()
                    deleted_msg = False
                    for each_msg in messages:
                        if each_msg.address_from in access["primary_addresses"]:
                            continue  # Owners can post to locked threads
                        deleted_msg = True
                        self.logger.info(
                            "Found post {} in thread {} with a timestamp beyond the lock timestamp. Deleting".format(
                                each_msg.post_id, thread.thread_hash_short))
                        new_session.delete(each_msg)

                    # Generate new cards for threads with messages deleted
                    if deleted_msg:
                        card_test = new_session.query(PostCards).filter(
                            PostCards.thread_id == thread.thread_hash).first()
                        if card_test and not card_test.regenerate:
                            card_test.regenerate = True
                            new_session.commit()

                # Find anchored threads and check for consistency
                if (each_adm.thread_id and
                        each_adm.thread_anchor and
                        each_adm.thread_anchor_ts):
                    thread = new_session.query(Threads).filter(
                        Threads.thread_hash == each_adm.thread_id).first()
                    if not thread:
                        continue

                    if thread.anchored_local and thread.anchored_local_ts:
                        latest_allowed_ts_local = thread.anchored_local_ts
                    else:
                        latest_allowed_ts_local = 0
                    latest_allowed_ts_remote = each_adm.thread_anchor_ts

                    list_ts = []
                    if latest_allowed_ts_local:
                        list_ts.append(latest_allowed_ts_local)
                    if latest_allowed_ts_remote:
                        list_ts.append(latest_allowed_ts_remote)
                    if list_ts:
                        earliest_ts = min(list_ts)
                    else:
                        earliest_ts = 0

                    message = new_session.query(Messages).filter(and_(
                        Messages.thread_id == thread.id,
                        Messages.timestamp_sent < earliest_ts)).order_by(
                            Messages.timestamp_sent.desc()).first()
                    if thread.timestamp_sent != message.timestamp_sent:
                        self.logger.info(
                            "Found thread {} with a timestamp different from the latest allowed by a "
                            "local or remote anchor. Changing from {} to {}.".format(
                                message.post_id, thread.timestamp_sent, message.timestamp_sent))
                        thread.timestamp_sent = message.timestamp_sent
                        new_session.commit()

    def clear_session_info(self):
        with session_scope(config.DB_PATH) as new_session:
            session_infos = new_session.query(SessionInfo).all()
            for session in session_infos:
                now = time.time()
                if (session.request_rate_ts > 0 and
                        now - session.request_rate_ts > 60 * 60 * 24 * config.SESSION_TIMEOUT_DAYS):
                    self.logger.info("Deleting session: verified: {}, ID: {}, now: {}, last: {}, stale_sec: {}".format(
                        session.verified,
                        session.session_id,
                        now,
                        session.request_rate_ts,
                        now - session.request_rate_ts))
                    # Delete if last request is older than 7 days
                    new_session.delete(session)
                    new_session.commit()

    def signal_generate_post_numbers(self):
        self.timer_update_post_numbers = time.time() + (60 * 5)
        self.update_post_numbers = True

    def generate_post_numbers(self, all_boards=False):
        try:
            with session_scope(config.DB_PATH) as session:
                # First, reset all board counts to 0
                if all_boards:
                    boards = session.query(Chan).filter(
                        Chan.type == "board").all()
                else:
                    boards = session.query(Chan).filter(
                        and_(
                            Chan.type == "board",
                            Chan.regenerate_numbers.is_(True))).all()
                for each_board in boards:
                    each_board.last_post_number = 0
                session.commit()

                # Set post numbers
                messages = session.query(Messages).order_by(
                    Messages.timestamp_sent.asc()).all()
                for each_msg in messages:
                    if not each_msg.thread_id:
                        each_msg.post_number = 0
                        session.commit()
                        continue

                    thread = session.query(Threads).filter(
                        Threads.id == each_msg.thread_id).first()
                    if not thread.chan_id:
                        each_msg.post_number = 0
                        session.commit()
                        continue

                    board = session.query(Chan).filter(
                        Chan.id == thread.chan_id).first()
                    if not board:
                        each_msg.post_number = 0
                        session.commit()
                        continue

                    board.last_post_number = board.last_post_number + 1
                    if each_msg.post_number != board.last_post_number:
                        each_msg.regenerate_post_html = True
                    each_msg.post_number = board.last_post_number

                    self.logger.debug("Board {}: Post {}: Post number {}".format(
                        board.address,
                        each_msg.post_id,
                        each_msg.post_number))
                    session.commit()
        except Exception:
            self.logger.exception("Updating post numbers")

    def check_sync_locked(self):
        """Determine if a Bitmessage sync has completed"""
        bm_status = {}
        messages_processed_diff = 0
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                with timeout(seconds=5):
                    bm_status = api.clientStatus()
            except Exception as err:
                self.logger.error("Error check_sync_locked(): {}".format(err))
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)

        if "networkStatus" in bm_status:
            if bm_status["networkStatus"] != "notConnected":
                if not self.bm_connected_timer:
                    # upon becoming connected, wait 90 sec until checking if synced
                    self.bm_connected_timer = time.time() + 60
                self.bm_connected = True
            else:
                self.bm_connected = False
                self.bm_connected_timer = None
                self.bm_pending_download_timer = None

        if "numberOfMessagesProcessed" in bm_status:
            if bm_status["numberOfMessagesProcessed"] > self.bm_number_messages_processed_last:
                messages_processed_diff = (bm_status["numberOfMessagesProcessed"] -
                                           self.bm_number_messages_processed_last)
            self.bm_number_messages_processed_last = bm_status["numberOfMessagesProcessed"]

        if "pendingDownload" in bm_status:
            if bm_status["pendingDownload"] == 0:
                self.bm_pending_download = False
            else:
                self.bm_pending_download = True
                self.bm_sync_complete = False

            if self.bm_connected:
                if "pendingDownload" in bm_status and bm_status["pendingDownload"] < 50:
                    if not self.bm_pending_download_timer:
                        self.bm_pending_download_timer = time.time() + 60
                else:
                    self.bm_pending_download_timer = None
                    self.bm_sync_complete = False

        # indicate sync is complete if:
        # 1) connected and no more than 10 new messages processed
        # and no pending downloads for past 60 seconds.
        # or
        # 2) connected and no more than 10 new messages processed and
        # only a few pending downloads remain and have not increased over 50 in the past 60 seconds.
        if (self.bm_connected and
                messages_processed_diff < 20 and
                (self.bm_connected_timer and time.time() > self.bm_connected_timer) and
                (
                    not self.bm_pending_download or
                    (self.bm_pending_download_timer and
                     time.time() > self.bm_pending_download_timer)
                )):
            self.bm_connected_timer = None
            self.bm_pending_download_timer = None
            self.bm_sync_complete = True

        # self.logger.debug("con {}, pend {} {}, synced {}".format(
        #     self.bm_connected,
        #     bm_status["pendingDownload"],
        #     self.bm_pending_download,
        #     self.bm_sync_complete))

    def send_lists(self):
        for list_chan in get_db_table_daemon(Chan).filter(Chan.type == "list").all():
            if not list_chan:
                continue

            try:
                run_id = get_random_alphanumeric_string(
                    6, with_punctuation=False, with_spaces=False)

                self.logger.info("{}: Checking list {} ({})".format(
                    run_id, list_chan.address, list_chan.label))

                list_access = get_access(list_chan.address)

                errors, dict_chan_info = process_passphrase(list_chan.passphrase)
                if not dict_chan_info or errors:
                    self.logger.error("{}: Error(s) sending list message to {}".format(
                        run_id, list_chan.address))
                    for err in errors:
                        self.logger.error(err)
                    break

                from_primary_secondary = self.find_senders(
                    list_chan.address, ["primary_addresses", "secondary_addresses"])
                from_tertiary = self.find_senders(
                    list_chan.address, ["tertiary_addresses"])

                try:
                    rules = json.loads(list_chan.rules)
                except:
                    rules = {}

                from_non_self = []
                requires_identity = False
                if (dict_chan_info["access"] == "public" and
                        "require_identity_to_post" in rules and
                        rules["require_identity_to_post"]):
                    requires_identity = True
                    for each_add in self.get_all_chans():
                        if each_add != list_chan.address and each_add not in list_access["restricted_addresses"]:
                            from_non_self.append(each_add)
                    for each_add in self.get_identities():
                        if each_add != list_chan.address and each_add not in list_access["restricted_addresses"]:
                            from_non_self.append(each_add)

                if list_chan.list_send:
                    self.logger.info("{}: List instructed to send.".format(run_id))
                    with session_scope(config.DB_PATH) as new_session:
                        list_mod = new_session.query(Chan).filter(
                            Chan.address == list_chan.address).first()
                        list_mod.list_send = False
                        new_session.commit()

                        allowed_addresses = []

                        if from_primary_secondary:
                            allowed_addresses += from_primary_secondary
                        if from_tertiary:
                            allowed_addresses += from_tertiary
                        if (dict_chan_info["access"] == "public" and
                                requires_identity and
                                from_non_self):
                            allowed_addresses += from_non_self
                        if dict_chan_info["access"] == "public":
                            allowed_addresses.append(list_chan.address)

                        if allowed_addresses and list_chan.default_from_address in allowed_addresses:
                            from_address = list_chan.default_from_address
                        elif allowed_addresses:
                            from_address = allowed_addresses[0]
                        else:
                            from_address = None

                elif from_primary_secondary and list_chan.list_message_expires_time_owner:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_owner):
                        self.logger.info(
                            "{}: List expiring for owner with expires_time.".format(run_id))
                        from_address = from_primary_secondary[0]
                    else:
                        continue
                elif from_tertiary and list_chan.list_message_expires_time_user:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        self.logger.info(
                            "{}: List expiring for user with expires_time.".format(run_id))
                        from_address = from_tertiary[0]
                    else:
                        continue
                elif (dict_chan_info["access"] == "public" and
                        requires_identity and
                        from_non_self and
                        list_chan.list_message_expires_time_user):
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        self.logger.info(
                            "{}: List expiring for user with expires_time and is public "
                            "with rule requires_identity_to_post.".format(run_id))
                        from_address = from_non_self[0]
                    else:
                        continue
                elif dict_chan_info["access"] == "public" and list_chan.list_message_expires_time_user:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        self.logger.info(
                            "{}: List expiring for user with expires_time and is public.".format(run_id))
                        from_address = list_chan.address
                    else:
                        continue
                elif from_primary_secondary and list_chan.list_message_timestamp_utc_owner:
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_owner):
                        self.logger.info(
                            "{}: List expiring for owner with timestamp.".format(run_id))
                        from_address = from_primary_secondary[0]
                    else:
                        continue
                elif from_tertiary and list_chan.list_message_timestamp_utc_user:
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        self.logger.info(
                            "{}: List expiring for user with timestamp.".format(run_id))
                        from_address = from_tertiary[0]
                    else:
                        continue
                elif (dict_chan_info["access"] == "public" and
                        requires_identity and
                        from_non_self and
                        list_chan.list_message_timestamp_utc_user):
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        self.logger.info(
                            "{}: List expiring for user with timestamp and is public "
                            "with rule requires_identity_to_post.".format(run_id))
                        from_address = from_non_self[0]
                    else:
                        continue
                elif dict_chan_info["access"] == "public" and list_chan.list_message_timestamp_utc_user:
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        self.logger.info(
                            "{}: List expiring for user with timestamp and "
                            "is public.".format(run_id))
                        from_address = list_chan.address
                    else:
                        continue
                else:
                    self.logger.info("{}: List not expiring or you don't have an "
                                "address authorized to send.".format(run_id))
                    continue

                if not from_address:
                    continue

                send_msg_dict = {
                    "version": config.VERSION_MSG,
                    "timestamp_utc": self.get_utc(),
                    "message_type": "list",
                    "access": list_chan.access,
                    "list": json.loads(list_chan.list)
                }

                pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                if list_chan.pgp_passphrase_msg:
                    pgp_passphrase_msg = list_chan.pgp_passphrase_msg

                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    json.dumps(send_msg_dict),
                    symmetric="AES256",
                    passphrase=pgp_passphrase_msg,
                    recipients=None)
                message_send = base64.b64encode(message_encrypted.data).decode()

                # Don't send empty public list
                if dict_chan_info["access"] == "public" and len(send_msg_dict["list"]) == 0:
                    self.logger.info("{}: Don't send empty public list".format(run_id))
                    continue

                self.logger.info("{}: Sending {} list message with {} entries from {} to {}".format(
                    run_id,
                    dict_chan_info["access"],
                    len(send_msg_dict["list"]),
                    from_address,
                    list_chan.address))

                # Don't allow a message to send while Bitmessage is restarting
                allow_send = False
                timer = time.time()
                while not allow_send:
                    if self.bitmessage_restarting() is False:
                        allow_send = True
                    if time.time() - timer > config.BM_WAIT_DELAY:
                        self.logger.error(
                            "{}: Unable to send message: "
                            "Could not detect Bitmessage running.".format(run_id))
                        return
                    time.sleep(1)

                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                    try:
                        with timeout(seconds=20):
                            return_str = api.sendMessage(
                                list_chan.address,
                                from_address,
                                "",
                                message_send,
                                2,
                                config.BM_TTL)
                    except Exception:
                        pass
                    finally:
                        time.sleep(config.API_PAUSE)
                        lf.lock_release(config.LOCKFILE_API)
            except Exception:
                self.logger.exception("send_lists()")

    def get_message_expires_times(self):
        try:
            with session_scope(config.DB_PATH) as new_session:
                msg_inbox = new_session.query(Messages).filter(
                    Messages.expires_time == 5).all()
                for each_msg in msg_inbox:
                    each_msg.expires_time = 1  # No inventory entry, mark for deletion

                msg_inbox = new_session.query(Messages).filter(
                    or_(Messages.expires_time.is_(None),
                        Messages.expires_time == 0)).all()
                for each_msg in msg_inbox:
                    expires = get_msg_expires_time(each_msg.message_id)
                    if expires:
                        self.logger.info("{}: Messages: Set expire time to {}".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper(), expires))
                        each_msg.expires_time = expires
                        each_msg.regenerate_post_html = True
                    else:
                        self.logger.info("{}: Messages: No inventory entry.".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper()))
                        each_msg.expires_time = 5

                msg_deleted = new_session.query(DeletedMessages).filter(
                    DeletedMessages.expires_time == 5).all()
                for each_msg in msg_deleted:
                    each_msg.expires_time = 1  # No inventory entry, mark for deletion

                msg_deleted = new_session.query(DeletedMessages).filter(
                    or_(DeletedMessages.expires_time.is_(None),
                        DeletedMessages.expires_time == 0)).all()
                for each_msg in msg_deleted:
                    expires = get_msg_expires_time(each_msg.message_id)
                    if expires:
                        self.logger.info("{}: DeletedMessages: Set expire time to {}".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper(), expires))
                        each_msg.expires_time = expires

                        # Update list expires time for owner messages
                        chan_list = new_session.query(Chan).filter(and_(
                            Chan.type == "list",
                            Chan.list_message_id_owner == each_msg.message_id,
                            Chan.list_message_expires_time_owner.is_(None))).first()
                        if chan_list:
                            chan_list.list_message_expires_time_owner = expires
                            if expires > self.get_utc():
                                days = (expires - self.get_utc()) / 60 / 60 / 24
                                self.logger.info(
                                    "{}: Setting empty owner list expire time"
                                    " to {} ({:.1f} days from now)".format(
                                        each_msg.message_id[-config.ID_LENGTH:].upper(),
                                        expires,
                                        days))

                        # Update list expires time for user messages
                        chan_list = new_session.query(Chan).filter(and_(
                            Chan.type == "list",
                            Chan.list_message_id_user == each_msg.message_id,
                            Chan.list_message_expires_time_user.is_(None))).first()
                        if chan_list:
                            chan_list.list_message_expires_time_user = expires
                            if expires > self.get_utc():
                                days = (expires - self.get_utc()) / 60 / 60 / 24
                                self.logger.info(
                                    "{}: Setting empty user list expire time "
                                    "to {} ({:.1f} days from now)".format(
                                        each_msg.message_id[-config.ID_LENGTH:].upper(),
                                        expires,
                                        days))
                    else:
                        self.logger.info("{}: DeletedMessages. No inventory entry.".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper()))
                        each_msg.expires_time = 5
                new_session.commit()
        except:
            self.logger.exception("get_msg_expires_time")

    def get_mail_count(self, address):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                with timeout(seconds=5):
                    messages = api.getInboxMessagesByReceiver(address)
                if "inboxMessages" in messages:
                    unread_count = 0
                    total_count = 0
                    for each_msg in messages["inboxMessages"]:
                        total_count += 1
                        if not each_msg["read"]:
                            unread_count += 1
                    return total_count, unread_count
            except Exception as err:
                self.logger.error("Error get_mail_count(): {}".format(err))
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)
        return None, None

    def update_unread_mail_count(self, address):
        with session_scope(config.DB_PATH) as new_session:
            ident = new_session.query(Identity).filter(
                Identity.address == address).first()
            total, unread = self.get_mail_count(address)
            if None not in [total, unread]:
                ident.total_messages = total
                ident.unread_messages = unread
                new_session.commit()

    def check_unread_mail(self):
        """Save number of unread messages for each Identity"""
        with session_scope(config.DB_PATH) as new_session:
            for identity in new_session.query(Identity).all():
                self.update_unread_mail_count(identity.address)

    def update_identities(self):
        new_identities = {}
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                with timeout(seconds=5):
                    dict_return = api.listAddresses()
            except Exception as err:
                self.logger.error("Exception getting identities: {}".format(err))
                return
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)
        else:
            return

        for address in dict_return['addresses']:
            if not address['chan']:
                new_identities[address['address']] = {
                    "label": address['label'],
                    "enabled": address['enabled']
                }
                if len(address['label']) > config.LABEL_LENGTH:
                    new_identities[address['address']]["label_short"] = address['label'][:config.LABEL_LENGTH]
                else:
                    new_identities[address['address']]["label_short"] = address['label']

        if self._identity_dict.keys() != new_identities.keys() or self._refresh_identities:
            self._refresh_identities = False
            self.logger.info("Updating Identities")
            with session_scope(config.DB_PATH) as new_session:
                for address, each_ident in new_identities.items():
                    identity = new_session.query(
                        Identity).filter(Identity.address == address).first()
                    if not identity:
                        new_ident = Identity()
                        new_ident.address = address
                        new_ident.label = each_ident["label"]
                        new_session.add(new_ident)
                        new_session.commit()
                    else:
                        new_identities[address]["label"] = identity.label
                        if len(new_identities[address]["label"]) > config.LABEL_LENGTH:
                            new_identities[address]["label_short"] = new_identities[address]["label"][:config.LABEL_LENGTH]
                        else:
                            new_identities[address]["label_short"] = new_identities[address]["label"]
            self._identity_dict = new_identities

    def update_subscriptions(self):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                with timeout(seconds=5):
                    dict_return = api.listSubscriptions()
            except Exception as err:
                self.logger.error("Exception getting subscriptions: {}".format(err))
                return
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)
        else:
            return

        for address in dict_return['subscriptions']:
            dict_subscription = {
                "label": address['label'],
                "enabled": address['enabled']
            }
            if (address['address'] not in self._subscription_dict or
                    self._subscription_dict[address['address']] != dict_subscription):
                self.logger.info("Updating Identity {}".format(address['address']))
                self._subscription_dict[address['address']] = dict_subscription

    def update_address_book(self):
        new_addresses = {}
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                with timeout(seconds=5):
                    dict_return = api.listAddressBookEntries()
            except Exception as err:
                self.logger.error("Exception getting address book entries: {}".format(err))
                return
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)
        else:
            return

        for address in dict_return["addresses"]:
            label = base64.b64decode(address["label"]).decode()
            new_addresses[address["address"]] = {"label": label}

        with session_scope(config.DB_PATH) as new_session:
            for address in new_session.query(AddressBook).all():
                if address.address not in new_addresses:
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                        try:
                            with timeout(seconds=5):
                                api.addAddressBookEntry(address.address, base64.b64encode(address.label.encode()).decode())
                            new_addresses[address.address] = {"label": address.label}
                        except Exception as err:
                            self.logger.error("Exception adding address book entry: {}".format(err))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)

        for address in new_addresses:
            label = new_addresses[address]["label"]
            if len(label) > config.LABEL_LENGTH:
                new_addresses[address]["label_short"] = label[:config.LABEL_LENGTH]
            else:
                new_addresses[address]["label_short"] = label

        if (self._address_book_dict.keys() != new_addresses.keys() or
                self._refresh_address_book):
            self._refresh_address_book = False
            self.logger.info("Updating Address Book")
            with session_scope(config.DB_PATH) as new_session:
                for address, each_add in new_addresses.items():
                    address_book = new_session.query(AddressBook).filter(
                        AddressBook.address == address).first()
                    if not address_book:
                        new_add_book = AddressBook()
                        new_add_book.address = address
                        new_add_book.label = each_add["label"]
                        new_session.add(new_add_book)
                        new_session.commit()
                    else:
                        new_addresses[address]["label"] = address_book.label
                        if len(new_addresses[address]["label"]) > config.LABEL_LENGTH:
                            new_addresses[address]["label_short"] = new_addresses[address]["label"][:config.LABEL_LENGTH]
                        else:
                            new_addresses[address]["label_short"] = new_addresses[address]["label"]

            self._address_book_dict = new_addresses

    def update_chans(self):
        chans_labels = {}
        chans_addresses = {}
        all_chans = {}
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                with timeout(seconds=5):
                    dict_return = api.listAddresses()
            except Exception as err:
                self.logger.error("Exception getting chans: {}".format(err))
                return
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)
        else:
            return

        for address in dict_return['addresses']:
            # self.logger.info("Chan: {}".format(address))
            if address['chan']:
                all_chans[address['address']] = {
                    "label": address['label'],
                    "enabled": address['enabled']
                }

            with session_scope(config.DB_PATH) as new_session:
                # Only scan chans from the bitchan database
                # Leave other chans alone
                chan = new_session.query(
                    Chan).filter(Chan.address == address['address']).first()
                if chan and address['chan'] and address['enabled']:
                    chans_labels[address['label']] = address['address']
                    chans_addresses[address['address']] = address['label']

                if address['chan']:
                    if chan:
                        all_chans[address['address']]["label"] = chan.label
                    label = all_chans[address['address']]["label"]
                    if len(all_chans[address['address']]["label"]) > config.LABEL_LENGTH:
                        all_chans[address['address']]["label_short"] = label[:config.LABEL_LENGTH]
                    else:
                        all_chans[address['address']]["label_short"] = label

        if self._all_chans != all_chans:
            self._all_chans = all_chans

        with session_scope(config.DB_PATH) as new_session:
            log_description = None
            log_address = None

            # Join board chan if found in database and not found in Bitmessage
            board_chans = new_session.query(Chan).filter(Chan.type == "board").all()
            for each_board in board_chans:
                if not each_board.is_setup:
                    self.logger.info("Found board chan in database that needs to be joined. Joining.")
                    address = self.join_chan(each_board.passphrase, clear_inventory=True)
                    time.sleep(1)

                    if address and "Chan address is already present" in address:
                        self.logger.info("Board already present in Bitmessage. Finding address...")
                        for each_address in self._all_chans:
                            if each_board.passphrase in self._all_chans[each_address]["label"]:
                                self.logger.info(
                                    "Board address found in BM: {}. Saving to database.".format(each_address))
                                each_board.address = each_address
                                break
                        each_board.is_setup = True
                        log_description = "Joined Board {}".format(each_address)
                        log_address = each_board.address
                        new_session.commit()
                    elif address and address.startswith("BM-") and not each_board.address:
                        each_board.address = address
                        each_board.is_setup = True
                        log_description = "Joined Board {}".format(address)
                        log_address = address
                        new_session.commit()
                    else:
                        self.logger.info("Could not join board. Joining might be queued. Trying again later.")

            # Join list chans if in database and not added to Bitmessage
            chans_list = new_session.query(Chan).filter(Chan.type == "list").all()
            for each_list in chans_list:
                if not each_list.is_setup:
                    # Chan in bitmessage not in database. Add to database, generate and send list message.
                    self.logger.info("Found list chan in database that needs to be joined. Joining.")
                    # Join default list chan
                    address = self.join_chan(each_list.passphrase, clear_inventory=False)
                    time.sleep(1)

                    if address and "Chan address is already present" in address:
                        self.logger.info("List already present in Bitmessage. Finding address...")
                        for each_address in self._all_chans:
                            if each_list.passphrase in self._all_chans[each_address]["label"]:
                                self.logger.info(
                                    "List address found in BM: {}. Saving to database.".format(each_address))
                                each_list.address = each_address
                                break
                        each_list.is_setup = True
                        log_description = "Joined List {}".format(each_address)
                        log_address = each_list.address
                        new_session.commit()
                    elif address and address.startswith("BM-") and not each_list.address:
                        each_list.address = address
                        each_list.is_setup = True
                        log_description = "Joined List {}".format(address)
                        log_address = address
                        new_session.commit()
                    else:
                        self.logger.info("Could not join list. Joining might be queued. Trying again later.")

            if log_description:
                add_mod_log_entry(log_description, board_address=log_address)

    def process_stored_messages(self):
        self.logger.debug("process_stored_messages() start")
        found_empty_post_number = False

        with session_scope(config.DB_PATH) as new_session:
            for message in new_session.query(Messages).all():
                if message.post_number is None:
                    found_empty_post_number = True

                if not message.post_id:
                    post_id = message.message_id[-config.ID_LENGTH:].upper()
                    self.logger.info("{}: Post ID doesn't exist, creating and saving {}".format(
                        message.message_id[-config.ID_LENGTH:].upper(),
                        post_id))
                    message.post_id = post_id
                    new_session.commit()

                if new_session.query(DeletedMessages).filter(
                        DeletedMessages.message_id == message.message_id).count():
                    self.logger.info("{}: process_stored_messages(): Message labeled as deleted. Deleting.".format(
                        message.message_id[-config.ID_LENGTH:].upper()))
                    self.trash_message(message.message_id)
                    new_session.delete(message)
                    continue

                if not message.thread or not message.thread.chan:
                    self.logger.info("{}: Message missing thread or chan. Deleting.".format(
                        message.message_id[-config.ID_LENGTH:].upper()))
                    self.trash_message(message.message_id)
                    continue

        if found_empty_post_number:
            self.logger.info("Post with post_number of None found. Scanning all posts.")
            self.update_post_numbers = True

    def check_downloads(self):
        with session_scope(config.DB_PATH) as new_session:
            messages = new_session.query(Messages).filter(
                and_(
                    Messages.file_amount.isnot(None),
                    Messages.file_download_successful.isnot(True),
                    or_(
                        and_(Messages.start_download.is_(True), Messages.file_currently_downloading.isnot(True)),
                        and_(Messages.start_download.is_(False), Messages.file_currently_downloading.is_(True))
                    )
                ))

            for message in messages.all():
                if message.start_download and not message.file_currently_downloading:
                    # Download instructed to start by user. Only initiate
                    # download once, and skip further processing attempts
                    # unless download has failed. Use thread to allow new
                    # messages to continue to be processed while
                    # downloading.
                    self.logger.debug(f"Starting download thread for {message.message_id}")
                    message.file_progress = "Download starting"
                    message.regenerate_post_html = True
                    message.file_currently_downloading = True
                    new_session.commit()
                    thread_download = Thread(
                        target=allow_download, args=(message.message_id,))
                    thread_download.daemon = True
                    thread_download.start()

    def queue_new_messages(self):
        """Add new messages to processing queue"""
        messages = []
        all_chans = self.get_all_chans()
        for i, each_address in enumerate(all_chans):
            self.logger.debug("Getting messages for chan {}".format(each_address))
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                try:
                    with timeout(seconds=5):
                        messages_api = api.getInboxMessagesByReceiver(each_address)
                    if "inboxMessages" in messages_api and messages_api['inboxMessages']:
                        messages.extend(messages_api['inboxMessages'])
                except Exception as err:
                    self.logger.error("Exception getting all message IDs: {}".format(err))
                    return
                finally:
                    if i + 1 == len(all_chans):
                        time.sleep(config.API_PAUSE)
                    else:
                        time.sleep(0.1)
                    lf.lock_release(config.LOCKFILE_API)
            else:
                return

        with session_scope(config.DB_PATH) as new_session:
            for message in messages:
                if message["msgid"] in self._non_bitchan_message_ids:
                    continue

                if new_session.query(DeletedMessages).filter(
                        DeletedMessages.message_id == message["msgid"]).count():
                    self.logger.info("{}: queue_new_messages(): Message labeled as deleted. Deleting.".format(
                        message["msgid"][-config.ID_LENGTH:].upper()))
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=120):
                        try:
                            with timeout(seconds=5):
                                api.trashMessage(message["msgid"])
                        except Exception as err:
                            self.logger.error("Exception during message delete: {}".format(err))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)
                    continue

                if new_session.query(Messages).filter(
                        Messages.message_id == message["msgid"]).count():
                    self.logger.info("{}: Message already in DB. Deleting.".format(
                        message["msgid"][-config.ID_LENGTH:].upper()))
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=120):
                        try:
                            api.trashMessage(message["msgid"])
                        except Exception as err:
                            self.logger.error("Exception during message delete: {}".format(err))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)
                    continue

                to_address = message['toAddress']

                # Check if chan exists
                if not new_session.query(Chan).filter(
                        Chan.address == to_address).count():
                    self.logger.info(
                        "{}: To address {} not in board or list DB. "
                        "Indicative of a non-BitChan message. "
                        "Adding to non-BC message list.".format(
                            message["msgid"][-config.ID_LENGTH:].upper(),
                            to_address))
                    if message["msgid"] not in self._non_bitchan_message_ids:
                        self._non_bitchan_message_ids.append(message["msgid"])
                    continue

                if message["msgid"] not in self.message_threads:
                    self.logger.info(
                        "{}: Adding message to processing queue".format(
                            message["msgid"][-config.ID_LENGTH:].upper()))
                    self.message_threads[message["msgid"]] = {
                        "thread": Thread(target=self.process_message, args=(message,)),
                        "started": False,
                        "completed": False
                    }
                    self.message_threads[message["msgid"]]["thread"].setDaemon(True)
                    self.check_message_threads()

        #
        # Update list of non-bitchan message IDs in database
        #
        now = time.time()
        if self.timer_non_bitchan_message_ids < now:
            while self.timer_non_bitchan_message_ids < now:
                self.timer_non_bitchan_message_ids += 3600  # 1 hour
            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                settings.discard_message_ids = json.dumps(self._non_bitchan_message_ids)
                new_session.commit()

    def check_message_threads(self):
        """Ensure message thread queue is moving"""
        threads_running = 0
        list_threads_completed = []
        for thread_id in self.message_threads:
            if self.message_threads[thread_id]["thread"].is_alive():
                self.logger.debug(f"Message thread is alive. ID: {thread_id}")
                threads_running += 1
            if (self.message_threads[thread_id]["started"] and
                    not self.message_threads[thread_id]["thread"].is_alive()):
                self.logger.debug(f"Message thread is complete. ID: {thread_id}")
                list_threads_completed.append(thread_id)

        # Remove completed threads from dict
        for thread_id in list_threads_completed:
            self.message_threads.pop(thread_id, None)

        for thread_id in self.message_threads:
            if (not self.message_threads[thread_id]["started"] and
                    threads_running < config.MAX_PROC_THREADS and
                    threads_running < len(self.message_threads)):
                self.message_threads[thread_id]["started"] = True
                self.logger.info("{}: Starting message processing thread".format(
                    thread_id[-config.ID_LENGTH:].upper()))
                self.message_threads[thread_id]["thread"].start()
                threads_running += 1

    def join_chan(self, passphrase, clear_inventory=True):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                result = api.createChan(base64.b64encode(
                    passphrase.encode()).decode())
                self._refresh = True
                if clear_inventory:
                    self.signal_clear_inventory()  # resync inventory to get older messages
                return result
            except Exception as e:
                return repr(e)
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)

    def leave_chan(self, address):
        # Currently bug preventing removal from bitmessage until restart
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                result = api.leaveChan(address)
                self._refresh = True
                return result
            except Exception as e:
                return repr(e)
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)

    def get_api_status(self, return_stored=True):
        if return_stored:
            return self.api_status

        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                with timeout(seconds=5):
                    result = api.add(2, 2)
                    if result == 4:
                        self.api_status = True
                    else:
                        self.api_status = False
            except Exception:
                self.api_status = False
                self.logger.exception("Getting API status")
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)

        return self.api_status

    def trash_message(self, message_id, address=None):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=120):
            try:
                # Add message ID and TTL expiration in database (for inventory wipes)
                expires = get_msg_expires_time(message_id)
                address_from = get_msg_address_from(message_id)
                with session_scope(config.DB_PATH) as new_session:
                    test_del = new_session.query(DeletedMessages).filter(
                        DeletedMessages.message_id == message_id).first()
                    if not test_del:
                        self.logger.info("DeletedMessages table: add {}, {}, {}".format(
                            address, expires, message_id))
                        del_msg = DeletedMessages()
                        del_msg.message_id = message_id
                        del_msg.address_from = address_from
                        if address:  # Leaving board/list
                            del_msg.address_to = address
                        del_msg.expires_time = expires
                        new_session.add(del_msg)
                        new_session.commit()

                return_val = api.trashMessage(message_id)
                return return_val
            except Exception as err:
                self.logger.error("Exception during message delete: {}".format(err))
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)

    def find_senders(self, address, list_send):
        list_senders = []
        access = get_access(address)
        for each_sender in list_send:
            for each_chan in self.get_all_chans():
                if (each_chan in access[each_sender] and
                        each_chan not in access["restricted_addresses"]):
                    list_senders.append(each_chan)
            for each_ident in self.get_identities():
                if (each_ident in access[each_sender] and
                        each_ident not in access["restricted_addresses"]):
                    list_senders.append(each_ident)
        return list_senders

    def expiring_from_expires_time(self, run_id, expire_time):
        """Determine from expires_time if the list is expiring"""
        if not expire_time:
            return
        if expire_time > self.get_utc():
            days = (expire_time - self.get_utc()) / 60 / 60 / 24
            if days < 28 - config.SEND_BEFORE_EXPIRE_DAYS:
                self.logger.info("{}: List expiring in {:.1f} days. Send list.".format(
                    run_id, days))
                return True
            else:
                self.logger.info("{}: List expiring in {:.1f} days. Do nothing.".format(
                    run_id, days))
        else:
            days = (self.get_utc() - expire_time) / 60 / 60 / 24
            self.logger.info("{}: List expired {:.1f} days ago. Send list.".format(
                run_id, days))
            return True

    def expiring_from_timestamp(self, run_id, timestamp):
        """Determine from sent/received timestamp if the list is expiring"""
        if not timestamp:
            return
        days = (self.get_utc() - timestamp) / 60 / 60 / 24
        if days > config.SEND_BEFORE_EXPIRE_DAYS:
            self.logger.info("{}: List might be expiring: {:.1f} days old.".format(
                run_id, days))
            return True
        else:
            self.logger.info("{}: List might not be expiring: {:.1f} days old.".format(
                run_id, days))

    def clear_list_board_contents(self, address):
        with session_scope(config.DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(Chan.address == address).first()
            if chan.type == "list":
                self.logger.info("Wiping List {}".format(chan.address))
                try:
                    list_list = json.loads(chan.list)
                    if list_list:
                        chan.list = "{}"
                        new_session.commit()

                        add_mod_log_entry("Wiping List (Rule)", board_address=address)
                except:
                    pass
            elif chan.type == "board":
                self.logger.info("Wiping Board {}".format(chan.address))
                try:
                    self.delete_all_messages(chan.address)
                except:
                    self.logger.exception("Wiping board")

                add_mod_log_entry("Wiping Board (Rule)", board_address=address)

    def delete_all_messages(self, address):
        with session_scope(config.DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(
                Chan.address == address).first()
            threads = new_session.query(Threads).filter(
                Threads.chan_id == chan.id).all()
            for each_thread in threads:
                messages = new_session.query(Messages).filter(
                    Messages.thread_id == each_thread.id).all()
                for each_message in messages:
                    # Delete post
                    delete_post(each_message.message_id)
                # Delete thread
                new_session.delete(each_thread)
                new_session.commit()
            self.signal_generate_post_numbers()

    def get_address_labels(self):
        address_labels = {}
        list_name_objects = [
            self.get_address_book(),
            self.get_all_chans(),
            self.get_identities()
        ]
        for each_name_repo in list_name_objects:
            for each_address in each_name_repo:
                if "label_short" in each_name_repo[each_address]:
                    address_labels[each_address] = each_name_repo[each_address]["label_short"]
        return address_labels

    def get_chans_board_info(self):
        return self.chans_boards_info

    def generate_chans_board_info(self):
        chans_board_dict = OrderedDict()
        chans = get_db_table_daemon(Chan).filter(
            Chan.type == "board").order_by(func.lower(Chan.label)).all()
        for each_chan in chans:
            if not each_chan.address:
                self.logger.error("Found Board in DB without address: /{}/ - {}".format(
                    each_chan.label, each_chan.description))
                continue
            chans_board_dict[each_chan.address] = {}
            chans_board_dict[each_chan.address]["label"] = replace_lt_gt(each_chan.label)
            chans_board_dict[each_chan.address]["description"] = replace_lt_gt(each_chan.description)
            chans_board_dict[each_chan.address]["rules"] = json.loads(each_chan.rules)

            access = get_access(each_chan.address)
            chans_board_dict[each_chan.address]["primary_addresses"] = access["primary_addresses"]
            chans_board_dict[each_chan.address]["secondary_addresses"] = access["secondary_addresses"]
            chans_board_dict[each_chan.address]["tertiary_addresses"] = access["tertiary_addresses"]
            chans_board_dict[each_chan.address]["restricted_addresses"] = access["restricted_addresses"]

            if len(each_chan.label) > config.LABEL_LENGTH:
                chans_board_dict[each_chan.address]["label_short"] = replace_lt_gt(each_chan.label[:config.LABEL_LENGTH])
            else:
                chans_board_dict[each_chan.address]["label_short"] = replace_lt_gt(each_chan.label)
        self.chans_boards_info = chans_board_dict

    def get_chans_list_info(self):
        chans_list_dict = OrderedDict()
        chans = get_db_table_daemon(Chan).filter(
            Chan.type == "list").order_by(func.lower(Chan.label)).all()
        for each_chan in chans:
            if not each_chan.address:
                self.logger.error("Found List in DB without address: /{}/ - {}".format(
                    each_chan.label, each_chan.description))
                continue
            chans_list_dict[each_chan.address] = {}
            chans_list_dict[each_chan.address]["label"] = replace_lt_gt(each_chan.label)
            chans_list_dict[each_chan.address]["description"] = replace_lt_gt(each_chan.description)
            chans_list_dict[each_chan.address]["rules"] = json.loads(each_chan.rules)
            chans_list_dict[each_chan.address]["primary_addresses"] = json.loads(each_chan.primary_addresses)

            access = get_access(each_chan.address)
            chans_list_dict[each_chan.address]["primary_addresses"] = access["primary_addresses"]
            chans_list_dict[each_chan.address]["secondary_addresses"] = access["secondary_addresses"]
            chans_list_dict[each_chan.address]["tertiary_addresses"] = access["tertiary_addresses"]
            chans_list_dict[each_chan.address]["restricted_addresses"] = access["restricted_addresses"]

            if len(each_chan.label) > config.LABEL_LENGTH:
                chans_list_dict[each_chan.address]["label_short"] = replace_lt_gt(each_chan.label[:config.LABEL_LENGTH])
            else:
                chans_list_dict[each_chan.address]["label_short"] = replace_lt_gt(each_chan.label)
        return chans_list_dict

    def get_from_list(self, address, only_owner_admin=False, all_addresses=False):
        """Generate a list of addresses available for the From address to send with"""
        from_addresses = {}
        anon_post = False

        address_labels = self.get_address_labels()
        all_chans = self.get_all_chans()
        identities = self.get_identities()

        chan = get_db_table_daemon(Chan).filter(
            Chan.address == address).first()
        if chan.type == "board":
            chans_info = self.get_chans_board_info()
        elif chan.type == "list":
            chans_info = self.get_chans_list_info()
        else:
            self.logger.error("Address neither board nor list")
            return

        primary_addresses = chans_info[address]["primary_addresses"]
        secondary_addresses = chans_info[address]["secondary_addresses"]
        tertiary_addresses = chans_info[address]["tertiary_addresses"]
        restricted_addresses = chans_info[address]["restricted_addresses"]
        rules = chans_info[address]["rules"]
        require_identity_to_post = ("require_identity_to_post" in rules and
                                    rules["require_identity_to_post"])

        if (all_addresses or
                (
                    not only_owner_admin and
                    chan.access == "public" and
                    not require_identity_to_post and
                    address not in restricted_addresses
                )):
            anon_post = address
            from_addresses[address] = "Anonymous (this {})".format(chan.type)

        for each_address in identities:
            if each_address in from_addresses:
                continue

            if only_owner_admin and each_address not in primary_addresses + secondary_addresses:
                continue

            if (identities[each_address]['enabled'] and
                    (
                        all_addresses or
                        (
                            (chan.access == "private" and
                             (each_address in primary_addresses or
                              each_address in secondary_addresses or
                              each_address in tertiary_addresses)
                             ) or
                            (chan.access == "public" and
                             each_address not in restricted_addresses)
                        )
                    )):
                if each_address in primary_addresses:
                    from_addresses[each_address] = "[Owner] "
                elif each_address in secondary_addresses:
                    from_addresses[each_address] = "[Admin] "
                elif each_address in tertiary_addresses:
                    from_addresses[each_address] = "[User] "
                else:
                    from_addresses[each_address] = "[Other] "
                from_addresses[each_address] += "Identity: "
                if each_address in address_labels:
                    from_addresses[each_address] += "{} ".format(
                        address_labels[each_address])
                from_addresses[each_address] += "({}...{})".format(
                    each_address[:9], each_address[-6:])

        for each_address in all_chans:
            chan_test = get_db_table_daemon(Chan).filter(Chan.address == each_address).first()
            if not chan_test:
                continue

            if chan_test.unlisted or chan_test.restricted:
                continue  # Do not list unlisted or restricted addresses in the From List

            if each_address in from_addresses:
                continue

            if only_owner_admin and each_address not in primary_addresses + secondary_addresses:
                continue

            if all_chans[each_address]['enabled'] and \
                    (
                        all_addresses or
                        (
                            (chan.access == "private" and
                             (each_address in primary_addresses or
                              each_address in secondary_addresses or
                              each_address in tertiary_addresses)
                             ) or
                            (chan.access == "public" and
                             each_address != address and
                             each_address not in restricted_addresses)
                        )
                    ):
                if each_address in primary_addresses:
                    from_addresses[each_address] = "[Owner] "
                elif each_address in secondary_addresses:
                    from_addresses[each_address] = "[Admin] "
                elif each_address in tertiary_addresses:
                    from_addresses[each_address] = "[User] "
                else:
                    from_addresses[each_address] = "[Other] "

                if chan_test.type == "board":
                    from_addresses[each_address] += "Board: "
                elif chan_test.type == "list":
                    from_addresses[each_address] += "List: "

                if each_address in address_labels:
                    from_addresses[each_address] += "{} ".format(address_labels[each_address])
                from_addresses[each_address] += "({}...{})".format(each_address[:9], each_address[-6:])

        # sort
        owners = {"board": {}, "list": {}, "ident": {}}
        admins = {"board": {}, "list": {}, "ident": {}}
        users = {"board": {}, "list": {}, "ident": {}}
        others = {"board": {}, "list": {}, "ident": {}}

        for each_address in from_addresses:
            if from_addresses[each_address].startswith("[Owner] Board:"):
                owners["board"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[Owner] List:"):
                owners["list"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[Owner] Identity:"):
                owners["ident"][each_address] = from_addresses[each_address]

            elif from_addresses[each_address].startswith("[Admin] Board:"):
                admins["board"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[Admin] List:"):
                admins["list"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[Admin] Identity:"):
                admins["ident"][each_address] = from_addresses[each_address]

            elif from_addresses[each_address].startswith("[User] Board:"):
                users["board"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[User] List:"):
                users["list"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[User] Identity:"):
                users["ident"][each_address] = from_addresses[each_address]

            elif from_addresses[each_address].startswith("[Other] Board:"):
                others["board"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[Other] List:"):
                others["list"][each_address] = from_addresses[each_address]
            elif from_addresses[each_address].startswith("[Other] Identity:"):
                others["ident"][each_address] = from_addresses[each_address]

        owners["board"] = OrderedDict(sorted(owners["board"].items(), key=lambda x: x[1].lower()))
        owners["list"] = OrderedDict(sorted(owners["list"].items(), key=lambda x: x[1].lower()))
        owners["ident"] = OrderedDict(sorted(owners["ident"].items(), key=lambda x: x[1].lower()))

        admins["board"] = OrderedDict(sorted(admins["board"].items(), key=lambda x: x[1].lower()))
        admins["list"] = OrderedDict(sorted(admins["list"].items(), key=lambda x: x[1].lower()))
        admins["ident"] = OrderedDict(sorted(admins["ident"].items(), key=lambda x: x[1].lower()))

        users["board"] = OrderedDict(sorted(users["board"].items(), key=lambda x: x[1].lower()))
        users["list"] = OrderedDict(sorted(users["list"].items(), key=lambda x: x[1].lower()))
        users["ident"] = OrderedDict(sorted(users["ident"].items(), key=lambda x: x[1].lower()))

        others["board"] = OrderedDict(sorted(others["board"].items(), key=lambda x: x[1].lower()))
        others["list"] = OrderedDict(sorted(others["list"].items(), key=lambda x: x[1].lower()))
        others["ident"] = OrderedDict(sorted(others["ident"].items(), key=lambda x: x[1].lower()))

        combined_dict = OrderedDict()
        if anon_post:
            combined_dict.update({anon_post: from_addresses[anon_post]})
        combined_dict.update(owners["board"])
        combined_dict.update(owners["list"])
        combined_dict.update(owners["ident"])
        combined_dict.update(admins["board"])
        combined_dict.update(admins["list"])
        combined_dict.update(admins["ident"])
        combined_dict.update(users["board"])
        combined_dict.update(users["list"])
        combined_dict.update(users["ident"])
        combined_dict.update(others["board"])
        combined_dict.update(others["list"])
        combined_dict.update(others["ident"])

        return combined_dict

    def process_message(self, msg_dict):
        """Parse a message to determine if it is valid"""
        try:
            if len(msg_dict) == 0:
                self.logger.error("{}: message is empty".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                return

            admin_store = get_db_table_daemon(AdminMessageStore).filter(
                AdminMessageStore.message_id == msg_dict["msgid"]).first()
            if admin_store and not self.bm_sync_complete:
                self.logger.info(
                    "{}: Stored message ID detected. "
                    "Skipping processing of admin command until synced".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                return

            message_post = get_db_table_daemon(Messages).filter(
                Messages.message_id == msg_dict["msgid"]).first()
            if message_post and message_post.thread and message_post.thread.chan:
                self.logger.info("{}: Adding message from database to chan {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                    message_post.thread.chan.address))
                return

            # Decode message
            message = base64.b64decode(msg_dict['message']).decode()

            # Check if message is an encrypted PGP message
            if not message.startswith("-----BEGIN PGP MESSAGE-----"):
                self.logger.info("{}: Message doesn't appear to be PGP message. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

            pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
            with session_scope(config.DB_PATH) as new_session:
                chan = new_session.query(Chan).filter(
                    Chan.address == msg_dict['toAddress']).first()
                if chan and chan.pgp_passphrase_msg:
                    pgp_passphrase_msg = chan.pgp_passphrase_msg

            # Decrypt the message
            # Protect against explosive PGP message size exploit
            msg_decrypted = decrypt_safe_size(message, pgp_passphrase_msg, 400000)

            if msg_decrypted is not None:
                self.logger.info("{}: Message decrypted".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                try:
                    msg_decrypted_dict = json.loads(msg_decrypted)
                except:
                    self.logger.info(
                        "{}: Malformed JSON payload. Deleting.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    self.trash_message(msg_dict["msgid"])
                    return
            else:
                self.logger.info(
                    "{}: Could not decrypt message. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

            if "version" not in msg_decrypted_dict:
                self.logger.error("{}: 'version' not found in message. Deleting.")
                self.trash_message(msg_dict["msgid"])
                return

            ver_diff_msg_ver = version_checker(config.VERSION_MSG, msg_decrypted_dict["version"])
            ver_diff_min_ver = version_checker(msg_decrypted_dict["version"], config.VERSION_MIN_MSG)
            if ver_diff_msg_ver[0] == "Error":
                self.logger.error(
                    f"Error comparing message version ({msg_decrypted_dict['version']}): {ver_diff_msg_ver[1]}")
            elif ver_diff_msg_ver[1] == "less":
                self.logger.info("{}: Message version greater than BitChan version ({} > {}). Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                    msg_decrypted_dict["version"],
                    config.VERSION_MSG))
                self.trash_message(msg_dict["msgid"])
                with session_scope(config.DB_PATH) as new_session:
                    settings = new_session.query(GlobalSettings).first()
                    settings.messages_newer += 1
                    new_session.commit()
                return
            elif ver_diff_min_ver[0] == "Error":
                self.logger.error(f"Error comparing min message version: {ver_diff_min_ver[1]}")
            elif ver_diff_min_ver[1] == "less":
                self.logger.info("{}: Message version too old ({} < {}). Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                    msg_decrypted_dict["version"],
                    config.VERSION_MSG))
                self.trash_message(msg_dict["msgid"])
                with session_scope(config.DB_PATH) as new_session:
                    settings = new_session.query(GlobalSettings).first()
                    settings.messages_older += 1
                    new_session.commit()
                return
            else:
                with session_scope(config.DB_PATH) as new_session:
                    settings = new_session.query(GlobalSettings).first()
                    settings.messages_current += 1
                    new_session.commit()

            # Check if a previous request to delete a post with a password has been made, compare hashes
            delete_post_hash_check = new_session.query(PostDeletePasswordHashes).filter(
                PostDeletePasswordHashes.message_id == msg_dict["msgid"]).first()
            if (delete_post_hash_check and
                    "thread_hash" in msg_decrypted_dict and msg_decrypted_dict["thread_hash"] and
                    "delete_password_hash" in msg_decrypted_dict and msg_decrypted_dict["delete_password_hash"] and
                    delete_post_hash_check.password_hash == msg_decrypted_dict["delete_password_hash"]):
                self.logger.info("{}: Message received that matches password hash to delete post. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                add_mod_log_entry(
                    "Post deleted with password",
                    message_id=msg_dict["msgid"],
                    user_from=msg_dict["fromAddress"],
                    board_address=msg_dict["toAddress"],
                    thread_hash=msg_decrypted_dict["thread_hash"])
                return

            #
            # Determine the message type
            #
            if "message_type" not in msg_decrypted_dict:
                self.logger.info(
                    "{}: 'message_type' missing from message. "
                    "Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
            elif msg_decrypted_dict["message_type"] == "admin":
                with session_scope(config.DB_PATH) as new_session:
                    admin_store = new_session.query(AdminMessageStore).filter(
                        AdminMessageStore.message_id == msg_dict["msgid"]).first()
                    if not self.bm_sync_complete:
                        # Add to admin message store DB to indicate to skip processing if not synced
                        if not admin_store:
                            new_store = AdminMessageStore()
                            new_store.message_id = msg_dict["msgid"]
                            new_store.time_added = datetime.datetime.now()
                            new_session.add(new_store)
                            new_session.commit()
                        self.logger.info("{}: Skipping processing of admin command until synced".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    else:
                        # delete stored admin message ID and process admin command
                        if admin_store:
                            new_session.delete(admin_store)
                        process_admin(msg_dict, msg_decrypted_dict)
            elif msg_decrypted_dict["message_type"] == "post_delete_password":
                self.process_post_delete_password(msg_dict, msg_decrypted_dict)
            elif msg_decrypted_dict["message_type"] == "post":
                self.process_post(msg_dict, msg_decrypted_dict)
            elif msg_decrypted_dict["message_type"] == "game":
                self.process_game(msg_dict, msg_decrypted_dict)
            elif msg_decrypted_dict["message_type"] == "list":
                self.process_list(msg_dict, msg_decrypted_dict)
            else:
                self.logger.error("{}: Unknown message type: {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                    msg_decrypted_dict["message_type"]))
        except Exception as e:
            self.logger.exception("{}: process_message() error: {}".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), e))

    def process_post_delete_password(self, msg_dict, msg_decrypted_dict):
        """Process message as a request to delete post"""
        self.logger.info("{}: Message is a request to delete a post".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))

        if "message_id" not in msg_decrypted_dict or not msg_decrypted_dict["message_id"]:
            self.logger.error(
                "{}: No message ID. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            self.trash_message(msg_dict["msgid"])
            return

        if "thread_hash" not in msg_decrypted_dict or not msg_decrypted_dict["thread_hash"]:
            self.logger.error(
                "{}: No thread hash. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            self.trash_message(msg_dict["msgid"])
            return

        if "delete_password" not in msg_decrypted_dict or not msg_decrypted_dict["delete_password"]:
            self.logger.error(
                "{}: No password. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            self.trash_message(msg_dict["msgid"])
            return

        if "timestamp_utc" not in msg_decrypted_dict or not msg_decrypted_dict["timestamp_utc"]:
            self.logger.error(
                "{}: No timestamp. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            self.trash_message(msg_dict["msgid"])
            return

        if "timestamp_utc" in msg_decrypted_dict and msg_decrypted_dict["timestamp_utc"]:
            if msg_decrypted_dict["timestamp_utc"] > time.time() + (60 * 60 * 24):
                self.logger.error(
                    "{}: Timestamp too far in the future. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return
            elif msg_decrypted_dict["timestamp_utc"] < time.time() - (60 * 60 * 24 * 30):
                self.logger.error(
                    "{}: Timestamp too far in the past. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

        try:
            hashed_password = hashlib.sha512(msg_decrypted_dict["delete_password"].encode('utf-8')).hexdigest()

            with session_scope(config.DB_PATH) as new_session:
                create_hash_entry = True
                message = new_session.query(Messages).filter(
                    Messages.message_id == msg_decrypted_dict["message_id"]).first()
                if message:
                    if hashed_password == message.delete_password_hash:
                        settings = new_session.query(GlobalSettings).first()
                        if settings.remote_delete_action == "hide":
                            hide = True
                        else:
                            hide = False
                        self.logger.info(
                            f"{msg_dict['msgid'][-config.ID_LENGTH:].upper()}: Hashes match to delete post (hide={hide}).")
                        add_mod_log_entry(
                            f"Delete post with password (hide={hide})",
                            message_id=msg_decrypted_dict["message_id"],
                            user_from=msg_dict["fromAddress"],
                            board_address=msg_dict["toAddress"],
                            thread_hash=msg_decrypted_dict["thread_hash"])
                        delete_post(msg_decrypted_dict["message_id"], only_hide=hide)
                    else:
                        create_hash_entry = False
                        self.logger.error(
                            "{}: Hashes don't match. Not deleting post.".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        add_mod_log_entry(
                            "Invalid password to delete post with password",
                            message_id=msg_decrypted_dict["message_id"],
                            user_from=msg_dict["fromAddress"],
                            board_address=msg_dict["toAddress"],
                            thread_hash=msg_decrypted_dict["thread_hash"],
                            success=False)

                if create_hash_entry:
                    hash_entry = new_session.query(PostDeletePasswordHashes).filter(
                        PostDeletePasswordHashes.message_id == msg_decrypted_dict["message_id"]).first()
                    if not hash_entry:
                        new_hash = PostDeletePasswordHashes()
                        new_hash.message_id = msg_decrypted_dict["message_id"]
                        new_hash.password_hash = hashed_password
                        new_hash.address_from = msg_dict["fromAddress"]
                        new_hash.address_to = msg_dict["toAddress"]
                        new_hash.timestamp_utc = msg_decrypted_dict["timestamp_utc"]
                        new_session.add(new_hash)
                        new_session.commit()
        except Exception as err:
            self.logger.error("{}: Could not process post delete with password: {}".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), err))

        self.trash_message(msg_dict["msgid"])

    # TODO: Move to shared functions file
    def is_public_board_require_identity(self, msg_id, to_address, from_address):
        # Determine if board is public and requires an Identity to post
        chan = get_db_table_daemon(Chan).filter(and_(
            Chan.access == "public",
            Chan.type == "board",
            Chan.address == to_address)).first()
        if chan:
            try:
                rules = json.loads(chan.rules)
            except:
                rules = {}
            if ("require_identity_to_post" in rules and
                    rules["require_identity_to_post"] and
                    to_address == from_address):
                # From address is not different from board address
                self.logger.info(
                    "{}: Message is from its own board's address {} but "
                    "requires a non-board address to post. "
                    "Deleting.".format(
                        msg_id[-config.ID_LENGTH:].upper(),
                        from_address))
                self.trash_message(msg_id)
                return True

    def is_ban_in_place(self, msg_id, to_address, from_address):
        # Determine if there is a current ban in place for an address
        # If so, delete message and don't process it
        admin_bans = get_db_table_daemon(Command).filter(and_(
            or_(Command.action == "board_ban_silent", Command.action == "board_ban_public"),
            Command.action_type == "ban_address",
            Command.chan_address == to_address)).all()
        for each_ban in admin_bans:
            try:
                options = json.loads(each_ban.options)
            except:
                options = {}
            if ("ban_address" in options and
                    options["ban_address"] == from_address and
                    from_address not in self.get_identities()):
                # If there is a ban and the banned user isn't yourself, delete post
                self.logger.info(
                    "{}: Message is from address {} that's banned from "
                    "board {}. Deleting.".format(
                        msg_id[-config.ID_LENGTH:].upper(),
                        from_address,
                        to_address))
                self.trash_message(msg_id)
                return True

    def is_block_in_place(self, msg_id, to_address, from_address):
        # Determine if there is a current block in place for an address
        # If so, delete message and don't process it
        # Note: only affects your local system, not other users
        with session_scope(config.DB_PATH) as new_session:
            blocks = new_session.query(Command).filter(and_(
                Command.action == "block",
                Command.do_not_send.is_(True),
                Command.action_type == "block_address",
                or_(Command.chan_address == to_address,
                    Command.chan_address == "all"))).all()
            for each_block in blocks:
                try:
                    options = json.loads(each_block.options)
                except:
                    options = {}
                if ("block_address" in options and
                        options["block_address"] == from_address and
                        each_block.chan_address in [to_address, "all"] and
                        from_address not in self.get_identities()):
                    # If there is a block and the blocked user isn't yourself, delete post
                    self.logger.info(
                        "{}: Message is from address {} that's blocked from "
                        "board {}. Deleting.".format(
                            msg_id[-config.ID_LENGTH:].upper(),
                            from_address,
                            to_address))
                    self.trash_message(msg_id)
                    return True

    def is_sender_restricted(self, msg_id, to_address, from_address):
        # Determine if board is public and the sender is restricted from posting
        with session_scope(config.DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(and_(
                Chan.access == "public",
                Chan.type == "board",
                Chan.address == to_address)).first()
            if chan:
                # Check if sender in restricted list
                access = get_access(to_address)
                if from_address in access["restricted_addresses"]:
                    self.logger.info(
                        "{}: Post from restricted sender: {}. Deleting.".format(
                            msg_id[-config.ID_LENGTH:].upper(),
                            from_address))
                    self.trash_message(msg_id)
                    return True
                else:
                    self.logger.info("{}: Post from unrestricted sender: {}".format(
                        msg_id[-config.ID_LENGTH:].upper(),
                        from_address))

    def is_sender_not_allowed_to_send(self, msg_id, to_address, from_address):
        # Determine if board is private and the sender is allowed to send to the board
        with session_scope(config.DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(and_(
                Chan.access == "private",
                Chan.type == "board",
                Chan.address == to_address)).first()
            if chan:
                errors, dict_info = process_passphrase(chan.passphrase)
                # Sender must be in at least one address list
                access = get_access(to_address)
                if (from_address not in
                        access["primary_addresses"] +
                        access["secondary_addresses"] +
                        access["tertiary_addresses"]):
                    self.logger.info(
                        "{}: Post from unauthorized sender: {}. Deleting.".format(
                            msg_id[-config.ID_LENGTH:].upper(),
                            from_address))
                    self.trash_message(msg_id)
                    return True
                else:
                    self.logger.info("{}: Post from authorized sender: {}".format(
                        msg_id[-config.ID_LENGTH:].upper(),
                        from_address))

    def process_post(self, msg_dict, msg_decrypted_dict):
        """Process message as a post to a board"""
        self.logger.info("{}: Message is a post".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))

        not_allow_post = self.is_public_board_require_identity(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_ban_in_place(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_block_in_place(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_sender_restricted(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_sender_not_allowed_to_send(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        # Delete message if sent timestamp is too far in the future or the past
        if "timestamp_utc" in msg_decrypted_dict and msg_decrypted_dict["timestamp_utc"]:
            if msg_decrypted_dict["timestamp_utc"] > self.get_utc() + (60 * 60 * 3):  # 3 hours in the future
                self.logger.error(
                    "{}: Timestamp too far in the future. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return
            elif msg_decrypted_dict["timestamp_utc"] < self.get_utc() - (60 * 60 * 24 * 29):  # 29 days in the past
                self.logger.error(
                    "{}: Timestamp too far in the past. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

        # Pre-processing checks passed. Continue processing message.
        with session_scope(config.DB_PATH) as new_session:
            if msg_decrypted_dict["message"]:
                # Remove any potentially malicious HTML in received message text
                # before saving it to the database or presenting it to the user
                msg_decrypted_dict["message"] = html.escape(msg_decrypted_dict["message"])

                # perform admin command word replacements
                try:
                    admin_cmd = new_session.query(Command).filter(and_(
                        Command.chan_address == msg_dict['toAddress'],
                        Command.action == "set",
                        Command.action_type == "options")).first()
                    if admin_cmd and admin_cmd.options:
                        try:
                            options = json.loads(admin_cmd.options)
                        except:
                            options = {}
                        if "word_replace" in options:
                            msg_decrypted_dict["message"] = replace_dict_keys_with_values(
                                msg_decrypted_dict["message"], options["word_replace"])
                except Exception as err:
                    self.logger.error("Could not complete admin command word "
                                      "replacements: {}".format(err))

            msg_dict['message_decrypted'] = msg_decrypted_dict

            #
            # Save message to database
            #
            message = new_session.query(Messages).filter(
                Messages.message_id == msg_dict["msgid"]).first()
            if not message:
                self.logger.info(
                    "{}: Message not in DB. Start processing.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                return_obj = parse_message(msg_dict["msgid"], msg_dict)
                self.logger.info(f"Return type from parse_message(): {type(return_obj)}")
                if (type(return_obj) is dict and
                        "process_op_json_obj" in return_obj and
                        "orig_op_bm_json_obj" in return_obj):
                    self.logger.info("Detected OP in received reply")
                    test_del = new_session.query(DeletedMessages).filter(
                        DeletedMessages.message_id == return_obj["orig_op_bm_json_obj"]["msgid"]).first()
                    if test_del:
                        self.logger.info("Message ID of OP has previously been deleted. Not healing OP.")
                    else:
                        # Parse OP of thread that appears to currently be missing
                        self.logger.info("Allowing OP to be processed")
                        parse_message(return_obj["orig_op_bm_json_obj"]["msgid"],
                                      return_obj["orig_op_bm_json_obj"])

        # Check if message was created by parse_message()
        with session_scope(config.DB_PATH) as new_session:
            message = new_session.query(Messages).filter(
                Messages.message_id == msg_dict["msgid"]).first()
            if not message:
                self.logger.error("{}: 1: Message not created. Don't create post object.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return
            elif not message.thread or not message.thread.chan:
                # Chan or thread doesn't exist, delete thread and message
                if message.thread:
                    new_session.delete(message.thread)
                if message:
                    new_session.delete(message)
                new_session.commit()
                self.logger.error("{}: Thread or board doesn't exist. Deleting DB entries.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

            self.logger.info("{}: Adding to {} ({})".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                message.thread.chan.address,
                message.thread.chan.label))

    def process_game(self, msg_dict, msg_decrypted_dict):
        """Process message as a game to a thread"""
        self.logger.info("{}: Message is a game".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))

        not_allow_post = self.is_public_board_require_identity(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_ban_in_place(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_block_in_place(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_sender_restricted(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        not_allow_post = self.is_sender_not_allowed_to_send(
            msg_dict["msgid"], msg_dict['toAddress'], msg_dict['fromAddress'])
        if not_allow_post:
            self.trash_message(msg_dict["msgid"])
            return

        if ("game" not in msg_decrypted_dict or
                "game_hash" not in msg_decrypted_dict or
                "game_over" not in msg_decrypted_dict or
                "game_moves" not in msg_decrypted_dict or
                "game_termination_pw_hash" not in msg_decrypted_dict or
                "thread_hash" not in msg_decrypted_dict or
                "message" not in msg_decrypted_dict or
                "message_extra" not in msg_decrypted_dict):
            self.logger.error("Malformed game post. Deleting")
            self.trash_message(msg_dict["msgid"])
            return

        # Pre-processing checks passed. Continue processing message.
        with session_scope(config.DB_PATH) as new_session:
            if msg_decrypted_dict["message"]:
                # Remove any potentially malicious HTML in received message text
                # before saving it to the database or presenting it to the user
                msg_decrypted_dict["message"] = '<span class="god-text">{}</span>'.format(
                    html.escape(msg_decrypted_dict["message"]))
                msg_decrypted_dict["message"] = msg_decrypted_dict["message"].replace("\n", "<br/>")

            if "message_extra" in msg_decrypted_dict and msg_decrypted_dict["message_extra"]:
                # Remove any potentially malicious HTML in received message text
                # before saving it to the database or presenting it to the user
                msg_decrypted_dict["message_extra"] = '<span style="font-size: 1.1em; font-family: \'Lucida Console\', Monaco, monospace;">{}</span>'.format(
                    html.escape(msg_decrypted_dict["message_extra"]))
                msg_decrypted_dict["message_extra"] = msg_decrypted_dict["message_extra"].replace("\n", "<br/>")

            #
            # Save message to database
            #
            message = new_session.query(Messages).filter(
                Messages.message_id == msg_dict["msgid"]).first()
            if not message:
                try:
                    # Create game entry if it doesn't exist
                    test_game = new_session.query(Games).filter(
                        Games.game_hash == msg_decrypted_dict["game_hash"]).first()
                    if (not test_game and
                            ("thread_hash" in msg_decrypted_dict and msg_decrypted_dict["thread_hash"]) and
                            ("game_hash" in msg_decrypted_dict and msg_decrypted_dict["game_hash"])):
                        self.logger.info("Game not found. I'm not hosting. Creating game.")
                        new_game = Games()
                        new_game.game_hash = msg_decrypted_dict["game_hash"]
                        new_game.thread_hash = msg_decrypted_dict["thread_hash"]
                        if "game_over" in msg_decrypted_dict:
                            new_game.game_over = msg_decrypted_dict["game_over"]
                        new_game.is_host = False
                        new_game.game_type = msg_decrypted_dict["game"]
                        if msg_decrypted_dict["game_termination_pw_hash"]:
                            new_game.game_termination_pw_hash = msg_decrypted_dict["game_termination_pw_hash"]
                        new_session.add(new_game)
                    if (test_game and
                            ("thread_hash" in msg_decrypted_dict and msg_decrypted_dict["thread_hash"]) and
                            ("game_hash" in msg_decrypted_dict and msg_decrypted_dict["game_hash"]) and
                            ("game_over" in msg_decrypted_dict)):
                        self.logger.info("Game found. Updating game_over status to {}.".format(
                            msg_decrypted_dict["game_over"]))
                        test_game.game_over = msg_decrypted_dict["game_over"]
                        new_session.commit()

                    test_game = new_session.query(Games).filter(
                        Games.game_hash == msg_decrypted_dict["game_hash"]).first()
                    if test_game:
                        self.logger.info("Game found. Make game post.")
                    else:
                        self.logger.info("Game not found. Not making game post.")
                        self.trash_message(msg_dict["msgid"])
                        return

                    if "thread_hash" in msg_decrypted_dict and msg_decrypted_dict["thread_hash"]:
                        thread = new_session.query(Threads).filter(
                            Threads.thread_hash == msg_decrypted_dict["thread_hash"]).first()
                        if not thread:
                            self.logger.info("Thread not found. Not making game post.")
                            self.trash_message(msg_dict["msgid"])
                            return
                    else:
                        self.logger.info("thread_hash not found. Not making game post.")
                        self.trash_message(msg_dict["msgid"])
                        return

                    if not thread.chan:
                        self.logger.info("Chan not found. Not making game post.")
                        self.trash_message(msg_dict["msgid"])
                        return

                    if ("timestamp_utc" in msg_decrypted_dict and msg_decrypted_dict["timestamp_utc"] and
                            (isinstance(msg_decrypted_dict["timestamp_utc"], int) or
                             isinstance(msg_decrypted_dict["timestamp_utc"], float))):
                        timestamp_sent = int(msg_decrypted_dict["timestamp_utc"])
                    else:
                        timestamp_sent = int(msg_dict['receivedTime'])

                    # Create message
                    new_msg = Messages()
                    new_msg.version = msg_decrypted_dict["version"]
                    new_msg.message_id = msg_dict["msgid"]
                    new_msg.post_id = get_post_id(msg_dict["msgid"])
                    new_msg.post_number = thread.chan.last_post_number
                    new_msg.message_sha256_hash = hashlib.sha256(
                        json.dumps(msg_dict['message']).encode('utf-8')).hexdigest()
                    new_msg.thread_id = thread.id
                    new_msg.address_from = bleach.clean(msg_dict['fromAddress'])
                    new_msg.is_op = False
                    new_msg.message = msg_decrypted_dict["message"]
                    new_msg.timestamp_sent = timestamp_sent
                    new_msg.timestamp_received = int(msg_dict['receivedTime'])
                    new_msg.message_original = msg_dict["message"]
                    new_msg.game_message_extra = msg_decrypted_dict["message_extra"]

                    if ("game_moves" in msg_decrypted_dict and
                            msg_decrypted_dict["game_moves"] is not None and
                            msg_decrypted_dict["game"] == "chess"):
                        # Generate SVG board
                        import chess
                        import chess.svg
                        board = chess.Board()
                        for move in msg_decrypted_dict["game_moves"]:
                            board.push_san(move)
                        new_msg.game_image_file = chess.svg.board(board, size=500)
                        new_msg.game_image_name = "chess_board.svg"
                        new_msg.game_image_extension = "svg"

                    new_session.add(new_msg)

                    if int(msg_dict['receivedTime']) > thread.chan.timestamp_received:
                        thread.chan.timestamp_received = int(msg_dict['receivedTime'])

                    # regenerate card
                    card_test = new_session.query(PostCards).filter(
                        PostCards.thread_id == thread.id).first()
                    if card_test and not card_test.regenerate:
                        card_test.regenerate = True

                    new_session.commit()

                    # Delete message from Bitmessage after parsing and adding to BitChan database
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=120):
                        try:
                            with timeout(seconds=5):
                                return_val = api.trashMessage(msg_dict["msgid"])
                        except Exception as err:
                            self.logger.error("{}: Exception during message delete: {}".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper(), err))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)

                except Exception as err:
                    self.logger.error(
                        "{}: Could not write to database. Deleting. Error: {}".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(), err))
                    self.logger.exception("Saving message to DB")
                    self.trash_message(msg_dict["msgid"])
                finally:
                    time.sleep(config.API_PAUSE)

            # Check if message was created by parse_message()
            message = new_session.query(Messages).filter(
                Messages.message_id == msg_dict["msgid"]).first()
            if not message:
                self.logger.error("{}: 2: Message not created. Don't create post object.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return
            elif not message.thread or not message.thread.chan:
                # Chan or thread doesn't exist, delete thread and message
                if message.thread:
                    new_session.delete(message.thread)
                if message:
                    new_session.delete(message)
                new_session.commit()
                self.logger.error("{}: Thread or board doesn't exist. Deleting DB entries.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

            self.logger.info("{}: Adding game post to {} ({})".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                message.thread.chan.address,
                message.thread.chan.label))

    def process_list(self, msg_dict, msg_decrypted_dict):
        """Process message as a list"""
        self.logger.info("{}: Message is a list".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))

        # Check integrity of message
        required_keys = ["version", "timestamp_utc", "access", "list"]
        integrity_pass = True
        mod_log_description = ""

        with session_scope(config.DB_PATH) as new_session:
            list_chan = new_session.query(Chan).filter(and_(
                Chan.type == "list",
                Chan.address == msg_dict['toAddress'])).first()

            if not list_chan:
                return

            try:
                rules = json.loads(list_chan.rules)
            except:
                rules = {}

            for each_key in required_keys:
                if each_key not in msg_decrypted_dict:
                    self.logger.error("{}: List message missing '{}'".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), each_key))
                    integrity_pass = False

            for each_chan in msg_decrypted_dict["list"]:
                if "passphrase" not in msg_decrypted_dict["list"][each_chan]:
                    self.logger.error("{}: Entry in list missing 'passphrase'".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    integrity_pass = False
                    continue

                errors, dict_info = process_passphrase(
                    msg_decrypted_dict["list"][each_chan]["passphrase"])
                if not dict_info or errors:
                    self.logger.error("{}: List passphrase did not pass integrity check: {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                        msg_decrypted_dict["list"][each_chan]["passphrase"]))
                    for err in errors:
                        self.logger.error(err)
                    integrity_pass = False

                if "allow_list_pgp_metadata" in rules and rules["allow_list_pgp_metadata"]:
                    if ("pgp_passphrase_msg" in msg_decrypted_dict["list"][each_chan] and
                            len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_msg"]) > config.PGP_PASSPHRASE_LENGTH):
                        self.logger.error("{}: Message PGP Passphrase longer than {}: {}".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                            config.PGP_PASSPHRASE_LENGTH,
                            len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_msg"])))
                        integrity_pass = False

                    if ("pgp_passphrase_attach" in msg_decrypted_dict["list"][each_chan] and
                            len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_attach"]) > config.PGP_PASSPHRASE_LENGTH):
                        self.logger.error("{}: Attachment PGP Passphrase longer than {}: {}".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                            config.PGP_PASSPHRASE_LENGTH,
                            len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_attach"])))
                        integrity_pass = False

                    if ("pgp_passphrase_steg" in msg_decrypted_dict["list"][each_chan] and
                            len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_steg"]) > config.PGP_PASSPHRASE_LENGTH):
                        self.logger.error("{}: Steg PGP Passphrase longer than {}: {}".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                            config.PGP_PASSPHRASE_LENGTH,
                            len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_steg"])))
                        integrity_pass = False

            if not integrity_pass:
                self.logger.error("{}: List message failed integrity test: {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_decrypted_dict))
                self.trash_message(msg_dict["msgid"])
                return

            if msg_decrypted_dict["timestamp_utc"] - (60 * 60 * 3) > self.get_utc():
                # message timestamp is in the distant future. Delete.
                self.logger.info("{}: List message has future timestamp. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

            log_age_and_expiration(
                msg_dict["msgid"],
                self.get_utc(),
                msg_decrypted_dict["timestamp_utc"],
                get_msg_expires_time(msg_dict["msgid"]))

            if (msg_decrypted_dict["timestamp_utc"] < self.get_utc() and
                    ((self.get_utc() - msg_decrypted_dict["timestamp_utc"]) / 60 / 60 / 24) > 28):
                # message timestamp is too old. Delete.
                self.logger.info("{}: List message is supposedly older than 28 days. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                self.trash_message(msg_dict["msgid"])
                return

            # Check if board is set to automatically clear and message is older than the last clearing
            if chan_auto_clears_and_message_too_old(
                    msg_dict['toAddress'], msg_decrypted_dict["timestamp_utc"]):
                self.logger.info("{}: Message sent before auto wipe for {}. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
                self.trash_message(msg_dict["msgid"])
                return

            self.logger.info("{}: List message passed integrity test".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))

            # Check if sending address is in primary or secondary address list
            access = get_access(msg_dict['toAddress'])
            sender_is_primary = False
            sender_is_secondary = False
            sender_is_tertiary = False
            sender_is_restricted = False
            if msg_dict['fromAddress'] in access["primary_addresses"]:
                sender_is_primary = True
            if msg_dict['fromAddress'] in access["secondary_addresses"]:
                sender_is_secondary = True
            if msg_dict['fromAddress'] in access["tertiary_addresses"]:
                sender_is_tertiary = True
            if msg_dict['fromAddress'] in access["restricted_addresses"]:
                sender_is_restricted = True

            # Check if address restricted
            if list_chan.access == "public" and sender_is_restricted:
                self.logger.info("{}: List from restricted sender: {}. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))
                self.trash_message(msg_dict["msgid"])
                return

            # Check if rule prevents sending from own address
            if ("require_identity_to_post" in rules and
                    rules["require_identity_to_post"] and
                    msg_dict['toAddress'] == msg_dict['fromAddress']):
                # From address is not different from list address
                self.logger.info(
                    "{}: List is from its own address {} but requires a "
                    "non-list address to post. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))
                self.trash_message(msg_dict["msgid"])
                return

            if list_chan.access == "public":

                if sender_is_primary or sender_is_secondary:
                    # store latest list timestamp from primary/secondary addresses
                    if (list_chan.list_message_timestamp_utc_owner and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_owner):
                        # message timestamp is older than what's in the database
                        self.logger.info(
                            "{}: Owner/Admin of public list message older than DB timestamp. Deleting.".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        self.trash_message(msg_dict["msgid"])
                        return
                    else:
                        self.logger.info(
                            "{}: Owner/Admin of public list message newer than DB timestamp. Updating.".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        list_chan.list_message_id_owner = msg_dict["msgid"]
                        list_chan.list_message_expires_time_owner = get_msg_expires_time(msg_dict["msgid"])
                        list_chan.list_message_timestamp_utc_owner = msg_decrypted_dict["timestamp_utc"]

                        # Set user times to those of owner
                        if (
                                (not list_chan.list_message_expires_time_user or
                                 (list_chan.list_message_expires_time_user and
                                  list_chan.list_message_expires_time_owner and
                                  list_chan.list_message_expires_time_owner > list_chan.list_message_expires_time_user))
                                or
                                (not list_chan.list_message_timestamp_utc_user or
                                 (list_chan.list_message_timestamp_utc_user and
                                  list_chan.list_message_timestamp_utc_owner and
                                  list_chan.list_message_timestamp_utc_owner > list_chan.list_message_timestamp_utc_user))
                        ):
                            self.logger.info("{}: Setting user timestamp/expires_time to that of Owner/Admin.".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                            list_chan.list_message_id_user = msg_dict["msgid"]
                            list_chan.list_message_expires_time_user = get_msg_expires_time(msg_dict["msgid"])
                            list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                    self.logger.info(
                        "{}: List {} is public and From address {} "
                        "in primary or secondary access list. Replacing entire list.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'],
                            msg_dict['fromAddress']))

                    # Set the time the list changed
                    if list_chan.list != json.dumps(msg_decrypted_dict["list"]):
                        list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                        # Add what addresses were added and/or removed to the mod log
                        addresses_removed, addresses_added = diff_list_added_removed(
                            list(json.loads(list_chan.list).keys()),
                            list(msg_decrypted_dict["list"].keys()))
                        mod_log_list = []
                        if addresses_removed:
                            mod_log_list.append("Removed: {}".format(", ".join(addresses_removed)))
                        if addresses_added:
                            mod_log_list.append("Added: {}".format(", ".join(addresses_added)))
                        mod_log_description = "; ".join(mod_log_list)

                    list_chan.list = json.dumps(msg_decrypted_dict["list"])
                else:
                    # store latest list timestamp from tertiary addresses
                    if (list_chan.list_message_timestamp_utc_user and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_user):
                        # message timestamp is older than what's in the database
                        self.logger.info("{}: User list message older than DB timestamp. Deleting.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        self.trash_message(msg_dict["msgid"])
                        return
                    else:
                        self.logger.info("{}: User list message newer than DB timestamp. Updating.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        list_chan.list_message_id_user = msg_dict["msgid"]
                        list_chan.list_message_expires_time_user = get_msg_expires_time(msg_dict["msgid"])
                        list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                    try:
                        dict_chan_list = json.loads(list_chan.list)
                    except:
                        dict_chan_list = {}
                    self.logger.info("{}: List {} is public, adding addresses to list".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
                    mod_log_addresses_added = []
                    for each_address in msg_decrypted_dict["list"]:
                        if each_address not in dict_chan_list:
                            self.logger.info("{}: Adding {} to list".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                                each_address))
                            dict_chan_list[each_address] = msg_decrypted_dict["list"][each_address]
                            mod_log_addresses_added.append(each_address)
                        else:
                            self.logger.info("{}: {} already in list".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                                each_address))

                    # Set the time the list changed
                    if list_chan.list != json.dumps(dict_chan_list):
                        list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                        # Log the additions
                        mod_log_description = "Added: {}".format(", ".join(mod_log_addresses_added))

                    list_chan.list = json.dumps(dict_chan_list)

                new_session.commit()

            elif list_chan.access == "private":
                # Check if private list by checking if any identities match From address
                if not sender_is_primary and not sender_is_secondary and not sender_is_tertiary:
                    self.logger.error(
                        "{}: List {} is private but {} not in primary, secondary, or tertiary access list".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'],
                            msg_dict['fromAddress']))

                elif sender_is_primary or sender_is_secondary:
                    # store latest list timestamp from primary/secondary addresses
                    if (list_chan.list_message_timestamp_utc_owner and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_owner):
                        # message timestamp is older than what's in the database
                        self.logger.info(
                            "{}: Owner/Admin of private list message older than DB timestamp. Deleting.".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        self.trash_message(msg_dict["msgid"])
                        return
                    else:
                        self.logger.info(
                            "{}: Owner/Admin of private list message newer than DB timestamp. Updating.".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        list_chan.list_message_id_owner = msg_dict["msgid"]
                        list_chan.list_message_expires_time_owner = get_msg_expires_time(msg_dict["msgid"])
                        list_chan.list_message_timestamp_utc_owner = msg_decrypted_dict["timestamp_utc"]

                    self.logger.info(
                        "{}: List {} is private and From address {} "
                        "in primary or secondary access list. Replacing entire list.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'],
                            msg_dict['fromAddress']))
                    list_chan = new_session.query(Chan).filter(
                        Chan.address == msg_dict['toAddress']).first()

                    # Set the time the list changed
                    if list_chan.list != json.dumps(msg_decrypted_dict["list"]):
                        list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                        # Add what addresses were added and/or removed to the mod log
                        addresses_removed, addresses_added = diff_list_added_removed(
                            list(json.loads(list_chan.list).keys()),
                            list(msg_decrypted_dict["list"].keys()))
                        mod_log_list = []
                        if addresses_removed:
                            mod_log_list.append("Removed: {}".format(", ".join(addresses_removed)))
                        if addresses_added:
                            mod_log_list.append("Added: {}".format(", ".join(addresses_added)))
                        mod_log_description = "; ".join(mod_log_list)

                    list_chan.list = json.dumps(msg_decrypted_dict["list"])

                elif sender_is_tertiary:
                    # store latest list timestamp from tertiary addresses
                    if (list_chan.list_message_timestamp_utc_user and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_user):
                        # message timestamp is older than what's in the database
                        self.logger.info("{}: User list message older than DB timestamp. Deleting.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        self.trash_message(msg_dict["msgid"])
                        return
                    else:
                        self.logger.info("{}: User list message newer than DB timestamp. Updating.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        list_chan.list_message_id_user = msg_dict["msgid"]
                        list_chan.list_message_expires_time_user = get_msg_expires_time(msg_dict["msgid"])
                        list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                    self.logger.info(
                        "{}: List {} is private and From address {} "
                        "in tertiary access list. Adding addresses to list.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'],
                            msg_dict['fromAddress']))
                    try:
                        dict_chan_list = json.loads(list_chan.list)
                    except:
                        dict_chan_list = {}
                    mod_log_addresses_added = []
                    for each_address in msg_decrypted_dict["list"]:
                        if each_address not in dict_chan_list:
                            self.logger.info("{}: Adding {} to list".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                                each_address))
                            dict_chan_list[each_address] = msg_decrypted_dict["list"][each_address]
                            mod_log_addresses_added.append(each_address)
                        else:
                            self.logger.info("{}: {} already in list".format(
                                msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                                each_address))

                    # Set the time the list changed
                    if list_chan.list != json.dumps(dict_chan_list):
                        list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                        # Log the additions
                        mod_log_description = "Added: {}".format(", ".join(mod_log_addresses_added))

                    list_chan.list = json.dumps(dict_chan_list)

                new_session.commit()

            if mod_log_description:
                add_mod_log_entry(
                    mod_log_description,
                    user_from=msg_dict['fromAddress'],
                    board_address=msg_dict['toAddress'])

        self.trash_message(msg_dict["msgid"])

    def bulk_join(self, list_address, join_bulk_list):
        bulk_join_run = Thread(
            target=self.bulk_join_thread, args=(list_address, join_bulk_list,))
        bulk_join_run.daemon = True
        bulk_join_run.start()

    def bulk_join_thread(self, list_address_origin, join_list):
        chan_list = get_db_table_daemon(Chan).filter(and_(
            Chan.type == "list",
            Chan.address == list_address_origin)).first()
        try:
            dict_list_addresses = json.loads(chan_list.list)
        except:
            self.logger.error("Could not find list address")
            return

        for each_join_address in join_list:
            try:
                rules = json.loads(chan_list.rules)
            except:
                rules = {}

            if each_join_address not in dict_list_addresses:
                self.logger.error("Address to join not in list: {}".format(each_join_address))
                continue

            dict_chan_info = {}
            passphrase = ""
            if "passphrase" in dict_list_addresses[each_join_address]:
                passphrase = dict_list_addresses[each_join_address]["passphrase"]

                if get_db_table_daemon(Chan).filter(Chan.passphrase == passphrase).count():
                    self.logger.error("Chan already in database")
                    continue

                errors, dict_chan_info = process_passphrase(passphrase)
                if not dict_chan_info:
                    self.logger.error("Error parsing passphrase")
                    for error in errors:
                        self.logger.error(error)
                    continue

                if "%" in passphrase:  # TODO: Remove check when Bitmessage fixes this issue
                    self.logger.error('Chan passphrase cannot contain: "%"')
                    continue

            pgp_passphrase_msg = None
            pgp_passphrase_steg = None
            pgp_passphrase_attach = None
            if (rules and 'allow_list_pgp_metadata' in rules and
                    'pgp_passphrase_msg' in dict_list_addresses[each_join_address] and
                    dict_list_addresses[each_join_address]['pgp_passphrase_msg']):
                pgp_passphrase_msg = dict_list_addresses[each_join_address]['pgp_passphrase_msg']
            if (rules and 'allow_list_pgp_metadata' in rules and
                    'pgp_passphrase_steg' in dict_list_addresses[each_join_address] and
                    dict_list_addresses[each_join_address]['pgp_passphrase_steg']):
                pgp_passphrase_steg = dict_list_addresses[each_join_address]['pgp_passphrase_steg']
            if (rules and 'allow_list_pgp_metadata' in rules and
                    'pgp_passphrase_attach' in dict_list_addresses[each_join_address] and
                    dict_list_addresses[each_join_address]['pgp_passphrase_attach']):
                pgp_passphrase_attach = dict_list_addresses[each_join_address]['pgp_passphrase_attach']

            try:
                with session_scope(config.DB_PATH) as new_session:
                    if dict_chan_info["rules"]:
                        dict_chan_info["rules"] = set_clear_time_to_future(dict_chan_info["rules"])

                    new_chan = Chan()
                    new_chan.passphrase = passphrase
                    new_chan.access = dict_chan_info["access"]
                    new_chan.type = dict_chan_info["type"]
                    new_chan.primary_addresses = json.dumps(dict_chan_info["primary_addresses"])
                    new_chan.secondary_addresses = json.dumps(dict_chan_info["secondary_addresses"])
                    new_chan.tertiary_addresses = json.dumps(dict_chan_info["tertiary_addresses"])
                    new_chan.rules = json.dumps(dict_chan_info["rules"])
                    new_chan.label = dict_chan_info["label"]
                    new_chan.description = dict_chan_info["description"]

                    if pgp_passphrase_msg:
                        new_chan.pgp_passphrase_msg = pgp_passphrase_msg
                    else:
                        new_chan.pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                    if new_chan.type == "board":
                        if pgp_passphrase_steg:
                            new_chan.pgp_passphrase_steg = pgp_passphrase_steg
                        else:
                            new_chan.pgp_passphrase_steg = config.PGP_PASSPHRASE_STEG
                        if pgp_passphrase_attach:
                            new_chan.pgp_passphrase_attach = pgp_passphrase_attach
                        else:
                            new_chan.pgp_passphrase_attach = config.PGP_PASSPHRASE_ATTACH

                    result = self.join_chan(passphrase)
                    if result and result.startswith("BM-"):
                        new_chan.address = result
                        new_chan.is_setup = True

                        log_description = None
                        if new_chan.type == "board":
                            log_description = "Joined Board {}".format(result)
                        elif new_chan.type == "list":
                            log_description = "Joined List {}".format(result)
                        if log_description:
                            add_mod_log_entry(log_description, board_address=result)
                    else:
                        self.logger.info("Could not join at this time: {}".format(result))
                        new_chan.address = None
                        new_chan.is_setup = False
                    new_session.add(new_chan)
                    new_session.commit()
            except:
                self.logger.exception("Could not join {}".format(each_join_address))
                continue

            time.sleep(1)

    def clear_bm_inventory(self):
        try:
            self.is_restarting_bitmessage = True
            self.bitmessage_stop()
            time.sleep(20)

            self.logger.info("Deleting Bitmessage inventory")

            conn = sqlite3.connect('file:{}'.format(config.BM_MESSAGES_DAT), uri=True)
            c = conn.cursor()
            c.execute('DELETE FROM inventory')
            conn.commit()
            conn.close()

            self.bitmessage_start()
            time.sleep(20)
        finally:
            self.is_restarting_bitmessage = False

    def combine_bm_knownnodes(self, knownnodes_list):
        dict_nodes_all = {}
        dict_nodes_1d = {}
        dict_nodes_7d = {}
        dict_nodes_15d = {}
        dict_nodes_30d = {}
        duplicates = 0
        file = None

        list_dicts_nodes = [
            (dict_nodes_1d, "1d", 60 * 60 * 24),
            (dict_nodes_7d, "7d", 60 * 60 * 24 * 7),
            (dict_nodes_15d, "15d", 60 * 60 * 24 * 15),
            (dict_nodes_30d, "30d", 60 * 60 * 24 * 30)
        ]

        try:
            self.is_restarting_bitmessage = True
            self.bitmessage_stop()

            # Get owner/group before modification
            try:
                uid = pwd.getpwnam("bitchan").pw_uid
                gid = grp.getgrnam("bitchan").gr_gid
            except:
                try:
                    uid = os.stat(config.BM_KEYS_DAT).st_uid
                    gid = os.stat(config.BM_KEYS_DAT).st_gid
                except:
                    uid = None
                    gid = None

            file = open(config.BM_KNOWNNODES_DAT, mode='r')
            knownnodes_bm = json.loads(file.read())
            knownnodes_list += knownnodes_bm

            self.logger.info(f"Nodes in current knownnodes.dat: {len(knownnodes_bm)}")
            self.logger.info(f"Nodes in submitted knownnodes.dat: {len(knownnodes_list)}")

            for each_node in knownnodes_list:
                add = False
                if not each_node['info']['self'] and each_node['peer']['host'] not in dict_nodes_all:
                    add = True
                elif not each_node['info']['self']:
                    if each_node['info']['lastseen'] > dict_nodes_all[each_node['peer']['host']]["lastseen"]:
                        add = True
                    duplicates += 1
                    # print(f"Duplicate host: {each_node['peer']['host']}")
                if add:
                    dict_nodes_all[each_node['peer']['host']] = {
                        "port": each_node['peer']['port'],
                        "rating": each_node['info']['rating'],
                        "lastseen": each_node['info']['lastseen'],
                        "stream": each_node['stream']
                    }

            self.logger.info(f"Unique nodes: {len(dict_nodes_all)}")
            self.logger.info(f"Duplicate nodes: {duplicates}")

            now = time.time()
            for each_set in list_dicts_nodes:
                self.logger.info(f"Creating list of {each_set[1]}")
                for host, data in dict_nodes_all.items():
                    max_age = each_set[2]
                    if host not in each_set[0] and now - data["lastseen"] < max_age:
                        each_set[0][host] = {
                            "port": data['port'],
                            "rating": data['rating'],
                            "lastseen": data['lastseen'],
                            "stream": data['stream']
                        }
                self.logger.info(f"Nodes: {len(each_set[0])}")

            try:
                os.remove(config.BM_KNOWNNODES_DAT)
            except:
                pass

            with open(config.BM_KNOWNNODES_DAT, "a") as file:
                file.write('[\n')
                for i, (host, node) in enumerate(dict_nodes_30d.items()):
                    file.write('    {\n')
                    file.write('        "peer": {\n')
                    file.write(f'            "host": "{host}",\n')
                    file.write(f'            "port": {node["port"]}\n')
                    file.write('        },\n')
                    file.write('        "info": {\n')
                    file.write(f'            "rating": {node["rating"]:.1f},\n')
                    file.write(f'            "self": false,\n')
                    file.write(f'            "lastseen": {node["lastseen"]}\n')
                    file.write('        },\n')
                    file.write(f'        "stream": {node["stream"]}\n')
                    if i < len(dict_nodes_30d) - 1:
                        file.write('    },\n')
                    else:
                        file.write('    }\n')
                file.write(']\n')

            # Set owner/group after modification
            if uid and pwd:
                os.chown(config.BM_KNOWNNODES_DAT, uid, gid)

            self.bitmessage_start()
        except Exception as err:
            self.logger.exception(f"Error: {err}")
        finally:
            if file:
                file.close()
            self.is_restarting_bitmessage = False

    def is_pow_sending(self):
        doing_pow = False
        try:
            conn = sqlite3.connect('file:{}'.format(config.BM_MESSAGES_DAT), uri=True)
            conn.text_factory = lambda x: str(x, 'latin1')
            c = conn.cursor()
            c.execute("SELECT * "
                      "FROM sent "
                      "WHERE folder='sent' "
                      "AND status='doingmsgpow'")
            row = c.fetchone()
            if row:
                doing_pow = True
                self.timer_safe_send = time.time() + 15
            conn.commit()
            conn.close()
        except Exception as err:
            self.logger.exception("Error checking for POW: {}".format(err))
        finally:
            return doing_pow

    def delete_and_vacuum(self):
        self.logger.debug("Deleting Bitmessage Trash items")
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
            try:
                api.deleteAndVacuum()
            except Exception as err:
                self.logger.error("delete_and_vacuum() error: {}".format(err))
            finally:
                time.sleep(config.API_PAUSE)
                lf.lock_release(config.LOCKFILE_API)

    def signal_clear_inventory(self):
        self.logger.info("Signaling deletion of Bitmessage inventory in {} minutes".format(
            config.CLEAR_INVENTORY_WAIT / 60))
        self.timer_clear_inventory = time.time() + config.CLEAR_INVENTORY_WAIT
        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            if settings:
                settings.clear_inventory = True
                new_session.commit()

    def bitmessage_monitor(self):
        """Monitor bitmessage and restart it if its API is unresponsive"""
        self.get_api_status(return_stored=False)
        if not self.api_status:
            self.restart_bitmessage()

    def update_utc_offset(self):
        ntp = ntplib.NTPClient()
        for _ in range(3):
            try:
                ntp_utc = ntp.request('pool.ntp.org').tx_time
                self.utc_offset = time.time() - ntp_utc
                self.logger.info("NTP UTC: {}, Offset saved: {}".format(
                    ntp_utc, self.utc_offset))
                break
            except ntplib.NTPException as err:
                self.logger.error("Error NTPException: {}".format(err))
            except Exception as err:
                self.logger.exception("Error update_utc_offset(): {}".format(err))
            time.sleep(60)

    def restart_bitmessage(self):
        """Restart bitmessage"""
        try:
            if self.is_restarting_bitmessage:
                self.logger.info("Already restarting bitmessage. Please wait.")
            else:
                self.is_restarting_bitmessage = True
                self.bitmessage_stop()
                time.sleep(15)
                self.bitmessage_start()
                time.sleep(15)
        finally:
            self.is_restarting_bitmessage = False

    def bitmessage_stop(self):
        try:
            self.logger.info("Stopping bitmessage. Please wait.")
            if config.DOCKER:
                cmd = 'docker stop -t 15 bitchan_bitmessage 2>&1'
            else:
                cmd = 'service bitchan_bitmessage stop'
            self.logger.info(f"Stop command: {cmd}")
            subprocess.Popen(cmd, shell=True)
            time.sleep(20)
        except Exception as err:
            self.logger.error("Exception stopping Bitmessage: {}".format(err))

    def bitmessage_start(self):
        try:
            self.logger.info("Starting bitmessage. Please wait.")
            if config.DOCKER:
                cmd = 'docker start bitchan_bitmessage 2>&1'
            else:
                cmd = 'service bitchan_bitmessage start'
            self.logger.info(f"Start command: {cmd}")
            subprocess.Popen(cmd, shell=True)
            time.sleep(15)
        except Exception as err:
            self.logger.error("Exception starting Bitmessage: {}".format(err))

    def get_sent_items(self):
        sent_items = []

        try:
            conn = sqlite3.connect('file:{}'.format(config.BM_MESSAGES_DAT), uri=True)
            conn.text_factory = bytes
            c = conn.cursor()
            c.execute("SELECT fromaddress, status, folder, msgid FROM sent")
            rows = c.fetchall()
            conn.commit()
            conn.close()

            for each_row in rows:
                try:
                    from_address = each_row[0]
                    status = each_row[1]
                    folder = each_row[2]
                    msgid = hexlify(each_row[3])
                    sent_items.append({
                        'from_address': from_address.decode(),
                        'folder': folder.decode(),
                        'status': status.decode(),
                        'msgid': msgid.decode()
                    })
                except:
                    self.logger.exception("Getting sent items")
        except:
            self.logger.exception("querying messages.dat")
        finally:
            return sent_items

    def delete_msgs(self):
        self.logger.debug("Checking sent box for messages to be deleted")
        list_pow = []
        list_sent = []

        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            list_addresses_ident = list(self._identity_dict.keys())

            sent_items = self.get_sent_items()
            self.logger.debug("Sent items: {}".format(sent_items))
            for each_sent in sent_items:
                if (each_sent['folder'] == 'sent' and
                        each_sent["status"] not in ["doingmsgpow", "msgqueued"] and
                        each_sent['status'] in ["msgsentnoackexpected", "ackreceived"]):

                    if ((settings.delete_sent_identity_msgs and each_sent['from_address'] in list_addresses_ident) or
                            each_sent['from_address'] not in list_addresses_ident):
                        self.logger.debug("Deleting sent msg from {}, msgid {}".format(
                            each_sent['from_address'], each_sent["msgid"]))
                        with timeout(seconds=5):
                            self.logger.debug(api.trashSentMessage(each_sent["msgid"]))

            sent_items = self.get_sent_items()
            for each_sent in sent_items:
                if each_sent['folder'] == "sent":
                    if each_sent["status"] == "doingmsgpow":
                        list_pow.append(list_pow)
                    else:
                        list_sent.append(list_sent)
            self.logger.debug(
                "Sent messages remaining: POW finished: {}, doing POW: {}".format(
                    len(list_sent), len(list_pow)))

    def new_tor_identity(self):
        try:
            with Controller.from_port(address=config.TOR_HOST,
                                      port=config.TOR_CONTROL_PORT) as controller:
                controller.authenticate(password=config.TOR_PASS)
                controller.signal(Signal.NEWNYM)
                self.logger.info("New tor identity requested")
        except Exception as err:
            self.logger.info("Error getting new tor identity: {}".format(err))

    def bitmessage_restarting(self):
        return self.is_restarting_bitmessage

    def get_utc(self):
        if self.utc_offset:
            return int(time.time() + self.utc_offset)
        else:
            return int(time.time())

    def is_utc_offset_set(self):
        return bool(self.utc_offset)

    def get_address_book(self):
        return self._address_book_dict

    def get_all_chans(self):
        return self._all_chans

    def get_bm_sync_complete(self):
        return self.bm_sync_complete

    def get_identities(self):
        return self._identity_dict

    def get_last_post_ts(self):
        return self.last_post_ts

    def get_subscriptions(self):
        return self._subscription_dict

    @staticmethod
    def get_start_download():
        list_message_ids = []
        with session_scope(config.DB_PATH) as new_session:
            messages = new_session.query(Messages).filter(
                Messages.start_download.is_(True)).all()
            for each_message in messages:
                list_message_ids.append(each_message.message_id)
        return list_message_ids

    def get_timer_clear_inventory(self):
        return self.timer_clear_inventory

    def get_view_counter(self):
        return self.view_counter

    def refresh_address_book(self):
        self._refresh_address_book = True
        self._refresh = True

    def refresh_identities(self):
        self._refresh_identities = True
        self._refresh = True

    @staticmethod
    def remove_start_download(message_id):
        with session_scope(config.DB_PATH) as new_session:
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if message:
                message.start_download = False
                new_session.commit()

    def shutdown_daemon(self):
        self.logger.info("Daemon instructed to shut down.")
        self.running = False

    def set_last_post_ts(self, ts):
        self.last_post_ts = ts

    def set_start_download(self, message_id):
        self.logger.info("{}: Allowing file to be downloaded".format(
            message_id[-config.ID_LENGTH:].upper()))
        with session_scope(config.DB_PATH) as new_session:
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if message:
                message.start_download = True
                new_session.commit()

    def set_view_counter(self, key, endpoint, value=None, increment=None):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_ENDPOINT_COUNTER, to=10):
            try:
                if key not in self.view_counter:
                    self.view_counter[key] = {}
                if endpoint not in self.view_counter[key]:
                    self.view_counter[key][endpoint] = 0

                if increment:
                    self.view_counter[key][endpoint] += 1
                elif value:
                    self.view_counter[key][endpoint] = value
            except Exception as err:
                self.logger.error("Error set_view_counter(): {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_ENDPOINT_COUNTER)

    def tor_enable_custom_address(self):
        self.logger.info("Enabling custom onion address")
        time.sleep(5)
        enable_custom_address(True)
        self.logger.info("Restarting tor")
        if config.DOCKER:
            subprocess.Popen(
                'docker stop -t 15 bitchan_tor 2>&1 && sleep 10 && docker start bitchan_tor 2>&1', shell=True)
        else:
            subprocess.Popen('service bitchan_tor restart', shell=True)

    def tor_disable_custom_address(self):
        self.logger.info("Disabling custom onion address")
        enable_custom_address(False)

    def tor_enable_random_address(self):
        self.logger.info("Enabling random onion address")
        enable_random_address(True)

    def tor_disable_random_address(self):
        self.logger.info("Disabling random onion address")
        enable_random_address(False)

    def tor_get_new_random_address(self):
        self.logger.info("Getting new random onion address")
        enable_random_address(True)
        self.logger.info("Deleting current random onion priv/pub/hostname files")
        delete_file(f"{config.TOR_HS_RAND}/hostname")
        delete_file(f"{config.TOR_HS_RAND}/hs_ed25519_public_key")
        delete_file(f"{config.TOR_HS_RAND}/hs_ed25519_secret_key")

    def tor_restart(self):
        self.logger.info("Restarting tor")
        time.sleep(20)
        if config.DOCKER:
            subprocess.Popen(
                'docker stop -t 15 bitchan_tor 2>&1 && sleep 10 && docker start bitchan_tor 2>&1', shell=True)
        else:
            subprocess.Popen('service bitchan_tor restart', shell=True)

    def update_timer_clear_inventory(self, seconds):
        self.timer_clear_inventory = time.time() + seconds

    def update_timer_send_lists(self, seconds):
        self.timer_send_lists = time.time() + seconds


@expose
class Pyros(object):
    def __init__(self, bc):
        self.logger = logging.getLogger('bitchan.pyros')
        self.bitchan = bc

    def bitmessage_restarting(self):
        return self.bitchan.bitmessage_restarting()

    def bm_sync_complete(self):
        return self.bitchan.get_bm_sync_complete()

    def bm_change_connection_settings(self):
        return self.bitchan.bm_change_connection_settings()

    def bulk_join(self, list_address, join_bulk_list):
        return self.bitchan.bulk_join(list_address, join_bulk_list)

    def clear_bm_inventory(self):
        return self.bitchan.clear_bm_inventory()

    def combine_bm_knownnodes(self, knownnodes_list):
        return self.bitchan.combine_bm_knownnodes(knownnodes_list)

    def delete_and_vacuum(self):
        return self.bitchan.delete_and_vacuum()

    def enable_onion_services_only(self, enable=False):
        return self.bitchan.enable_onion_services_only(enable=enable)

    def generate_post_numbers(self, all_boards=False):
        return self.bitchan.generate_post_numbers(all_boards=all_boards)

    def get_address_book(self):
        return self.bitchan.get_address_book()

    def get_address_labels(self):
        return self.bitchan.get_address_labels()

    def get_all_chans(self):
        return self.bitchan.get_all_chans()

    def get_api_status(self, return_stored=True):
        return self.bitchan.get_api_status(return_stored=return_stored)

    def get_bm_sync_complete(self):
        return self.bitchan.get_bm_sync_complete()

    def get_chans_board_info(self):
        return self.bitchan.get_chans_board_info()

    def get_chans_list_info(self):
        return self.bitchan.get_chans_list_info()

    def get_from_list(self, chan_address, only_owner_admin=False, all_addresses=False):
        return self.bitchan.get_from_list(
            chan_address, only_owner_admin=only_owner_admin, all_addresses=all_addresses)

    def get_identities(self):
        return self.bitchan.get_identities()

    def get_last_post_ts(self):
        return self.bitchan.get_last_post_ts()

    def get_start_download(self):
        return self.bitchan.get_start_download()

    def get_subscriptions(self):
        return self.bitchan.get_subscriptions()

    def get_timer_clear_inventory(self):
        return self.bitchan.get_timer_clear_inventory()

    def get_utc(self):
        return self.bitchan.get_utc()

    def get_view_counter(self):
        return self.bitchan.get_view_counter()

    def join_chan(self, passphrase, clear_inventory=False):
        return self.bitchan.join_chan(passphrase, clear_inventory=clear_inventory)

    def leave_chan(self, chan_address):
        return self.bitchan.leave_chan(chan_address)

    def refresh_address_book(self):
        return self.bitchan.refresh_address_book()

    def refresh_identities(self):
        return self.bitchan.refresh_identities()

    def refresh_settings(self):
        return self.bitchan.refresh_settings()

    def regenerate_bitmessage_onion_address(self):
        return self.bitchan.regenerate_bitmessage_onion_address()

    def remove_start_download(self, message_id):
        return self.bitchan.remove_start_download(message_id)

    def restart_bitmessage(self):
        new_thread = Thread(target=self.bitchan.restart_bitmessage)
        new_thread.daemon = True
        new_thread.start()

    def shutdown_daemon(self):
        return self.bitchan.shutdown_daemon()

    def set_last_post_ts(self, ts):
        return self.bitchan.set_last_post_ts(ts)

    def set_start_download(self, message_id):
        return self.bitchan.set_start_download(message_id)

    def set_view_counter(self, key, endpoint, value=None, increment=None):
        return self.bitchan.set_view_counter(key, endpoint, value=value, increment=increment)

    def update_unread_mail_count(self, ident_address):
        return self.bitchan.update_unread_mail_count(ident_address)

    def signal_clear_inventory(self):
        return self.bitchan.signal_clear_inventory()

    def signal_generate_post_numbers(self):
        return self.bitchan.signal_generate_post_numbers()

    def tor_enable_custom_address(self):
        tor_thread = Thread(target=self.bitchan.tor_enable_custom_address)
        tor_thread.daemon = True
        tor_thread.start()

    def tor_disable_custom_address(self):
        return self.bitchan.tor_disable_custom_address()

    def tor_enable_random_address(self):
        return self.bitchan.tor_enable_random_address()

    def tor_disable_random_address(self):
        return self.bitchan.tor_disable_random_address()

    def tor_get_new_random_address(self):
        return self.bitchan.tor_get_new_random_address()

    def tor_restart(self):
        tor_thread = Thread(target=self.bitchan.tor_restart)
        tor_thread.daemon = True
        tor_thread.start()

    def trash_message(self, message_id):
        return self.bitchan.trash_message(message_id)

    def update_timer_clear_inventory(self, seconds):
        return self.bitchan.update_timer_clear_inventory(seconds)

    def update_timer_send_lists(self, seconds):
        return self.bitchan.update_timer_send_lists(seconds)


class Pyrod(threading.Thread):
    def __init__(self, bc):
        threading.Thread.__init__(self)
        self.logger = logging.getLogger('bitchan.pyrod')
        self.bitchan = bc

    def run(self):
        try:
            self.logger.info("Starting Pyro5 daemon")
            serve({
                Pyros(self.bitchan): 'bitchan.pyro_server',
            }, host=config.DAEMON_BIND_IP, port=9099, use_ns=False)
        except Exception as err:
            self.logger.exception("ERROR: Pyrod: {msg}".format(msg=err))


class Daemon:
    def __init__(self, bc):
        self.logger = logging.getLogger('bitchan.daemon_run')
        self.bitchan = bc

    def start_daemon(self):
        try:
            pd = Pyrod(self.bitchan)
            pd.daemon = True
            pd.start()
            self.bitchan.run()
        except Exception:
            self.logger.exception("Daemon Error")


if __name__ == '__main__':
    if not os.geteuid() == 0:
        sys.exit("Run as root")

    bitchan = BitChan()
    daemon = Daemon(bitchan)

    if config.DOCKER:
        logging.basicConfig(
            level=config.LOG_LEVEL,
            format="[%(asctime)s] %(levelname)s/%(name)s: %(message)s",
            handlers=[
                handlers.RotatingFileHandler(
                    config.LOG_BACKEND_FILE, mode='a', maxBytes=1024 * 1024 * 30,
                    backupCount=3, encoding=None, delay=False
                ),
                logging.StreamHandler()
            ]
        )

        daemon.start_daemon()
    else:
        logger = logging.getLogger('bitchan')
        logger.setLevel(config.LOG_LEVEL)
        fh = logging.FileHandler(config.LOG_BACKEND_FILE, 'a')
        fh.setLevel(config.LOG_LEVEL)
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s/%(name)s: %(message)s")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        keep_fds = [fh.stream.fileno()]

        bc_daemon = Daemonize(
            app="bitchan_daemon",
            pid=config.PATH_DAEMON_PID,
            action=daemon.start_daemon,
            keep_fds=keep_fds)
        bc_daemon.start()
