import base64
import json
import logging
import random
import socket
import sqlite3
import subprocess
import time
import xmlrpc.client
from collections import OrderedDict
from operator import getitem
from threading import Thread

import gnupg
import ntplib
from sqlalchemy import and_
from stem import Signal
from stem.control import Controller

import config
from chan_objects import ChanBoard
from chan_objects import ChanPost
from database.models import AddressBook
from database.models import Chan
from database.models import DeletedMessages
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import PostMessages
from database.models import Threads
from database.models import UploadProgress
from database.utils import db_return
from database.utils import session_scope
from utils.files import LF
from utils.files import delete_message_files
from utils.gateway import get_access
from utils.gateway import get_bitmessage_endpoint
from utils.gateway import get_msg_address_from
from utils.general import get_random_alphanumeric_string
from utils.general import process_passphrase
from utils.message_admin_command import send_commands
from utils.message_processing import process_message
from utils.replacements import replace_lt_gt
from utils.shared import get_msg_expires_time

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.bm_gateway')


class BitChan(Thread):
    def __init__(self):
        super(BitChan, self).__init__()
        self._non_bitchan_message_ids = []
        self._posts_by_id = {}
        self._all_chans = {}
        self._board_by_chan = {}
        self._list_by_chan = {}
        self._address_book_dict = {}
        self._identity_dict = {}
        self._chan_list_dict = {}
        self._chan_board_dict = {}
        self._subscription_dict = {}
        self._refresh = True
        self._refresh_identities = False
        self._refresh_address_book = True
        self._api = xmlrpc.client.ServerProxy(get_bitmessage_endpoint())
        socket.setdefaulttimeout(config.API_TIMEOUT)

        self.list_start_download = []
        self.message_threads = {}
        self.max_threads = 8
        self.utc_offset = None
        self.time_last = 0
        self.is_restarting_bitmessage = False
        self.list_stats = []
        self.first_run = True
        self.update_ntp = False

        # Bitmessage sync check
        self.bm_connected = False
        self.bm_connected_timer = None
        self.bm_sync_complete = False
        self.bm_pending_download = True
        self.bm_pending_download_timer = None

        # Timers
        self.timer_check_bm_alive = time.time()
        self.timer_time_server = time.time()
        self.timer_sync = time.time()
        self.timer_bm_update = time.time()
        self.timer_clear_inventory = time.time()
        self.timer_message_threads = time.time()
        self.timer_clear_uploads = time.time()
        self.timer_unread_mail = time.time()
        self.timer_non_bitchan_message_ids = time.time()
        self.timer_safe_send = time.time()
        self.timer_new_tor_identity = time.time() + random.randint(1200, 7200)
        self.timer_delete_identity_msgs = time.time() + (60 * 10)  # 10 minutes
        self.timer_get_msg_expires_time = time.time() + (60 * 10)  # 10 minutes
        self.timer_remove_deleted_msgs = time.time() + (60 * 10)   # 10 minutes
        self.timer_send_lists = time.time() + (60 * 5)             # 5 minutes
        self.timer_send_commands = time.time() + (60 * 5)          # 5 minutes

        # Net disable settings
        self.allow_net_file_size_check = False
        self.allow_net_ntp = False

        self.refresh_settings()

        bm_monitor = Thread(target=self.bitmessage_monitor)
        bm_monitor.daemon = True
        bm_monitor.start()

    def refresh_settings(self):
        with session_scope(DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            try:
                self._non_bitchan_message_ids = json.loads(settings.discard_message_ids)
            except:
                self._non_bitchan_message_ids = "[]"
            self.allow_net_file_size_check = settings.allow_net_file_size_check
            self.allow_net_ntp = settings.allow_net_ntp

    def run(self):
        while True:
            lf = LF()
            if (not self.is_restarting_bitmessage and
                    lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=120)):
                try:
                   self.run_periodic()
                finally:
                    lf.lock_release(config.LOCKFILE_MSG_PROC)
            time.sleep(1)

    def run_periodic(self):
        now = time.time()

        #
        # Update the time
        #
        if self.allow_net_ntp:
            self.update_ntp = False
            if abs(self.time_last - now) > 600:
                logger.info("Time changed? Update NTP.")
                self.update_ntp = True
            self.time_last = now

            if self.timer_time_server < now or self.update_ntp:
                while self.timer_time_server < now:
                    self.timer_time_server += (60 * 6 * random.randint(40, 70))
                ntp = Thread(target=self.update_utc_offset)
                ntp.daemon = True
                ntp.start()

        #
        # Check if sync complete
        #
        if self.timer_sync < now or self.update_ntp:
            while self.timer_sync < now:
                self.timer_sync += config.BM_SYNC_CHECK_PERIOD
            try:
                self.check_sync()
            except:
                logger.exception("Could not complete check_sync()")

        #
        # New tor Identity
        #
        if self.timer_new_tor_identity < now:
            while self.timer_new_tor_identity < now:
                self.timer_new_tor_identity += random.randint(1200, 7200)
            try:
                self.new_tor_identity()
            except:
                logger.exception("Could not complete check_sync()")

        #
        # Update addresses and messages periodically
        #
        if self.timer_bm_update < now or self._refresh:
            while self.timer_bm_update < now:
                self.timer_bm_update += config.BM_REFRESH_PERIOD
            self._refresh = False
            try:
                # logger.info("Updating bitmessage info")
                timer = time.time()
                self._update_identities()
                # self.update_subscriptions()  # Currently not used
                self.update_address_book()
                self.update_chans()
                self.queue_new_messages()
                list_stats = [
                    len(self._posts_by_id),
                    len(self._chan_board_dict),
                    len(self._chan_list_dict),
                    len(self._identity_dict),
                    len(self._address_book_dict)
                ]
                if self.list_stats != list_stats:
                    msg = str(len(self._posts_by_id))
                    msg += " post, " if len(self._posts_by_id) == 1 else " posts, "
                    msg += str(len(self._chan_board_dict))
                    msg += " board, " if len(self._chan_board_dict) == 1 else " boards, "
                    msg += str(len(self._chan_list_dict))
                    msg += " list, " if len(self._chan_list_dict) == 1 else " lists, "
                    msg += str(len(self._identity_dict))
                    msg += " identity, " if len(self._identity_dict) == 1 else " identities, "
                    msg += str(len(self._address_book_dict))
                    msg += " address book entry" if len(self._address_book_dict) == 1 else " address book entries"
                    logger.info(msg)
                    # logger.info("updated in {:.1f} sec".format(time.time() - timer))
                    self.list_stats = list_stats
            except Exception:
                logger.exception("Updating bitchan")

        #
        # Update message thread queue
        #
        if self.timer_message_threads < now:
            while self.timer_message_threads < now:
                self.timer_message_threads += 1
            try:
                self.check_message_threads()
            except:
                logger.exception("Could not complete check_message_threads()")

        #
        # Clear upload progress table
        #
        if self.timer_clear_uploads < now:
            while self.timer_clear_uploads < now:
                self.timer_clear_uploads += 600
            with session_scope(DB_PATH) as new_session:
                if self.first_run:
                    upl = new_session.query(UploadProgress).all()
                else:
                    upl = new_session.query(UploadProgress).filter(and_(
                        UploadProgress.progress_percent == 100,
                        UploadProgress.uploading == False
                        )).all()
                for each_upl in upl:
                    new_session.delete(each_upl)

        #
        # Clear inventory 10 minutes after last board/list join
        #
        if self.timer_clear_inventory < now:
            with session_scope(DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                if settings and settings.clear_inventory:
                    self.is_pow_sending()
                    if self.timer_safe_send < now:  # Ensure we don't restart BM while sending
                        settings.clear_inventory = False
                        new_session.commit()
                        try:
                            self.clear_bm_inventory()
                        except:
                            logger.exception("Could not complete clear_bm_inventory()")

        #
        # Get message expires time if not currently set
        #
        if self.timer_get_msg_expires_time < now:
            while self.timer_get_msg_expires_time < now:
                self.timer_get_msg_expires_time += (60 * 10)  # 10 minutes
            try:
                self.get_message_expires_times()
            except:
                logger.exception("Could not complete get_message_expires_times()")

        #
        # Delete non-composed identity messages from sent box
        #
        if self.timer_delete_identity_msgs < now:
            while self.timer_delete_identity_msgs < now:
                self.timer_delete_identity_msgs += (60 * 10)  # 10 minutes
            try:
                self.delete_identity_msgs()
            except:
                logger.exception("Could not complete delete_identity_msgs()")

        #
        # Delete entries in deleted message database 1 day after they expire
        #
        if self.timer_remove_deleted_msgs < now:
            while self.timer_remove_deleted_msgs < now:
                self.timer_remove_deleted_msgs += (60 * 60 * 24)  # 1 day
            try:
                logger.info("Checking for expired message entries")
                with session_scope(DB_PATH) as new_session:
                    expired = time.time() - (24 * 60 * 60)  # 1 day in the past (expired yesterday)
                    for each_msg in new_session.query(DeletedMessages).all():
                        if each_msg.expires_time and expired and each_msg.expires_time < expired:
                            logger.info("DeletedMessages table: delete: {}, {}".format(
                                each_msg.expires_time, each_msg.message_id))
                            new_session.delete(each_msg)
                    new_session.commit()
            except:
                logger.exception("remove_deleted_msgs")

        #
        # Check lists that may be expiring and resend
        #
        if self.timer_send_lists < now and self.bm_sync_complete:
            logger.info("Running send_lists()")
            while self.timer_send_lists < now:
                self.timer_send_lists += (60 * 60 * 6)  # 6 hours
            try:
                self.send_lists()
            except:
                logger.exception("Could not complete send_lists()")

        #
        # Check commands that may be expiring and resend
        #
        if self.timer_send_commands < now and self.bm_sync_complete:
            while self.timer_send_commands < now:
                self.timer_send_commands += (60 * 60 * 6)  # 6 hours
            try:
                send_commands()
            except:
                logger.exception("Could not complete send_commands()")

        #
        # Get unread mail counts
        #
        if self.timer_unread_mail < now:
            while self.timer_unread_mail < now:
                self.timer_unread_mail += config.BM_UNREAD_CHECK_PERIOD
            try:
                self.check_unread_mail()
            except:
                logger.exception("Could not complete check_unread_mail()")

        #
        # Rule: Automatically Wipe Board/List
        #
        with session_scope(DB_PATH) as new_session:
            for each_chan in new_session.query(Chan).all():
                if each_chan.rules:
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
                        logger.error("Error clearing board/list: {}".format(err))
                        continue

        self.first_run = False

    def check_sync(self):
        """Determine if a Bitmessage sync has completed"""
        lf = LF()
        if lf.lock_acquire("/var/lock/bm_sync_check.lock", to=60):
            try:
                self.check_sync_locked()
            except Exception as err:
                logger.error("Error: {}".format(err))
            finally:
                lf.lock_release("/var/lock/bm_sync_check.lock")

    def check_sync_locked(self):
        """Determine if a Bitmessage sync has completed"""
        bm_status = {}
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                bm_status = self._api.clientStatus()
            except Exception as err:
                logger.error("Error: {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_API)

        if "networkStatus" in bm_status:
            if bm_status["networkStatus"] != "notConnected":
                if not self.bm_connected_timer:
                    # upon becoming connected, wait 90 sec until checking if synced
                    self.bm_connected_timer = time.time() + 90
                self.bm_connected = True
            else:
                self.bm_connected = False
                self.bm_connected_timer = None
                self.bm_pending_download_timer = None

        if "pendingDownload" in bm_status:
            if bm_status["pendingDownload"] == 0:
                self.bm_pending_download = False
            else:
                self.bm_pending_download = True
                self.bm_sync_complete = False

            if self.bm_connected:
                if bm_status["pendingDownload"] < 50:
                    if not self.bm_pending_download_timer:
                        self.bm_pending_download_timer = time.time() + 60
                else:
                    self.bm_pending_download_timer = None
                    self.bm_sync_complete = False

        # indicate sync is complete if:
        # 1) connected and no pending downloads for past 60 seconds.
        # or
        # 2) connected and only a few pending downloads remain and
        # have not increased over 50 in the past 60 seconds.
        if (self.bm_connected and
                (self.bm_connected_timer and time.time() > self.bm_connected_timer) and
                (
                    not self.bm_pending_download or
                    (self.bm_pending_download_timer and
                     time.time() > self.bm_pending_download_timer)
                )):
            self.bm_connected_timer = None
            self.bm_pending_download_timer = None
            self.bm_sync_complete = True

        # logger.info("con {}, pend {} {}, synced {}".format(
        #     self.bm_connected,
        #     bm_status["pendingDownload"],
        #     self.bm_pending_download,
        #     self.bm_sync_complete))

    def send_lists(self):
        for list_address in self.get_list_chans():
            from_address = None
            run_id = get_random_alphanumeric_string(
                6, with_punctuation=False, with_spaces=False)

            try:
                list_chan = db_return(Chan).filter(and_(
                    Chan.type == "list",
                    Chan.address == list_address)).first()

                if not list_chan:
                    continue

                logger.info("{}: Checking list {} ({})".format(
                    run_id, list_chan.address, list_chan.label))

                list_access = get_access(list_address)

                errors, dict_chan_info = process_passphrase(list_chan.passphrase)
                if not dict_chan_info or errors:
                    logger.error("{}: Error(s) sending list message to {}".format(
                        run_id, list_chan.address))
                    for err in errors:
                        logger.error(err)
                    break

                from_primary_secondary = self.find_senders(
                    list_address, ["primary_addresses", "secondary_addresses"])
                from_tertiary = self.find_senders(
                    list_address, ["tertiary_addresses"])

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
                        if each_add != list_address and each_add not in list_access["restricted_addresses"]:
                            from_non_self.append(each_add)
                    for each_add in self.get_identities():
                        if each_add != list_address and each_add not in list_access["restricted_addresses"]:
                            from_non_self.append(each_add)

                if list_chan.list_send:
                    logger.info("{}: List instructed to send.".format(run_id))
                    with session_scope(DB_PATH) as new_session:
                        list_mod = new_session.query(Chan).filter(
                            Chan.address == list_address).first()
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
                            allowed_addresses.append(list_address)

                        if allowed_addresses and list_chan.default_from_address in allowed_addresses:
                            from_address = list_chan.default_from_address
                        elif allowed_addresses:
                            from_address = allowed_addresses[0]
                        else:
                            from_address = None

                elif from_primary_secondary and list_chan.list_message_expires_time_owner:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_owner):
                        logger.info("{}: List expiring for owner with expires_time.".format(run_id))
                        from_address = from_primary_secondary[0]
                    else:
                        continue
                elif from_tertiary and list_chan.list_message_expires_time_user:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        logger.info("{}: List expiring for user with expires_time.".format(run_id))
                        from_address = from_tertiary[0]
                    else:
                        continue
                elif (dict_chan_info["access"] == "public" and
                        requires_identity and
                        from_non_self and
                        list_chan.list_message_expires_time_user):
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        logger.info("{}: List expiring for user with expires_time and is public "
                                    "with rule requires_identity_to_post.".format(run_id))
                        from_address = from_non_self[0]
                    else:
                        continue
                elif dict_chan_info["access"] == "public" and list_chan.list_message_expires_time_user:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        logger.info("{}: List expiring for user with expires_time and is public.".format(run_id))
                        from_address = list_address
                    else:
                        continue
                elif from_primary_secondary and list_chan.list_message_timestamp_utc_owner:
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_owner):
                        logger.info("{}: List expiring for owner with timestamp.".format(run_id))
                        from_address = from_primary_secondary[0]
                    else:
                        continue
                elif from_tertiary and list_chan.list_message_timestamp_utc_user:
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        logger.info("{}: List expiring for user with timestamp.".format(run_id))
                        from_address = from_tertiary[0]
                    else:
                        continue
                elif (dict_chan_info["access"] == "public" and
                        requires_identity and
                        from_non_self and
                        list_chan.list_message_timestamp_utc_user):
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        logger.info("{}: List expiring for user with timestamp and is public "
                                    "with rule requires_identity_to_post.".format(run_id))
                        from_address = from_non_self[0]
                    else:
                        continue
                elif dict_chan_info["access"] == "public" and list_chan.list_message_timestamp_utc_user:
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        logger.info("{}: List expiring for user with timestamp and is public.".format(run_id))
                        from_address = list_address
                    else:
                        continue
                else:
                    logger.info("{}: List not expiring or you don't have an address authorized to send.".format(run_id))
                    continue

                if not from_address:
                    continue

                send_msg_dict = {
                    "version": config.VERSION_BITCHAN,
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
                    continue

                logger.info("{}: Sending {} list message with {} entries from {} to {}".format(
                    run_id,
                    dict_chan_info["access"],
                    len(send_msg_dict["list"]),
                    from_address,
                    list_address))

                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        return_str = self._api.sendMessage(
                            list_address,
                            from_address,
                            "",
                            message_send,
                            2,
                            config.BM_TTL)
                        if return_str:
                            self.post_delete_queue(from_address, return_str)
                        time.sleep(0.1)
                    except Exception:
                        pass
                    finally:
                        lf.lock_release(config.LOCKFILE_API)
            except Exception:
                logger.exception("send_lists()")

    def get_message_expires_times(self):
        try:
            with session_scope(DB_PATH) as new_session:
                msg_inbox = new_session.query(Messages).filter(
                    Messages.expires_time == None).all()
                for each_msg in msg_inbox:
                    expires = get_msg_expires_time(each_msg.message_id)
                    if expires:
                        logger.info("{}: Messages: Set expire time to {}".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper(), expires))
                        each_msg.expires_time = expires
                    else:
                        logger.info("{}: Messages: No inventory entry.".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper()))

                msg_deleted = new_session.query(DeletedMessages).filter(
                    DeletedMessages.expires_time == None).all()
                for each_msg in msg_deleted:
                    expires = get_msg_expires_time(each_msg.message_id)
                    if expires:
                        logger.info("{}: DeletedMessages: Set expire time to {}".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper(), expires))
                        each_msg.expires_time = expires

                        # Update list expires time for owner messages
                        chan_list = new_session.query(Chan).filter(and_(
                            Chan.type == "list",
                            Chan.list_message_id_owner == each_msg.message_id,
                            Chan.list_message_expires_time_owner == None
                        )).first()
                        if chan_list:
                            chan_list.list_message_expires_time_owner = expires
                            if expires > self.get_utc():
                                days = (expires - self.get_utc()) / 60 / 60 / 24
                                logger.info("{}: Setting empty owner list expire time to {} ({:.1f} days from now)".format(
                                    each_msg.message_id[-config.ID_LENGTH:].upper(), expires, days))

                        # Update list expires time for user messages
                        chan_list = new_session.query(Chan).filter(and_(
                            Chan.type == "list",
                            Chan.list_message_id_user == each_msg.message_id,
                            Chan.list_message_expires_time_user == None
                        )).first()
                        if chan_list:
                            chan_list.list_message_expires_time_user = expires
                            if expires > self.get_utc():
                                days = (expires - self.get_utc()) / 60 / 60 / 24
                                logger.info(
                                    "{}: Setting empty user list expire time to {} ({:.1f} days from now)".format(
                                        each_msg.message_id[-config.ID_LENGTH:].upper(), expires, days))
                    else:
                        logger.info("{}: DeletedMessages. No inventory entry.".format(
                            each_msg.message_id[-config.ID_LENGTH:].upper()))
                new_session.commit()
        except:
            logger.exception("get_msg_expires_time")


    def get_unread_mail_count(self, address):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                messages = self._api.getInboxMessagesByReceiver(address)
                if "inboxMessages" in messages:
                    unread_count = 0
                    for each_msg in messages["inboxMessages"]:
                        if not each_msg["read"]:
                            unread_count += 1
                    return unread_count
            except Exception as err:
                logger.error("Error: {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_API)

    def set_unread_mail_count(self, address):
        with session_scope(DB_PATH) as new_session:
            ident = new_session.query(Identity).filter(
                Identity.address == address).first()
            ident.unread_messages = self.get_unread_mail_count(address)
            new_session.commit()

    def check_unread_mail(self):
        """Save number of unread messages for each Identity"""
        with session_scope(DB_PATH) as new_session:
            for identity in new_session.query(Identity).all():
                self.set_unread_mail_count(identity.address)

    def _update_identities(self):
        new_identities = {}
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                dict_return = self._api.listAddresses()
                time.sleep(0.1)
            except Exception as err:
                logger.error("Exception getting identities: {}".format(err))
                return
            finally:
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
            logger.info("Adding/Updating Identities")
            with session_scope(DB_PATH) as new_session:
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
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                dict_return = self._api.listSubscriptions()
                time.sleep(0.1)
            except Exception as err:
                logger.error("Exception getting subscriptions: {}".format(err))
                return
            finally:
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
                logger.info("Adding/Updating Identity {}".format(address['address']))
                self._subscription_dict[address['address']] = dict_subscription

    def update_address_book(self):
        new_addresses = {}
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                dict_return = self._api.listAddressBookEntries()
                time.sleep(0.1)
            except Exception as err:
                logger.error("Exception getting address book entries: {}".format(err))
                return
            finally:
                lf.lock_release(config.LOCKFILE_API)
        else:
            return

        for address in dict_return["addresses"]:
            label = base64.b64decode(address["label"]).decode()
            new_addresses[address["address"]] = {"label": label}

        with session_scope(DB_PATH) as new_session:
            for address in new_session.query(AddressBook).all():
                if address.address not in new_addresses:
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=60):
                        try:
                            self._api.addAddressBookEntry(address.address, address.label)
                            new_addresses[address.address] = {"label": address.label}
                            time.sleep(0.1)
                        except Exception as err:
                            logger.error("Exception adding address book entry: {}".format(err))
                        finally:
                            lf.lock_release(config.LOCKFILE_API)

        for address in new_addresses:
            label = new_addresses[address]["label"]
            if len(label) > config.LABEL_LENGTH:
                new_addresses[address]["label_short"] = label[:config.LABEL_LENGTH]
            else:
                new_addresses[address]["label_short"] = label

        if self._address_book_dict.keys() != new_addresses.keys() or self._refresh_address_book:
            self._refresh_address_book = False
            logger.info("Adding/Updating Address Book")
            with session_scope(DB_PATH) as new_session:
                for address, each_add in new_addresses.items():
                    address_book = new_session.query(
                        AddressBook).filter(AddressBook.address == address).first()
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
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                dict_return = self._api.listAddresses()
                time.sleep(0.1)
            except Exception as err:
                logger.error("Exception getting chans: {}".format(err))
                return
            finally:
                lf.lock_release(config.LOCKFILE_API)
        else:
            return

        for address in dict_return['addresses']:
            # logger.info("Chan: {}".format(address))

            if address['chan']:
                all_chans[address['address']] = {
                    "label": address['label'],
                    "enabled": address['enabled']
                }

            with session_scope(DB_PATH) as new_session:
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

        with session_scope(DB_PATH) as new_session:
            # Join board chan if found in database and not found in Bitmessage
            board_chans = new_session.query(Chan).filter(Chan.type == "board").all()
            for each_board in board_chans:
                if not each_board.is_setup:
                    logger.info("Found board chan in database that needs to be joined. Joining.")
                    address = self.join_chan(each_board.passphrase, clear_inventory=False)
                    time.sleep(1)

                    if address and "Chan address is already present" in address:
                        logger.info("Board already present in Bitmessage. Updating database.")
                        for each_address in self._all_chans:
                            if each_board.passphrase in self._all_chans[each_address]["label"]:
                                each_board.address = each_address
                                break
                        each_board.is_setup = True
                        new_session.commit()
                    elif address and address.startswith("BM-") and not each_board.address:
                        each_board.address = address
                        each_board.is_setup = True
                        new_session.commit()
                    else:
                        logger.info("Could not join board. Joining might be queued. Trying again later.")

                if (each_board.address not in self._chan_board_dict and
                        each_board.address in chans_addresses):
                    self._chan_board_dict[each_board.address] = chans_addresses[each_board.address]

            # Join list chans if in database and not added to Bitmessage
            chans_list = new_session.query(Chan).filter(Chan.type == "list").all()
            for each_list in chans_list:
                if not each_list.is_setup:
                    # Chan in bitmessage not in database. Add to database, generate and send list message.
                    logger.info("Found list chan in database that needs to be joined. Joining.")
                    # Join default list chan
                    address = self.join_chan(each_list.passphrase, clear_inventory=False)
                    time.sleep(1)

                    if address and "Chan address is already present" in address:
                        logger.info("List already present in bitmessage. Updating database.")
                        for each_address in self._all_chans:
                            if each_list.passphrase in self._all_chans[each_address]["label"]:
                                each_list.address = each_address
                                break
                        each_list.is_setup = True
                        new_session.commit()
                    elif address and address.startswith("BM-") and not each_list.address:
                        each_list.address = address
                        each_list.is_setup = True
                        new_session.commit()
                    else:
                        logger.info("Could not join list. Joining might be queued. Trying again later.")

                if (each_list.address not in self._chan_list_dict and
                        each_list.address in chans_addresses):
                    self._chan_list_dict[each_list.address] = chans_addresses[each_list.address]

    def queue_new_messages(self):
        """Add new messages to processing queue"""
        messages = []
        for each_address in self.get_all_chans():
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=60):
                try:
                    messages_api = self._api.getInboxMessagesByReceiver(each_address)
                    if "inboxMessages" in messages_api and messages_api['inboxMessages']:
                        messages.extend(messages_api['inboxMessages'])
                    time.sleep(0.1)
                except Exception as err:
                    logger.error("Exception getting all message IDs: {}".format(err))
                    return
                finally:
                    lf.lock_release(config.LOCKFILE_API)
            else:
                return

        with session_scope(DB_PATH) as new_session:
            for message in messages:

                if new_session.query(DeletedMessages).filter(
                        DeletedMessages.message_id == message["msgid"]).count():
                    logger.info("{}: Message labeled as deleted. Deleting.".format(
                        message["msgid"][-config.ID_LENGTH:].upper()))
                    self.trash_message(message["msgid"])
                    continue

                if message["msgid"] in self._non_bitchan_message_ids:
                    continue

                if (message["msgid"] in self._posts_by_id and
                        message["msgid"] not in self.list_start_download):
                    logger.debug("{}: Message already processed. return.".format(
                        message["msgid"][-config.ID_LENGTH:].upper()))
                    continue

                message_db = new_session.query(Messages).filter(
                    Messages.message_id == message["msgid"]).first()
                if message_db:
                    if (message["msgid"] in self.list_start_download and
                            not message_db.file_currently_downloading):
                        # Download instructed to start by user. Only initiate
                        # download once, and skip further processing attempts
                        # unless download has failed. Use thread to allow new
                        # messages to continue to be processed while
                        # downloading.
                        message_db.file_progress = "Download starting"
                        message_db.file_currently_downloading = True
                        new_session.commit()
                        thread_download = Thread(target=self._posts_by_id[message["msgid"]].allow_download)
                        thread_download.daemon = True
                        thread_download.start()
                        continue

                    # If the server restarted while a download was underway,
                    # reset the downloading indicator when the server starts
                    # again, allowing the presentation of the Download button
                    # to the user.
                    if (message["msgid"] not in self.list_start_download and
                            message_db.file_currently_downloading):
                        message_db.file_currently_downloading = False
                        new_session.commit()

                    #
                    # Create post object
                    #
                    if message_db.thread and message_db.thread.chan:
                        if message["msgid"] in self._posts_by_id:
                            continue
                        to_address = message_db.thread.chan.address
                        logger.info("{}: Adding message to {} ({})".format(
                            message["msgid"][-config.ID_LENGTH:].upper(), to_address, message_db.thread.chan.label))
                        post = ChanPost(message["msgid"])

                        if to_address not in self._board_by_chan:
                            self._board_by_chan[to_address] = ChanBoard(to_address)
                        self._posts_by_id[message["msgid"]] = post
                        chanboard = self._board_by_chan[to_address]
                        chanboard.add_post(post, message_db.thread.thread_hash)
                        continue

                to_address = message['toAddress']

                # Check if chan exists
                chan = new_session.query(Chan).filter(Chan.address == to_address).first()
                if not chan:
                    logger.info("{}: To address {} not in board or list DB. Indicative of a non-BitChan message.".format(
                        message["msgid"][-config.ID_LENGTH:].upper(), to_address))
                    if message["msgid"] not in self._non_bitchan_message_ids:
                        self._non_bitchan_message_ids.append(message["msgid"])
                    continue

                if message["msgid"] not in self.message_threads:
                    logger.info("{}: Adding message to processing queue".format(message["msgid"][-config.ID_LENGTH:].upper()))
                    self.message_threads[message["msgid"]] = {
                        "thread": Thread(target=process_message, args=(message,)),
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
            with session_scope(DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                settings.discard_message_ids = json.dumps(self._non_bitchan_message_ids)
                new_session.commit()

    def check_message_threads(self):
        """Ensure message thread queue is moving"""
        threads_running = 0
        list_threads_completed = []
        for thread_id in self.message_threads:
            if self.message_threads[thread_id]["thread"].is_alive():
                threads_running += 1
            if (self.message_threads[thread_id]["started"] and
                    not self.message_threads[thread_id]["thread"].is_alive()):
                list_threads_completed.append(thread_id)

        # Remove completed threads from dict
        for each_thread in list_threads_completed:
            self.message_threads.pop(each_thread, None)

        for thread_id in self.message_threads:
            if (not self.message_threads[thread_id]["started"] and
                    threads_running < self.max_threads and
                    threads_running < len(self.message_threads)):
                self.message_threads[thread_id]["started"] = True
                logger.info("{}: Starting message processing thread".format(thread_id[-config.ID_LENGTH:].upper()))
                self.message_threads[thread_id]["thread"].start()
                threads_running += 1

    def join_chan(self, passphrase, clear_inventory=True):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                result = self._api.createChan(base64.b64encode(passphrase.encode()).decode())
                time.sleep(0.1)
                self._refresh = True
                if clear_inventory:
                    self.signal_clear_inventory()  # resync inventory to get older messages
                return result
            except Exception as e:
                return repr(e)
            finally:
                lf.lock_release(config.LOCKFILE_API)

    def leave_chan(self, address):
        # Currently bug preventing removal from bitmessage until restart
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                result = self._api.leaveChan(address)
                time.sleep(0.1)
                self._refresh = True
                return result
            except Exception as e:
                return repr(e)
            finally:
                lf.lock_release(config.LOCKFILE_API)

    def get_api_status(self):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                result = self._api.add(2, 2)
                time.sleep(0.1)
            except Exception as e:
                return repr(e)
            finally:
                lf.lock_release(config.LOCKFILE_API)
            if result == 4:
                return True
            return result

    def get_chan_name(self, chan_address):
        for label, address in self._chan_board_dict.items():
            if address == chan_address:
                return label

    def get_chan_threads(self, chan_address, page=1):
        if chan_address not in self._board_by_chan:
            return []
        board = self._board_by_chan[chan_address]
        thread_start = int((int(page) - 1) * config.THREADS_PER_PAGE)
        thread_end = int(int(page) * config.THREADS_PER_PAGE)
        return board.get_threads(thread_start, thread_end)

    def get_chan_thread(self, chan_address, thread_id):
        if chan_address not in self._board_by_chan:
            return None
        board = self._board_by_chan[chan_address]
        return board.get_thread(thread_id)

    def get_thread_count(self, chan_address):
        if chan_address not in self._board_by_chan:
            return 0
        return self._board_by_chan[chan_address].get_thread_count()

    def trash_message(self, message_id, address=None):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=120):
            try:
                # Add message ID and TTL expiration in database (for inventory wipes)
                expires = get_msg_expires_time(message_id)
                address_from = get_msg_address_from(message_id)
                with session_scope(DB_PATH) as new_session:
                    test_del = new_session.query(DeletedMessages).filter(
                        DeletedMessages.message_id == message_id).count()
                    if not test_del:
                        logger.info("DeletedMessages table: add {}, {}, {}".format(address, expires, message_id))
                        del_msg = DeletedMessages()
                        del_msg.message_id = message_id
                        del_msg.address_from = address_from
                        if address:  # Leaving board/list
                            del_msg.address_to = address
                        del_msg.expires_time = expires
                        new_session.add(del_msg)
                        new_session.commit()

                return_val = self._api.trashMessage(message_id)
                time.sleep(0.1)

                return return_val
            except Exception as err:
                logger.error("Exception during message delete: {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_API)
    
    def find_senders(self, address, list_send):
        list_senders = []
        access = get_access(address)
        for each_sender in list_send:
            for each_chan in self.get_all_chans():
                if each_chan in access[each_sender] and each_chan not in access["restricted_addresses"]:
                    list_senders.append(each_chan)
            for each_ident in self.get_identities():
                if each_ident in access[each_sender] and each_ident not in access["restricted_addresses"]:
                    list_senders.append(each_ident)
        return list_senders

    def expiring_from_expires_time(self, run_id, expire_time):
        """Determine from expires_time if the list is expiring"""
        if not expire_time:
            return
        if expire_time > self.get_utc():
            days = (expire_time - self.get_utc()) / 60 / 60 / 24
            if days < 28 - config.SEND_BEFORE_EXPIRE_DAYS:
                logger.info("{}: List expiring in {:.1f} days. Send list.".format(
                    run_id, days))
                return True
            else:
                logger.info("{}: List expiring in {:.1f} days. Do nothing.".format(
                    run_id, days))
        else:
            days = (self.get_utc() - expire_time) / 60 / 60 / 24
            logger.info("{}: List expired {:.1f} days ago. Send list.".format(
                run_id, days))
            return True

    def expiring_from_timestamp(self, run_id, timestamp):
        """Determine from sent/received timestamp if the list is expiring"""
        if not timestamp:
            return
        days = (self.get_utc() - timestamp) / 60 / 60 / 24
        if days > config.SEND_BEFORE_EXPIRE_DAYS:
            logger.info("{}: List might be expiring: {:.1f} days old.".format(
                run_id, days))
            return True
        else:
            logger.info("{}: List might not be expiring: {:.1f} days old.".format(
                run_id, days))

    def clear_list_board_contents(self, address):
        with session_scope(DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(Chan.address == address).first()
            if chan.type == "list":
                logger.info("Clearing List {}".format(chan.address))
                try:
                    list_list = json.loads(chan.list)
                    if list_list:
                        chan.list = "{}"
                        new_session.commit()
                except:
                    pass
            elif chan.type == "board":
                logger.info("Clearing Board {}".format(chan.address))
                self.delete_all_messages(chan.address)

    def delete_all_messages(self, address):
        with session_scope(DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(
                Chan.address == address).first()
            threads = new_session.query(Threads).filter(
                Threads.chan_id == chan.id).all()
            for each_thread in threads:
                messages = new_session.query(Messages).filter(
                    Messages.thread_id == each_thread.thread_hash).all()
                for each_message in messages:
                    # First, delete messages from database
                    new_session.delete(each_message)
                    new_session.commit()
                    # Delete all files associated with message
                    delete_message_files(each_message.message_id)
                # Next, delete message objects from bitchan objects and thread from DB
                self.delete_thread(address, each_thread.thread_hash)
                new_session.delete(each_thread)
                new_session.commit()

    def delete_message(self, chan, thread_id, message_id):
        logger.info("{}: Deleting message from board {} and thread with hash {}".format(
            message_id[-config.ID_LENGTH:].upper(), chan, thread_id))
        try:
            board = self._board_by_chan[chan]
            post = self._posts_by_id[message_id]
            # thread = board.get_thread(thread_id)
            # thread.delete_post(post)
            board.delete_post(post)
            del self._posts_by_id[message_id]
        except Exception as err:
            logger.error("Exception deleting post: {}".format(err))
        return self.trash_message(message_id, address=chan)

    def delete_thread(self, chan, thread_id):
        logger.info("{}: Deleting thread".format(thread_id[0:6]))
        try:
            board = self._board_by_chan[chan]
            thread = board.get_thread(thread_id)
            if thread:
                list_post_ids = []
                threadposts = thread.get_posts()

                # Make list of post IDS to be deleted to avoid deleting
                # from the list that's being iterated
                for post in threadposts:
                    list_post_ids.append(post.message_id)

                # Actually delete the posts
                for each_post_id in list_post_ids:
                    self.delete_message(chan, thread_id, each_post_id)

                # Finally, delete the thread
                board.delete_thread(thread_id)
        except Exception as err:
            logger.exception("Exception deleting thread: {}".format(err))
        return "Thread {} deleted".format(repr(thread_id))

    def get_address_labels(self):
        address_labels = {}
        list_name_objects = [self.get_address_book(),
                             self.get_all_chans(),
                             self.get_identities()]
        for each_name_repo in list_name_objects:
            for each_address in each_name_repo:
                if "label_short" in each_name_repo[each_address]:
                    address_labels[each_address] = each_name_repo[each_address]["label_short"]
        return address_labels

    def get_chans_board_info(self):
        chans_board_unsorted = {}
        for each_chan in self.get_board_chans():
            with session_scope(DB_PATH) as new_session:
                chan = new_session.query(Chan).filter(and_(
                    Chan.address == each_chan,
                    Chan.type == "board")).first()
                if chan:
                    chans_board_unsorted[each_chan] = {}
                    chans_board_unsorted[each_chan]["db"] = chan
                    chans_board_unsorted[each_chan]["bm_label"] = self.get_board_chans()[each_chan]
                    chans_board_unsorted[each_chan]["label"] = replace_lt_gt(chan.label)
                    chans_board_unsorted[each_chan]["description"] = replace_lt_gt(chan.description)
                    chans_board_unsorted[each_chan]["rules"] = json.loads(chan.rules)

                    access = get_access(chan.address)
                    chans_board_unsorted[each_chan]["primary_addresses"] = access["primary_addresses"]
                    chans_board_unsorted[each_chan]["secondary_addresses"] = access["secondary_addresses"]
                    chans_board_unsorted[each_chan]["tertiary_addresses"] = access["tertiary_addresses"]
                    chans_board_unsorted[each_chan]["restricted_addresses"] = access["restricted_addresses"]

                    if len(chan.label) > config.LABEL_LENGTH:
                        chans_board_unsorted[each_chan]["label_short"] = replace_lt_gt(chan.label[:config.LABEL_LENGTH])
                    else:
                        chans_board_unsorted[each_chan]["label_short"] = replace_lt_gt(chan.label)
        return OrderedDict(
            sorted(chans_board_unsorted.items(), key=lambda x: getitem(x[1], 'label')))

    def get_chans_list_info(self):
        chans_list_unsorted = {}
        for each_chan in self.get_list_chans():
            with session_scope(DB_PATH) as new_session:
                chan = new_session.query(Chan).filter(and_(
                    Chan.address == each_chan,
                    Chan.type == "list")).first()
                if chan:
                    chans_list_unsorted[each_chan] = {}
                    chans_list_unsorted[each_chan]["db"] = chan
                    chans_list_unsorted[each_chan]["bm_label"] = self.get_list_chans()[each_chan]
                    chans_list_unsorted[each_chan]["label"] = replace_lt_gt(chan.label)
                    chans_list_unsorted[each_chan]["description"] = replace_lt_gt(chan.description)
                    chans_list_unsorted[each_chan]["rules"] = json.loads(chan.rules)
                    chans_list_unsorted[each_chan]["primary_addresses"] = json.loads(chan.primary_addresses)

                    access = get_access(chan.address)
                    chans_list_unsorted[each_chan]["primary_addresses"] = access["primary_addresses"]
                    chans_list_unsorted[each_chan]["secondary_addresses"] = access["secondary_addresses"]
                    chans_list_unsorted[each_chan]["tertiary_addresses"] = access["tertiary_addresses"]
                    chans_list_unsorted[each_chan]["restricted_addresses"] = access["restricted_addresses"]

                    if len(chan.label) > config.LABEL_LENGTH:
                        chans_list_unsorted[each_chan]["label_short"] = replace_lt_gt(chan.label[:config.LABEL_LENGTH])
                    else:
                        chans_list_unsorted[each_chan]["label_short"] = replace_lt_gt(chan.label)
        return OrderedDict(
            sorted(chans_list_unsorted.items(), key=lambda x: getitem(x[1], 'label')))

    def get_from_list(self, address):
        """Generate a list of addresses available for the From address to send with"""
        from_addresses = {}
        anon_post = False

        with session_scope(DB_PATH) as new_session:
            address_labels = self.get_address_labels()
            all_chans = self.get_all_chans()
            identities = self.get_identities()

            chan = new_session.query(Chan).filter(Chan.address == address).first()
            if chan.type == "board":
                chans_info = self.get_chans_board_info()
            elif chan.type == "list":
                chans_info = self.get_chans_list_info()

            primary_addresses = chans_info[address]["primary_addresses"]
            secondary_addresses = chans_info[address]["secondary_addresses"]
            tertiary_addresses = chans_info[address]["tertiary_addresses"]
            restricted_addresses = chans_info[address]["restricted_addresses"]
            rules = chans_info[address]["rules"]
            require_identity_to_post = ("require_identity_to_post" in rules and
                                        rules["require_identity_to_post"])

            if (chan.access == "public" and
                    not require_identity_to_post and
                    address not in restricted_addresses):
                anon_post = address
                from_addresses[address] = "Anonymous (this {})".format(chan.type)

            for each_address in identities:
                if each_address in from_addresses:
                    continue

                if identities[each_address]['enabled'] and (
                        (chan.access == "private" and
                         (each_address in primary_addresses or
                          each_address in secondary_addresses or
                          each_address in tertiary_addresses)
                        ) or
                        (chan.access == "public" and
                         each_address not in restricted_addresses)):

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
                        from_addresses[each_address] += "{} ".format(address_labels[each_address])
                    from_addresses[each_address] += "({}...{})".format(
                        each_address[:9], each_address[-6:])

            for each_address in all_chans:
                if each_address in from_addresses:
                    continue

                if all_chans[each_address]['enabled'] and (
                        (chan.access == "private" and
                         (each_address in primary_addresses or
                          each_address in secondary_addresses or
                          each_address in tertiary_addresses)
                        ) or
                        (chan.access == "public" and
                         each_address != address and
                         each_address not in restricted_addresses)):

                    if each_address in primary_addresses:
                        from_addresses[each_address] = "[Owner] "
                    elif each_address in secondary_addresses:
                        from_addresses[each_address] = "[Admin] "
                    elif each_address in tertiary_addresses:
                        from_addresses[each_address] = "[User] "
                    else:
                        from_addresses[each_address] = "[Other] "

                    if new_session.query(Chan).filter(Chan.address == each_address).first():
                        if new_session.query(Chan).filter(Chan.address == each_address).first().type == "board":
                            from_addresses[each_address] += "Board: "
                        elif new_session.query(Chan).filter(Chan.address == each_address).first().type == "list":
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

    def clear_bm_inventory(self):
        try:
            self.is_restarting_bitmessage = True
            self.bitmessage_stop()
            time.sleep(20)

            logger.info("Deleting Bitmessage inventory")
            conn = sqlite3.connect('file:{}'.format(config.messages_dat), uri=True)
            c = conn.cursor()
            c.execute('DELETE FROM inventory')
            conn.commit()
            conn.close()

            self.bitmessage_start()
            time.sleep(20)
        finally:
            self.is_restarting_bitmessage = False

    def is_pow_sending(self):
        doing_pow = False
        try:
            conn = sqlite3.connect('file:{}'.format(config.messages_dat), uri=True)
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
            logger.exception("Error checking for POW: {}".format(err))
        finally:
            return doing_pow

    def delete_and_vacuum(self):
        logger.info("Deleting Bitmessage Trash items")
        try:
            self._api.deleteAndVacuum()
        except:
            logger.exception("delete_and_vacuum()")

    def signal_clear_inventory(self):
        logger.info("Signaling deletion of Bitmessage inventory in {} minutes".format(
            config.CLEAR_INVENTORY_WAIT / 60))
        self.timer_clear_inventory = time.time() + config.CLEAR_INVENTORY_WAIT
        with session_scope(DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            if settings:
                settings.clear_inventory = True
                new_session.commit()

    def bitmessage_monitor(self):
        """Monitor bitmessage and restart it if it's API is unresponsive"""
        while True:
            now = time.time()
            if self.timer_check_bm_alive < now:
                while self.timer_check_bm_alive < now:
                    self.timer_check_bm_alive += 10
                lf = LF()
                if (not self.is_restarting_bitmessage and
                        lf.lock_acquire(config.LOCKFILE_API, to=60)):
                    try:
                        self._api.add(2, 3)
                        time.sleep(0.1)
                    except socket.timeout:
                        logger.error("Timeout during BM monitor API query: restarting bitmessage")
                        self.restart_bitmessage()
                    except Exception as err:
                        logger.error("Exception during BM monitor API query: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_API)
            time.sleep(2)

    def update_utc_offset(self):
        ntp = ntplib.NTPClient()
        for _ in range(3):
            try:
                ntp_utc = ntp.request('pool.ntp.org').tx_time
                self.utc_offset = time.time() - ntp_utc
                logger.info("NTP UTC: {}, Offset saved: {}".format(ntp_utc, self.utc_offset))
                break
            except ntplib.NTPException as err:
                logger.error("NTP Error: {}".format(err))
            except Exception as err:
                logger.exception("NTP Error: {}".format(err))
            time.sleep(60)

    def restart_bitmessage(self):
        """Restart bitmessage"""
        try:
            if self.is_restarting_bitmessage:
                logger.info("Already restarting bitmessage. Please wait.")
            else:
                self.is_restarting_bitmessage = True
                self.bitmessage_stop()
                time.sleep(15)
                self.bitmessage_start()
                time.sleep(15)
        finally:
            self.is_restarting_bitmessage = False

    @staticmethod
    def bitmessage_stop():
        try:
            if config.DOCKER:
                logger.info("Stopping bitmessage docker container. Please wait.")
                subprocess.Popen('docker stop -t 15 bitmessage 2>&1', shell=True)
                time.sleep(15)
        except Exception as err:
            logger.error("Exception stopping Bitmessage: {}".format(err))

    @staticmethod
    def bitmessage_start():
        try:
            if config.DOCKER:
                logger.info("Starting bitmessage docker container. Please wait.")
                subprocess.Popen('docker start bitmessage 2>&1', shell=True)
                time.sleep(15)
        except Exception as err:
            logger.error("Exception starting Bitmessage: {}".format(err))

    def post_delete_queue(self, from_address, ack_id):
        if from_address in self._identity_dict:
            with session_scope(DB_PATH) as new_session:
                new_post = PostMessages()
                new_post.ack_id = ack_id
                new_post.address_from = from_address
                new_session.add(new_post)
                new_session.commit()

    def delete_identity_msgs(self):
        logger.debug("Checking Identity sent box for messages to be deleted")
        list_msgs_del = []
        list_pow = []
        list_sent = []

        with session_scope(DB_PATH) as new_session:
            for each_identity in self._identity_dict.keys():
                ident_msgs = {}
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        ident_msgs = self._api.getSentMessagesBySender(each_identity)
                    except Exception as err:
                        logger.error("Error: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_API)
                        time.sleep(0.1)
                if "sentMessages" in ident_msgs:
                    for each_msg in ident_msgs["sentMessages"]:
                        ident_msg = new_session.query(PostMessages).filter(and_(
                            PostMessages.address_from == each_identity,
                            PostMessages.ack_id == each_msg["ackData"])).first()
                        if (ident_msg and
                                each_msg["status"] != "doingmsgpow" and
                                each_msg["status"] == "msgsentnoackexpected"):
                            list_msgs_del.append(
                                (each_msg["msgid"],
                                 each_identity,
                                 each_msg["ackData"]))

            for each_msg in list_msgs_del:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        logger.info("Deleting sent Identity msg from {}, ackData {}, msgid {}".format(
                            each_msg[1], each_msg[2], each_msg[0]))
                        self._api.trashSentMessage(each_msg[0])
                        msg_del = new_session.query(PostMessages).filter(and_(
                            PostMessages.address_from == each_msg[1],
                            PostMessages.ack_id == each_msg[2])).first()
                        if msg_del:
                            new_session.delete(ident_msg)
                    except Exception as err:
                        logger.error("Error: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_API)
                        time.sleep(0.1)

            for each_identity in self._identity_dict.keys():
                ident_msgs = {}
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        ident_msgs = self._api.getSentMessagesBySender(each_identity)
                    except Exception as err:
                        logger.error("Error: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_API)
                        time.sleep(0.1)
                if "sentMessages" in ident_msgs:
                    for each_msg in ident_msgs["sentMessages"]:
                        if each_msg["status"] == "doingmsgpow":
                            list_pow.append(list_pow)
                        else:
                            list_sent.append(list_sent)
            logger.debug("Sent Identity messages remaining: POW finished: {}, doing POW: {}".format(
                len(list_sent), len(list_pow)))

    @staticmethod
    def new_tor_identity():
        try:
            with Controller.from_port(address="172.28.1.2", port=9061) as controller:
                controller.authenticate(password=config.TOR_PASS)
                controller.signal(Signal.NEWNYM)
                logger.info("New tor identity requested")
        except Exception as err:
            logger.info("Error getting new tor identity: {}".format(err))

    def get_utc(self):
        if self.utc_offset:
            return int(time.time() + self.utc_offset)
        else:
            return int(time.time())

    def is_utc_offset_set(self):
        return bool(self.utc_offset)

    def get_address_book(self):
        return self._address_book_dict

    def get_identities(self):
        return self._identity_dict

    def get_all_chans(self):
        return self._all_chans

    def get_list_chans(self):
        return self._chan_list_dict

    def get_board_chans(self):
        return self._chan_board_dict

    def get_subscriptions(self):
        return self._subscription_dict

    def get_start_download(self):
        return self.list_start_download

    def set_start_download(self, message_id):
        if self.get_post_by_id(message_id):
            logger.info("{}: Allowing file to be downloaded".format(message_id[-config.ID_LENGTH:].upper()))
            self.list_start_download.append(message_id)

    def remove_start_download(self, message_id):
        if message_id in self.list_start_download:
            self.list_start_download.remove(message_id)

    def get_post_by_id(self, post_id):
        if post_id in self._posts_by_id:
            return self._posts_by_id[post_id]


bitchan = BitChan()
bitchan.setDaemon(True)
bitchan.start()
