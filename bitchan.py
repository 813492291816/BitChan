import base64
import hashlib
import html
import json
import logging
import os
import random
import shutil
import socket
import sqlite3
import subprocess
import time
import xmlrpc.client
from io import BytesIO
from threading import Thread
from urllib.parse import urlparse

import PIL
import bleach
import cv2
import gnupg
import ntplib
import pyminizip
from PIL import Image
from sqlalchemy import and_
from sqlalchemy import or_

import config
from chan_objects import ChanBoard
from chan_objects import ChanList
from chan_objects import ChanPost
from database.models import AddressBook
from database.models import Chan
from database.models import Command
from database.models import DeletedMessages
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import Threads
from database.utils import db_return
from database.utils import session_scope
from utils.anonfile import AnonFile
from utils.download import download_and_extract
from utils.download import generate_hash
from utils.encryption import decrypt_safe_size
from utils.files import LF
from utils.files import data_file_multiple_extract
from utils.files import delete_file
from utils.files import delete_message_files
from utils.files import generate_thumbnail
from utils.files import human_readable_size
from utils.files import return_non_overlapping_sequences
from utils.gateway import chan_auto_clears_and_message_too_old
from utils.gateway import delete_and_replace_comment
from utils.gateway import delete_db_message
from utils.gateway import get_access
from utils.gateway import get_bitmessage_endpoint
from utils.gateway import get_msg_address_from
from utils.gateway import get_msg_expires_time
from utils.gateway import log_age_and_expiration
from utils.general import get_random_alphanumeric_string
from utils.general import get_thread_id
from utils.general import is_bitmessage_address
from utils.general import process_passphrase
from utils.general import version_checker
from utils.replacements import is_post_id_reply
from utils.replacements import process_replacements
from utils.replacements import replace_dict_keys_with_values
from utils.shared import is_access_same_as_db
from utils.steg import check_steg
from utils.steg import steg_encrypt

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
        socket.setdefaulttimeout(10)

        self.list_start_download = []
        self.message_threads = {}
        self.max_threads = 8
        self.utc_offset = None
        self.time_last = 0
        self.is_restarting_bitmessage = False
        self.auto_clear_first_run = True
        self.list_stats = []

        # Timers
        self.timer_check_bm_alive = time.time()
        self.timer_time_server = time.time()
        self.timer_bm_update = time.time()
        self.timer_clear_inventory = time.time()
        self.timer_message_threads = time.time()
        self.timer_non_bitchan_message_ids = time.time()
        self.timer_get_msg_expires_time = time.time() + (60 * 10)  # 10 minutes
        self.timer_remove_deleted_msgs = time.time() + (60 * 10)   # 10 minutes
        self.timer_send_lists = time.time() + (60 * 20)            # 20 minutes
        self.timer_send_commands = time.time() + (60 * 20)         # 20 minutes

        with session_scope(DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            if settings.discard_message_ids:
                self._non_bitchan_message_ids = json.loads(settings.discard_message_ids)

        bm_monitor = Thread(target=self.bitmessage_monitor)
        bm_monitor.daemon = True
        bm_monitor.start()

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

        update_ntp = False
        if abs(self.time_last - now) > 600:
            logger.info("Time changed? Update NTP.")
            update_ntp = True
        self.time_last = now

        #
        # Update message thread queue
        #
        if self.timer_time_server < now or update_ntp:
            while self.timer_time_server < now:
                self.timer_time_server += (60 * 6 * random.randint(40, 70))
            ntp = Thread(target=self.update_utc_offset)
            ntp.daemon = True
            ntp.start()

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
                    msg += " message, " if len(self._posts_by_id) == 1 else " messages, "
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
            self.check_message_threads()

        #
        # Clear inventory 10 minutes after last board/list join
        #
        if self.timer_clear_inventory < now:
            with session_scope(DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                if settings and settings.clear_inventory:
                    settings.clear_inventory = False
                    new_session.commit()
                    self.clear_bm_inventory()

        #
        # Get message expires time if not currently set
        #
        if self.timer_get_msg_expires_time < now:
            while self.timer_get_msg_expires_time < now:
                self.timer_get_msg_expires_time += (60 * 10)  # 10 minutes
            self.get_message_expires_times()

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
        if self.timer_send_lists < now:
            logger.info("Running send_lists()")
            while self.timer_send_lists < now:
                self.timer_send_lists += (60 * 60 * 6)  # 6 hours
            self.send_lists()

        #
        # Check commands that may be expiring and resend
        #
        if self.timer_send_commands < now:
            while self.timer_send_commands < now:
                self.timer_send_commands += (60 * 60 * 6)  # 6 hours
            self.send_commands()

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

                errors, dict_chan_info = process_passphrase(list_chan.passphrase)
                if not dict_chan_info or errors:
                    logger.error("{}: Error(s) sending list message to {}".format(
                        run_id, list_chan.address))
                    for err in errors:
                        logger.error(err)
                    break

                from_primary_secondary = self.find_sender(
                    list_address, ["primary_addresses", "secondary_addresses"])
                from_tertiary = self.find_sender(
                    list_address, ["tertiary_addresses"])

                from_non_self = None
                requires_identity = False
                try:
                    rules = json.loads(list_chan.rules)
                except:
                    rules = {}
                if (dict_chan_info["access"] == "public" and
                        "require_identity_to_post" in rules and
                        rules["require_identity_to_post"]):
                    requires_identity = True
                    for each_add in self.get_identities():
                        if each_add != list_address:
                            from_non_self = each_add
                            break
                    if not from_non_self:
                        for each_add in self.get_all_chans():
                            if each_add != list_address:
                                from_non_self = each_add
                                break

                if list_chan.list_send:
                    logger.info("{}: List instructed to send.".format(run_id))
                    with session_scope(DB_PATH) as new_session:
                        list_mod = new_session.query(Chan).filter(
                            Chan.address == list_address).first()
                        list_mod.list_send = False
                        new_session.commit()

                        if from_primary_secondary:
                            from_address = from_primary_secondary
                        elif from_tertiary:
                            from_address = from_tertiary
                        elif (dict_chan_info["access"] == "public" and
                                requires_identity and
                                from_non_self):
                            from_address = from_non_self
                        elif dict_chan_info["access"] == "public":
                            from_address = list_address

                elif from_primary_secondary and list_chan.list_message_expires_time_owner:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_owner):
                        logger.info("{}: List expiring for owner with expires_time.".format(run_id))
                        from_address = from_primary_secondary
                    else:
                        continue
                elif from_tertiary and list_chan.list_message_expires_time_user:
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        logger.info("{}: List expiring for user with expires_time.".format(run_id))
                        from_address = from_tertiary
                    else:
                        continue
                elif (dict_chan_info["access"] == "public" and
                        requires_identity and
                        from_non_self and
                        list_chan.list_message_expires_time_user):
                    if self.expiring_from_expires_time(run_id, list_chan.list_message_expires_time_user):
                        logger.info("{}: List expiring for user with expires_time and is public "
                                    "with rule requires_identity_to_post.".format(run_id))
                        from_address = from_non_self
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
                        from_address = from_primary_secondary
                    else:
                        continue
                elif from_tertiary and list_chan.list_message_timestamp_utc_user:
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        logger.info("{}: List expiring for user with timestamp.".format(run_id))
                        from_address = from_tertiary
                    else:
                        continue
                elif (dict_chan_info["access"] == "public" and
                        requires_identity and
                        from_non_self and
                        list_chan.list_message_timestamp_utc_user):
                    if self.expiring_from_timestamp(run_id, list_chan.list_message_timestamp_utc_user):
                        logger.info("{}: List expiring for user with timestamp and is public "
                                    "with rule requires_identity_to_post.".format(run_id))
                        from_address = from_non_self
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
                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    json.dumps(send_msg_dict),
                    symmetric=True,
                    passphrase=config.PASSPHRASE_MSG,
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
                        self._api.sendMessage(
                            list_address,
                            from_address,
                            "",
                            message_send,
                            2,
                            config.BM_TTL)
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
                            each_msg.message_id[0:6], expires))
                        each_msg.expires_time = expires
                    else:
                        logger.info("{}: Messages: No inventory entry.".format(
                            each_msg.message_id[0:6], each_msg.message))

                msg_deleted = new_session.query(DeletedMessages).filter(
                    DeletedMessages.expires_time == None).all()
                for each_msg in msg_deleted:
                    expires = get_msg_expires_time(each_msg.message_id)
                    if expires:
                        logger.info("{}: DeletedMessages: Set expire time to {}".format(
                            each_msg.message_id[0:6], expires))
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
                                    each_msg.message_id[0:6], expires, days))

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
                                        each_msg.message_id[0:6], expires, days))
                    else:
                        logger.info("{}: DeletedMessages. No inventory entry.".format(
                            each_msg.message_id[0:6]))
                new_session.commit()
        except:
            logger.exception("get_msg_expires_time")

    def send_commands(self):
        """Send admin commands prior to them expiring to ensure options are available to all users"""
        try:
            run_id = get_random_alphanumeric_string(
                6, with_punctuation=False, with_spaces=False)
            with session_scope(DB_PATH) as new_session:
                admin_cmds = new_session.query(Command).filter(
                    Command.do_not_send == False).all()
                for each_cmd in admin_cmds:
                    if not each_cmd.options:
                        continue

                    logger.info("{}: Checking commands to send to {}".format(
                        run_id, each_cmd.chan_address))

                    # Determine if we have an authorized address to send from
                    chan = new_session.query(Chan).filter(
                        Chan.address == each_cmd.chan_address).first()
                    if not chan:
                        logger.info("{}: Chan not found in DB".format(run_id))
                        continue

                    def admin_has_access(address):
                        access = get_access(address)
                        for id_type in [self.get_identities(), self.get_all_chans()]:
                            for address in id_type:
                                if id_type[address]['enabled'] and address in access["primary_addresses"]:
                                    return address

                    from_address = admin_has_access(chan.address)
                    if not from_address:
                        continue

                    try:
                        options = json.loads(each_cmd.options)
                    except:
                        options = {}

                    if not options:
                        logger.info("{}: No options found for Admin command to send.".format(run_id))
                        continue

                    def is_expiring(ts_utc):
                        days = (self.get_utc() - ts_utc) / 60 / 60 / 24
                        if days > 20:
                            logger.info("{}: {:.1f} days old.".format(run_id, days))
                            return True, days
                        else:
                            return False, days

                    for each_option in options:
                        dict_message = {
                            "version": config.VERSION_BITCHAN,
                            "timestamp_utc": self.get_utc(),
                            "message_type": "admin",
                            "action": each_cmd.action,
                            "action_type": each_cmd.action_type,
                            "message_id": each_cmd.message_id,
                            "thread_id": each_cmd.thread_id,
                            "chan_address": each_cmd.chan_address,
                            "options": {}
                        }

                        option_ts = "{}_timestamp_utc".format(each_option)
                        if each_option in config.ADMIN_OPTIONS and option_ts in options:
                            if is_expiring(options[option_ts]):
                                logger.info("{}: {} expiring".format(run_id, each_option))
                                dict_message["options"][each_option] = options[each_option]
                            else:
                                logger.info("{}: {} not expiring".format(run_id, each_option))

                        if not dict_message["options"]:
                            logger.info("{}: No options nearing expiration".format(run_id))
                            continue

                        str_message = json.dumps(dict_message)
                        gpg = gnupg.GPG()
                        message_encrypted = gpg.encrypt(
                            str_message,
                            symmetric=True,
                            passphrase=config.PASSPHRASE_MSG,
                            recipients=None)
                        message_send = base64.b64encode(message_encrypted.data).decode()

                        lf = LF()
                        if lf.lock_acquire(config.LOCKFILE_API, to=60):
                            try:
                                return_str = self._api.sendMessage(
                                    chan.address,
                                    from_address,
                                    "",
                                    message_send,
                                    2,
                                    config.BM_TTL)
                                if return_str:
                                    logger.info(
                                        "{}: Sent command options. Return: "
                                        "{}".format(run_id, return_str))
                                time.sleep(0.1)
                            finally:
                                lf.lock_release(config.LOCKFILE_API)
        except:
            logger.exception("send_commands()")

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
            board_chans = new_session.query(Chan).filter(Chan.type == "board").all()
            for each_board in board_chans:
                board_chan_label = "[chan] {}".format(each_board.passphrase)

                # Join board chan if found in database and not found in BitMessage
                if board_chan_label not in chans_labels and not each_board.is_setup:
                    logger.info("Found board chan in database that needs to be joined. Joining.")
                    address = self.join_chan(each_board.passphrase, clear_inventory=False)
                    time.sleep(1)

                    if address and "Chan address is already present" in address:
                        logger.info("Board already present in BitMessage. Updating database.")
                        each_board.is_setup = True
                        new_session.commit()
                    elif address and address.startswith("BM-") and not each_board.address:
                        each_board.address = address
                        each_board.is_setup = True
                        new_session.commit()
                    else:
                        logger.info("Could not join board. Joining might be queued. Trying again later.")

                # Add address to database if address found
                elif board_chan_label in chans_labels and not each_board.is_setup:
                    logger.info("Found board chan not set up in database. Setting up.")
                    # The address column is only ever not set if there was an error while joining a chan.
                    # The chan will still be joined, but the address was unknown at the time of the error.
                    # If the passphrases match, then we can set the address in the database.
                    # The error during join has *hopefully* been fixed with the addition of locking
                    if not each_board.address:
                        each_board.address = chans_labels[board_chan_label]
                    each_board.is_setup = True
                    new_session.commit()

                if (each_board.address not in self._chan_board_dict and
                        each_board.address in chans_addresses):
                    self._chan_board_dict[each_board.address] = chans_addresses[each_board.address]

            # Join list chans if in database and not added to BitMessage
            chans_list = new_session.query(Chan).filter(Chan.type == "list").all()
            for each_list in chans_list:
                list_chan_label = "[chan] {}".format(each_list.passphrase)

                if list_chan_label not in chans_labels and not each_list.is_setup:
                    # Chan in bitmessage not in database. Add to database, generate and send list message.
                    logger.info("Found list chan in database that needs to be joined. Joining.")
                    # Join default list chan
                    address = self.join_chan(each_list.passphrase, clear_inventory=False)
                    time.sleep(1)

                    if address and "Chan address is already present" in address:
                        logger.info("List already present in bitmessage. Updating database.")
                        each_list.is_setup = True
                        new_session.commit()
                    elif address and address.startswith("BM-") and not each_list.address:
                        each_list.address = address
                        each_list.is_setup = True
                        new_session.commit()
                    else:
                        logger.info("Could not join list. Joining might be queued. Trying again later.")

                elif list_chan_label in chans_labels and not each_list.is_setup:
                    logger.info("Found list chan not set up in database. Setting up.")
                    # The address column is only ever not set if there was an
                    # error while joining a chan. The chan will still be
                    # joined, but the address was unknown at the time of the
                    # error. If the passphrases match, then we can set the
                    # address in the database.
                    if not each_list.address:
                        each_list.address = chans_labels[list_chan_label]
                    each_list.is_setup = True
                    new_session.commit()

                if (each_list.address not in self._chan_list_dict and
                        each_list.address in chans_addresses):
                    self._chan_list_dict[each_list.address] = chans_addresses[each_list.address]

    def queue_new_messages(self):
        """Add new messages to processing queue"""
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                str_messages = self._api.getAllInboxMessageIDs()
                time.sleep(0.1)
            except Exception as err:
                logger.error("Exception getting all message IDs: {}".format(err))
                return
            finally:
                lf.lock_release(config.LOCKFILE_API)
        else:
            return

        with session_scope(DB_PATH) as new_session:
            for message in str_messages['inboxMessageIds']:
                message_id = message["msgid"]

                deleted = new_session.query(DeletedMessages).filter(
                    DeletedMessages.message_id == message_id).first()
                if deleted:
                    logger.info("{}: Message labeled as deleted. Deleting.".format(
                        message_id[0:6]))
                    self.trash_message(message_id)
                    continue

                if message_id in self._non_bitchan_message_ids:
                    continue

                if (message_id in self._posts_by_id and
                        message_id not in self.list_start_download):
                    logger.debug("{}: Message already processed. return.".format(
                        message_id[0:6]))
                    continue

                message = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if message:
                    if (message_id in self.list_start_download and
                            not message.file_currently_downloading):
                        # Download instructed to start by user. Only initiate
                        # download once, and skip further processing attempts
                        # unless download has failed. Use thread to allow new
                        # messages to continue to be processed while
                        # downloading.
                        message.file_progress = "download starting"
                        message.file_currently_downloading = True
                        new_session.commit()
                        thread_download = Thread(target=self._posts_by_id[message_id].allow_download)
                        thread_download.daemon = True
                        thread_download.start()
                        continue

                    # If the server restarted while a download was underway,
                    # reset the downloading indicator when the server starts
                    # again, allowing the presentation of the Download button
                    # to the user.
                    if (message_id not in self.list_start_download and
                            message.file_currently_downloading):
                        message.file_currently_downloading = False
                        new_session.commit()

                    #
                    # Create post object
                    #
                    if message.thread and message.thread.chan:
                        to_address = message.thread.chan.address
                        logger.info("{}: Adding message to {} ({})".format(
                            message_id[0:6], to_address, message.thread.chan.label))
                        post = ChanPost(message_id)

                        if to_address not in self._board_by_chan:
                            self._board_by_chan[to_address] = ChanBoard(to_address)
                        self._posts_by_id[message_id] = post
                        chanboard = self._board_by_chan[to_address]
                        chanboard.add_post(post, message.thread.thread_hash)
                        continue

                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        str_message = self._api.getInboxMessageByID(message_id, True)
                        time.sleep(0.1)
                    except Exception as err:
                        logger.error("Exception getting message: {}".format(err))
                        continue
                    finally:
                        lf.lock_release(config.LOCKFILE_API)
                else:
                    continue

                msg_dict = str_message['inboxMessage']
                to_address = msg_dict[0]['toAddress']

                # Check if chan exists
                chan = new_session.query(Chan).filter(Chan.address == to_address).first()
                if not chan:
                    logger.info("{}: To address {} not in board or list DB. Indicative of a non-BitChan message.".format(
                        message_id[0:6], to_address))
                    if message_id not in self._non_bitchan_message_ids:
                        self._non_bitchan_message_ids.append(message_id)
                    continue

                if message_id not in self.message_threads:
                    logger.info("{}: Adding message to processing queue".format(message_id[0:6]))
                    self.message_threads[message_id] = {
                        "thread": Thread(target=self.process_message, args=(message_id, msg_dict,)),
                        "started": False,
                        "completed": False
                    }
                    self.message_threads[message_id]["thread"].setDaemon(True)
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
                logger.info("{}: Starting message processing thread".format(thread_id[0:6]))
                self.message_threads[thread_id]["thread"].start()
                threads_running += 1

    def process_message(self, message_id, msg_dict):
        """Parse a message to determine if it is valid and add it to bitchan"""
        if len(msg_dict) == 0:
            return

        with session_scope(DB_PATH) as new_session:
            message_post = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if message_post and message_post.thread and message_post.thread.chan:
                logger.info("{}: Adding message from database to chan {}".format(
                    message_id[0:6], message_post.thread.chan.address))
                post = ChanPost(message_id)

                if message_post.thread.chan.address not in self._board_by_chan:
                    self._board_by_chan[msg_dict[0]['toAddress']] = ChanBoard(
                        msg_dict[0]['toAddress'])

                self._posts_by_id[message_id] = post
                chanboard = self._board_by_chan[msg_dict[0]['toAddress']]
                chanboard.add_post(post, message_post.thread.thread_hash)
                return

        # Decode message
        message = base64.b64decode(msg_dict[0]['message']).decode()

        # Check if message is an encrypted PGP message
        if not message.startswith("-----BEGIN PGP MESSAGE-----"):
            logger.info("{}: Message doesn't appear to be PGP message. Deleting.".format(
                message_id[0:6]))
            self.trash_message(message_id)
            return

        # Decrypt the message
        # Protect against explosive PGP message size exploit
        msg_decrypted = decrypt_safe_size(message, config.PASSPHRASE_MSG, 400000)

        if msg_decrypted is not None:
            logger.info("{}: Message decrypted".format(message_id[0:6]))
            try:
                msg_decrypted_dict = json.loads(msg_decrypted)
            except:
                logger.info("{}: Malformed JSON payload. Deleting.".format(message_id[0:6]))
                self.trash_message(message_id)
                return
        else:
            logger.info("{}: Could not decrypt message. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return

        if "version" not in msg_decrypted_dict:
            logger.error("{}: 'version' not found in message. Deleting.")
            self.trash_message(message_id)
            return
        elif version_checker(config.VERSION_BITCHAN, msg_decrypted_dict["version"])[1] == "less":
            logger.info("{}: Message version greater than BitChan version. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            with session_scope(DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                settings.messages_newer += 1
                new_session.commit()
            return
        elif version_checker(msg_decrypted_dict["version"], config.VERSION_MIN_MSG)[1] == "less":
            logger.info("{}: Message version too old. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            with session_scope(DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                settings.messages_older += 1
                new_session.commit()
            return
        else:
            with session_scope(DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                settings.messages_current += 1
                new_session.commit()

        #
        # Determine the message type
        #
        if "message_type" not in msg_decrypted_dict:
            logger.info("{}: 'message_type' missing from message. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
        elif msg_decrypted_dict["message_type"] == "admin":
            self.process_admin(message_id, msg_dict, msg_decrypted_dict)
        elif msg_decrypted_dict["message_type"] == "post":
            self.process_post(message_id, msg_dict, msg_decrypted_dict)
        elif msg_decrypted_dict["message_type"] == "list":
            self.process_list(message_id, msg_dict, msg_decrypted_dict)
        else:
            logger.error("{}: Unknown message type: {}".format(
                message_id[0:6], msg_decrypted_dict["message_type"]))

    def process_admin(self, message_id, msg_dict, msg_decrypted_dict):
        """Process message as an admin command"""
        logger.info("{}: Message is an admin command".format(message_id[0:6]))

        # Authenticate sender
        with session_scope(DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(
                Chan.address == msg_dict[0]['toAddress']).first()
            if chan:
                errors, dict_info = process_passphrase(chan.passphrase)
                # Message must be from address in primary or secondary access list
                access = get_access(msg_dict[0]['toAddress'])
                if errors or (msg_dict[0]['fromAddress'] not in access["primary_addresses"] and
                              msg_dict[0]['fromAddress'] not in access["secondary_addresses"]):
                    logger.error("{}: Unauthorized Admin message. Deleting.".format(
                        message_id[0:6]))
                    self.trash_message(message_id)
                    return
            else:
                logger.error("{}: Admin message: Chan not found".format(message_id[0:6]))
                self.trash_message(message_id)
                return

        logger.info("{}: Admin message received for {} is authentic".format(
            message_id[0:6], msg_dict[0]['toAddress']))

        admin_dict = {
            "timestamp_utc": 0,
            "chan_type": None,
            "action": None,
            "action_type": None,
            "options": {},
            "thread_id": None,
            "message_id": None,
            "chan_address": None
        }

        if "timestamp_utc" in msg_decrypted_dict and msg_decrypted_dict["timestamp_utc"]:
            admin_dict["timestamp_utc"] = msg_decrypted_dict["timestamp_utc"]
        if "chan_type" in msg_decrypted_dict and msg_decrypted_dict["chan_type"]:
            admin_dict["chan_type"] = msg_decrypted_dict["chan_type"]
        if "action" in msg_decrypted_dict and msg_decrypted_dict["action"]:
            admin_dict["action"] = msg_decrypted_dict["action"]
        if "action_type" in msg_decrypted_dict and msg_decrypted_dict["action_type"]:
            admin_dict["action_type"] = msg_decrypted_dict["action_type"]
        if "options" in msg_decrypted_dict and msg_decrypted_dict["options"]:
            admin_dict["options"] = msg_decrypted_dict["options"]
        if "thread_id" in msg_decrypted_dict and msg_decrypted_dict["thread_id"]:
            admin_dict["thread_id"] = msg_decrypted_dict["thread_id"]
        if "message_id" in msg_decrypted_dict and msg_decrypted_dict["message_id"]:
            admin_dict["message_id"] = msg_decrypted_dict["message_id"]
        if "chan_address" in msg_decrypted_dict and msg_decrypted_dict["chan_address"]:
            admin_dict["chan_address"] = msg_decrypted_dict["chan_address"]

        access = get_access(msg_dict[0]['toAddress'])

        # (Owner): set board options
        if (admin_dict["action"] == "set" and
                admin_dict["action_type"] == "options" and
                msg_dict[0]['fromAddress'] in access["primary_addresses"]):
            self.admin_set_options(message_id, msg_dict, admin_dict)

        # (Owner, Admin): delete board thread or post
        elif (admin_dict["action"] == "delete" and
                admin_dict["chan_type"] == "board" and
                (msg_dict[0]['fromAddress'] in access["primary_addresses"] or
                 msg_dict[0]['fromAddress'] in access["secondary_addresses"])):
            self.admin_delete_from_board(message_id, msg_dict, admin_dict)

        # (Owner, Admin): delete board post with comment
        elif (admin_dict["action"] == "delete_comment" and
                admin_dict["action_type"] == "post" and
                "options" in admin_dict and
                "delete_comment" in admin_dict["options"] and
                "message_id" in admin_dict["options"]["delete_comment"] and
                "comment" in admin_dict["options"]["delete_comment"] and
                (msg_dict[0]['fromAddress'] in access["primary_addresses"] or
                 msg_dict[0]['fromAddress'] in access["secondary_addresses"])):
            self.admin_delete_from_board_with_comment(message_id, msg_dict, admin_dict)

        # (Owner, Admin): Ban user
        elif (admin_dict["action"] == "ban" and
                admin_dict["action_type"] == "ban_address" and
                admin_dict["options"] and
                "ban_address" in admin_dict["action_type"] and
                (msg_dict[0]['fromAddress'] in access["primary_addresses"] or
                 msg_dict[0]['fromAddress'] in access["secondary_addresses"])):
            self.admin_ban_address_from_board(message_id, msg_dict, admin_dict)

        else:
            logger.error("{}: Unknown Admin command. Deleting. {}".format(
                message_id[0:6], admin_dict))
            self.trash_message(message_id)

    def admin_set_options(self, message_id, msg_dict, admin_dict):
        """
        Set custom options for board or list
        e.g. Banner image, CSS, word replace, access
        """
        error = []

        if admin_dict["timestamp_utc"] - (60 * 60 * 6) > self.get_utc():
            # message timestamp is in the distant future. Delete.
            logger.error("{}: Command has future timestamp. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return

        if "options" not in admin_dict:
            logger.error("{}: Missing 'options' to set.".format(message_id[0:6]))
            self.trash_message(message_id)
            return

        if "banner_base64" in admin_dict["options"]:
            # Verify image is not larger than max dimensions
            im = Image.open(BytesIO(base64.b64decode(admin_dict["options"]["banner_base64"])))
            media_width, media_height = im.size
            if media_width > config.BANNER_MAX_WIDTH or media_height > config.BANNER_MAX_HEIGHT:
                logger.error("{}: Banner image too large. Discarding admin message.".format(
                    message_id[0:6]))
                self.trash_message(message_id)
                return

        if not msg_dict[0]['toAddress']:
            self.trash_message(message_id)
            return

        with session_scope(DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(
                Chan.address == msg_dict[0]['toAddress']).first()
            admin_cmd = new_session.query(Command).filter(and_(
                Command.chan_address == msg_dict[0]['toAddress'],
                Command.action == "set",
                Command.action_type == "options")).first()

            access_same = is_access_same_as_db(admin_dict["options"], chan)

            if admin_cmd:
                # Modify current entry
                admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
                options = json.loads(admin_cmd.options)

                # Set modify_admin_addresses
                if "modify_admin_addresses" in admin_dict["options"]:
                    # Check addresses
                    for each_add in admin_dict["options"]["modify_admin_addresses"]:
                        if not is_bitmessage_address(each_add):
                            error.append("Invalid admin address: {}".format(each_add))
                    # Add/Mod addresses
                    if "modify_admin_addresses_timestamp_utc" in options:
                        if admin_dict["timestamp_utc"] > options["modify_admin_addresses_timestamp_utc"]:
                            options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                            options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    else:
                        options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                        options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    # Last pass, delete entries if same as in chan db
                    if access_same["secondary_access"]:
                        options.pop('modify_admin_addresses', None)
                        options.pop('modify_admin_addresses_timestamp_utc', None)

                # Set modify_user_addresses
                if "modify_user_addresses" in admin_dict["options"]:
                    # Check addresses
                    for each_add in admin_dict["options"]["modify_user_addresses"]:
                        if not is_bitmessage_address(each_add):
                            error.append("Invalid user address: {}".format(each_add))
                    # Add/Mod addresses
                    if "modify_user_addresses_timestamp_utc" in options:
                        if admin_dict["timestamp_utc"] > options["modify_user_addresses_timestamp_utc"]:
                            options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                            options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    else:
                        options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                        options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    # Last pass, delete entries if same as in chan db
                    if access_same["tertiary_access"]:
                        options.pop('modify_user_addresses', None)
                        options.pop('modify_user_addresses_timestamp_utc', None)

                # Set modify_restricted_addresses
                if "modify_restricted_addresses" in admin_dict["options"]:
                    # Check addresses
                    for each_add in admin_dict["options"]["modify_restricted_addresses"]:
                        if not is_bitmessage_address(each_add):
                            error.append("Invalid restricted address: {}".format(each_add))
                    # Add/Mod addresses
                    if "modify_restricted_addresses_timestamp_utc" in options:
                        if admin_dict["timestamp_utc"] > options["modify_restricted_addresses_timestamp_utc"]:
                            options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                            options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    else:
                        options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                        options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    # Last pass, delete entries if same as in chan db
                    if access_same["restricted_access"]:
                        options.pop('modify_restricted_addresses', None)
                        options.pop('modify_restricted_addresses_timestamp_utc', None)

                # Set banner
                if "banner_base64" in admin_dict["options"]:
                    if "banner_base64_timestamp_utc" in options:
                        if admin_dict["timestamp_utc"] > options["banner_base64_timestamp_utc"]:
                            options["banner_base64"] = admin_dict["options"]["banner_base64"]
                            options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]
                    else:
                        options["banner_base64"] = admin_dict["options"]["banner_base64"]
                        options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]

                # Set CSS
                if "css" in admin_dict["options"]:
                    if "css_timestamp_utc" in options:
                        if admin_dict["timestamp_utc"] > options["css_timestamp_utc"]:
                            options["css"] = admin_dict["options"]["css"]
                            options["css_timestamp_utc"] = admin_dict["timestamp_utc"]
                    else:
                        options["css"] = admin_dict["options"]["css"]
                        options["css_timestamp_utc"] = admin_dict["timestamp_utc"]

                # Set word replace
                if "word_replace" in admin_dict["options"]:
                    if "word_replace_timestamp_utc" in options:
                        if admin_dict["timestamp_utc"] > options["word_replace_timestamp_utc"]:
                            options["word_replace"] = admin_dict["options"]["word_replace"]
                            options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]
                    else:
                        options["word_replace"] = admin_dict["options"]["word_replace"]
                        options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]

                if error:
                    pass
                elif json.dumps(options) == admin_cmd.options:
                    error.append("Options same as in DB. Not updating.")
                else:
                    admin_cmd.options = json.dumps(options)
            else:
                # Create new entry
                admin_cmd = Command()
                admin_cmd.chan_address = msg_dict[0]['toAddress']
                admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
                admin_cmd.action = "set"
                admin_cmd.action_type = "options"
                options = {}

                if ("modify_admin_addresses" in admin_dict["options"] and
                        not access_same["secondary_access"]):
                    # Check addresses
                    for each_add in admin_dict["options"]["modify_admin_addresses"]:
                        if not is_bitmessage_address(each_add):
                            error.append("Invalid admin address: {}".format(each_add))
                    options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                    options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]

                if ("modify_user_addresses" in admin_dict["options"] and
                        not access_same["tertiary_access"]):
                    # Check addresses
                    for each_add in admin_dict["options"]["modify_user_addresses"]:
                        if not is_bitmessage_address(each_add):
                            error.append("Invalid user address: {}".format(each_add))
                    options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                    options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]

                if ("modify_restricted_addresses" in admin_dict["options"] and
                        not access_same["restricted_access"]):
                    # Check addresses
                    for each_add in admin_dict["options"]["modify_restricted_addresses"]:
                        if not is_bitmessage_address(each_add):
                            error.append("Invalid restricted address: {}".format(each_add))
                    options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                    options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]

                if "banner_base64" in admin_dict["options"]:
                    options["banner_base64"] = admin_dict["options"]["banner_base64"]
                    options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]

                if "css" in admin_dict["options"]:
                    options["css"] = admin_dict["options"]["css"]
                    options["css_timestamp_utc"] = admin_dict["timestamp_utc"]

                if "word_replace" in admin_dict["options"]:
                    options["word_replace"] = admin_dict["options"]["word_replace"]
                    options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]

                if options:
                    admin_cmd.options = json.dumps(options)
                else:
                    error.append("No valid options received. Not saving.")
                if not error:
                    new_session.add(admin_cmd)

            if error:
                logger.info("{}: Errors found while processing custom options for {}".format(
                    message_id[0:6], msg_dict[0]['toAddress']))
                for err in error:
                    logger.error("{}: {}".format(message_id[0:6], err))
            else:
                logger.info("{}: Setting custom options for {}".format(
                    message_id[0:6], msg_dict[0]['toAddress']))
                new_session.commit()

        self.trash_message(message_id)

    def admin_delete_from_board(self, message_id, msg_dict, admin_dict):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
            try:
                logger.error("{}: Admin message contains delete request".format(
                    message_id[0:6]))
                with session_scope(DB_PATH) as new_session:
                    # Check if command already exists
                    commands = new_session.query(Command).filter(and_(
                        Command.chan_address == msg_dict[0]['toAddress'],
                        Command.action == "delete",
                        Command.action_type == "delete_post")).all()
                    command_exists = False
                    for each_cmd in commands:
                        try:
                            options = json.loads(each_cmd.options)
                        except:
                            options = {}
                        if (
                                ("delete_post" in options and
                                 "message_id" in options["delete_post"] and
                                 options["delete_post"]["message_id"] == admin_dict["options"]["delete_post"]["message_id"]) or

                                ("delete_thread" in options and
                                 "message_id" in options["delete_thread"] and
                                 "thread_id" in options["delete_thread"] and
                                 options["delete_thread"]["message_id"] == admin_dict["options"]["delete_thread"]["message_id"] and
                                 options["delete_thread"]["thread_id"] == admin_dict["options"]["delete_thread"]["thread_id"])
                                ):
                            command_exists = True
                            if "delete_thread" in options:
                                options["delete_thread_timestamp_utc"] = self.get_utc()
                            elif "delete_post" in options:
                                options["delete_post_timestamp_utc"] = self.get_utc()
                            each_cmd.options = json.dumps(options)
                            logger.error("{}: Admin command already exists. Updating.".format(
                                message_id[0:6]))

                    if not command_exists:
                        new_admin = Command()
                        new_admin.action = admin_dict["action"]
                        new_admin.action_type = admin_dict["action_type"]

                        if (admin_dict["action_type"] == "delete_post" and
                                "delete_post" in admin_dict["options"] and
                                "thread_id" in admin_dict["options"]["delete_post"] and
                                "message_id" in admin_dict["options"]["delete_post"]):
                            new_admin.chan_address = msg_dict[0]['toAddress']
                            new_admin.options = json.dumps({
                                "delete_post": {
                                    "thread_id": admin_dict["options"]["delete_post"]["thread_id"],
                                    "message_id": admin_dict["options"]["delete_post"]["message_id"]
                                },
                                "delete_post_timestamp_utc": self.get_utc()
                            })
                        elif (admin_dict["action_type"] == "delete_thread" and
                                "delete_thread" in admin_dict["options"] and
                                "thread_id" in admin_dict["options"]["delete_thread"] and
                                "message_id" in admin_dict["options"]["delete_thread"]):
                            new_admin.chan_address = msg_dict[0]['toAddress']
                            new_admin.options = json.dumps({
                                "delete_thread": {
                                    "thread_id": admin_dict["options"]["delete_thread"]["thread_id"],
                                    "message_id": admin_dict["options"]["delete_thread"]["message_id"]
                                },
                                "delete_thread_timestamp_utc": self.get_utc()
                            })
                        else:
                            logger.error("{}: Unknown admin action type: {}".format(
                                message_id[0:6], admin_dict["action_type"]))
                            self.trash_message(message_id)
                            return
                        new_session.add(new_admin)
                        new_session.commit()

                # Find if thread/post exist and delete
                if msg_dict[0]['toAddress']:
                    with session_scope(DB_PATH) as new_session:
                        admin_chan = new_session.query(Chan).filter(
                            Chan.address == msg_dict[0]['toAddress']).first()
                        if not admin_chan:
                            logger.error("{}: Unknown board in Admin message. Discarding.".format(message_id[0:6]))
                            self.trash_message(message_id)
                            return

                    logger.error("{}: Admin message board found".format(message_id[0:6]))

                    # Admin: Delete post
                    if (admin_dict["action_type"] == "delete_post" and
                            "delete_post" in admin_dict["options"] and
                            "thread_id" in admin_dict["options"]["delete_post"] and
                            "message_id" in admin_dict["options"]["delete_post"]):
                        logger.error("{}: Admin message to delete post {}".format(
                            message_id[0:6], admin_dict["options"]["delete_post"]["message_id"]))
                        delete_db_message(admin_dict["options"]["delete_post"]["message_id"])
                        try:
                            self.delete_message(
                                msg_dict[0]['toAddress'],
                                admin_dict["options"]["delete_post"]["thread_id"],
                                admin_dict["options"]["delete_post"]["message_id"])
                        except:
                            pass

                    # Admin: Delete thread
                    elif (admin_dict["action_type"] == "delete_thread" and
                          "delete_thread" in admin_dict["options"] and
                          "thread_id" in admin_dict["options"]["delete_thread"] and
                          "message_id" in admin_dict["options"]["delete_thread"]):
                        logger.error("{}: Admin message to delete thread {}".format(
                            message_id[0:6], admin_dict["options"]["delete_thread"]["thread_id"]))
                        # Delete all messages in thread
                        messages = new_session.query(Messages).filter(
                            Messages.thread_id == admin_dict["options"]["delete_thread"]["thread_id"]).all()
                        for message in messages:
                            delete_db_message(message.message_id)
                        # Delete the thread
                        thread = new_session.query(Threads).filter(
                            Threads.thread_hash == admin_dict["options"]["delete_thread"]["thread_id"]).first()
                        if thread:
                            new_session.delete(thread)
                            new_session.commit()
                        try:
                            self.delete_thread(
                                msg_dict[0]['toAddress'],
                                admin_dict["options"]["delete_thread"]["thread_id"])
                        except:
                            pass
                    self.trash_message(message_id)
            finally:
                lf.lock_release(config.LOCKFILE_MSG_PROC)

    def admin_delete_from_board_with_comment(self, message_id, msg_dict, admin_dict):
        """Delete a post with comment (really just replace the message and removes attachments)"""
        try:
            logger.error("{}: Admin message contains delete with comment request".format(
                message_id[0:6]))
            with session_scope(DB_PATH) as new_session:
                # Find if thread/post exist and delete
                admin_chan = new_session.query(Chan).filter(
                    Chan.address == msg_dict[0]['toAddress']).first()
                if not admin_chan:
                    logger.error("{}: Unknown board in Admin message. Discarding.".format(message_id[0:6]))
                    self.trash_message(message_id)
                    return

                # Check if command already exists
                commands = new_session.query(Command).filter(and_(
                    Command.chan_address == msg_dict[0]['toAddress'],
                    Command.action == "delete_comment",
                    Command.action_type == "post")).all()
                command_exists = False
                for each_cmd in commands:
                    try:
                        options = json.loads(each_cmd.options)
                    except:
                        options = {}
                    if ("delete_comment" in options and
                            "message_id" in options["delete_comment"] and
                            "comment" in options["delete_comment"] and
                            options["delete_comment"]["message_id"] == admin_dict["options"]["delete_comment"]["message_id"]):
                        command_exists = True
                        options["delete_comment_timestamp_utc"] = self.get_utc()
                        each_cmd.options = json.dumps(options)
                        logger.error("{}: Admin command already exists. Updating.".format(
                            message_id[0:6]))

                if not command_exists:
                    new_admin = Command()
                    new_admin.action = admin_dict["action"]
                    new_admin.action_type = admin_dict["action_type"]
                    new_admin.chan_address = msg_dict[0]['toAddress']
                    new_admin.options = json.dumps({
                        "delete_comment": {
                            "comment": admin_dict["options"]["delete_comment"]["comment"],
                            "message_id": admin_dict["options"]["delete_comment"]["message_id"]
                        },
                        "delete_comment_timestamp_utc": self.get_utc()
                    })
                    new_session.add(new_admin)
                    new_session.commit()

                if (admin_dict["options"]["delete_comment"]["message_id"] and
                        admin_dict["options"]["delete_comment"]["comment"]):
                    logger.error("{}: Admin message to delete post {} with comment".format(
                        message_id[0:6], admin_dict["options"]["delete_comment"]["message_id"]))
                    delete_and_replace_comment(
                        admin_dict["options"]["delete_comment"]["message_id"],
                        admin_dict["options"]["delete_comment"]["comment"])
        finally:
            self.trash_message(message_id)

    def admin_ban_address_from_board(self, message_id, msg_dict, admin_dict):
        if admin_dict["options"]["ban_address"] in self._identity_dict:
            # Don't ban yourself, fool
            self.trash_message(message_id)
            return

        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
            try:
                logger.error("{}: Admin message contains ban request".format(
                    message_id[0:6]))
                with session_scope(DB_PATH) as new_session:
                    # Check if admin entry already exists
                    command_exists = False
                    commands = new_session.query(Command).filter(and_(
                        Command.action == admin_dict["action"],
                        Command.action_type == admin_dict["action_type"],
                        Command.chan_address == admin_dict["chan_address"])).all()
                    for each_cmd in commands:
                        try:
                            options = json.loads(each_cmd.options)
                        except:
                            options = {}
                        if ("ban_address" in options and
                                admin_dict["options"]["ban_address"] == options["ban_address"]):
                            logger.error("{}: Ban already exists in database. Updating".format(
                                message_id[0:6]))
                            options["ban_address_timestamp_utc"] = admin_dict["timestamp_utc"]
                            each_cmd.options = json.dumps(options)
                            command_exists = True

                    if not command_exists:
                        logger.error("{}: Adding ban to database".format(message_id[0:6]))
                        new_admin = Command()
                        new_admin.action = admin_dict["action"]
                        new_admin.action_type = admin_dict["action_type"]
                        new_admin.chan_address = admin_dict["chan_address"]
                        options = {
                            "ban_address": admin_dict["options"]["ban_address"],
                            "ban_address_timestamp_utc": self.get_utc()
                        }
                        new_admin.options = json.dumps(options)
                        new_session.add(new_admin)
                        new_session.commit()

                # Find messages and delete
                with session_scope(DB_PATH) as new_session:
                    messages = new_session.query(Messages).filter(
                        Messages.address_from == admin_dict["options"]["ban_address"]).all()
                    if messages:
                        # Admin: Delete post
                        for each_message in messages:
                            if each_message.thread.chan.address == admin_dict["chan_address"]:
                                delete_db_message(each_message.message_id)
                self.trash_message(message_id)
            finally:
                lf.lock_release(config.LOCKFILE_MSG_PROC)

    def process_post(self, message_id, msg_dict, msg_decrypted_dict):
        """Process message as a post to a board"""
        logger.info("{}: Message is a post".format(message_id[0:6]))

        # Determine if board is public and requires an Identity to post
        with session_scope(DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(and_(
                Chan.access == "public",
                Chan.type == "board",
                Chan.address == msg_dict[0]['toAddress'])).first()
            if chan:
                try:
                    rules = json.loads(chan.rules)
                except:
                    rules = {}
                if ("require_identity_to_post" in rules and
                        rules["require_identity_to_post"] and
                        msg_dict[0]['toAddress'] == msg_dict[0]['fromAddress']):
                    # From address is not different from board address
                    logger.info(
                        "{}: Message is from its own board's address {} but requires a "
                        "non-board address to post. Deleting.".format(
                            message_id[0:6], msg_dict[0]['fromAddress']))
                    self.trash_message(message_id)
                    return

        # Determine if there is a current ban in place for an address
        # If so, delete message and don't process it
        with session_scope(DB_PATH) as new_session:
            admin_bans = new_session.query(Command).filter(and_(
                Command.action == "ban",
                Command.action_type == "ban_address",
                Command.chan_address == msg_dict[0]['toAddress'])).all()
            for each_ban in admin_bans:
                try:
                    options = json.loads(each_ban.options)
                except:
                    options = {}
                if ("ban_address" in options and
                        options["ban_address"] == msg_dict[0]['fromAddress'] and
                        msg_dict[0]['fromAddress'] not in self._identity_dict):
                    # If there is a ban and the banned user isn't yourself, delete post
                    logger.info("{}: Message is from address {} that's banned from board {}. Deleting.".format(
                        message_id[0:6], msg_dict[0]['fromAddress'], msg_dict[0]['toAddress']))
                    self.trash_message(message_id)
                    return

        # Determine if there is a current block in place for an address
        # If so, delete message and don't process it
        # Note: only affects your local system, not other users
        with session_scope(DB_PATH) as new_session:
            blocks = new_session.query(Command).filter(and_(
                Command.action == "block",
                Command.do_not_send == True,
                Command.action_type == "block_address",
                or_(Command.chan_address == msg_dict[0]['toAddress'],
                    Command.chan_address == "all"))).all()
            for each_block in blocks:
                try:
                    options = json.loads(each_block.options)
                except:
                    options = {}
                if ("block_address" in options and
                        options["block_address"] == msg_dict[0]['fromAddress'] and
                        each_block.chan_address in [msg_dict[0]['toAddress'], "all"] and
                        msg_dict[0]['fromAddress'] not in self._identity_dict):
                    # If there is a block and the blocked user isn't yourself, delete post
                    logger.info("{}: Message is from address {} that's blocked from board {}. Deleting.".format(
                        message_id[0:6], msg_dict[0]['fromAddress'], msg_dict[0]['toAddress']))
                    self.trash_message(message_id)
                    return

        # Determine if board is public and the sender is restricted from posting
        with session_scope(DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(and_(
                Chan.access == "public",
                Chan.type == "board",
                Chan.address == msg_dict[0]['toAddress'])).first()
            if chan:
                # Check if sender in restricted list
                access = get_access(msg_dict[0]['toAddress'])
                if msg_dict[0]['fromAddress'] in access["restricted_addresses"]:
                    logger.info("{}: Post from restricted sender: {}. Deleting.".format(
                        message_id[0:6], msg_dict[0]['fromAddress']))
                    self.trash_message(message_id)
                    return
                else:
                    logger.info("{}: Post from unrestricted sender: {}".format(
                        message_id[0:6], msg_dict[0]['fromAddress']))

        # Determine if board is private and the sender is allowed to send to the board
        with session_scope(DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(and_(
                Chan.access == "private",
                Chan.type == "board",
                Chan.address == msg_dict[0]['toAddress'])).first()
            if chan:
                errors, dict_info = process_passphrase(chan.passphrase)
                # Sender must be in at least one address list
                access = get_access(msg_dict[0]['toAddress'])
                if (msg_dict[0]['fromAddress'] not in
                        access["primary_addresses"] +
                        access["secondary_addresses"] +
                        access["tertiary_addresses"]):
                    logger.info("{}: Post from unauthorized sender: {}. Deleting.".format(
                        message_id[0:6], msg_dict[0]['fromAddress']))
                    self.trash_message(message_id)
                    return
                else:
                    logger.info("{}: Post from authorized sender: {}".format(
                        message_id[0:6], msg_dict[0]['fromAddress']))

        # Pre-processing checks passed. Continue processing message.
        with session_scope(DB_PATH) as new_session:
            if msg_decrypted_dict["message"]:
                # Remove any potentially malicious HTML in received message text
                # before saving it to the database or presenting it to the user
                msg_decrypted_dict["message"] = html.escape(msg_decrypted_dict["message"])

                # perform admin command word replacements
                try:
                    admin_cmd = new_session.query(Command).filter(and_(
                        Command.chan_address == msg_dict[0]['toAddress'],
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
                    logger.error("Could not complete admin command word replacements: {}".format(err))

                # Perform general text replacements/modifications before saving to the database
                try:
                    msg_decrypted_dict["message"] = process_replacements(
                        msg_decrypted_dict["message"], message_id, message_id)
                except Exception as err:
                    logger.exception("Error processing replacements: {}".format(err))

            msg_dict[0]['message_decrypted'] = msg_decrypted_dict

            #
            # Save message to database
            #
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if not message:
                logger.info("{}: Message not in DB. Start processing.".format(message_id[0:6]))
                self.parse_message(message_id, msg_dict[0])

            # Check if message was created by parse_message()
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if not message:
                logger.error("{}: Message not created. Don't create post object.".format(message_id[0:6]))
                return
            elif not message.thread or not message.thread.chan:
                # Chan or thread doesn't exist, delete thread and message
                if message.thread:
                    new_session.delete(message.thread)
                if message:
                    new_session.delete(message)
                new_session.commit()
                logger.error("{}: Thread or board doesn't exist. Deleting DB entries.".format(message_id[0:6]))
                return

            #
            # Create post object
            #
            logger.info("{}: Adding post to chan {}".format(message_id[0:6], msg_dict[0]['toAddress']))
            post = ChanPost(message_id)

            if msg_dict[0]['toAddress'] not in self._board_by_chan:
                self._board_by_chan[msg_dict[0]['toAddress']] = ChanBoard(msg_dict[0]['toAddress'])
            self._posts_by_id[message_id] = post
            chan_board = self._board_by_chan[msg_dict[0]['toAddress']]
            chan_board.add_post(post, message.thread.thread_hash)

    def process_list(self, message_id, msg_dict, msg_decrypted_dict):
        """Process message as a list"""
        logger.info("{}: Message is a list".format(message_id[0:6]))

        # Check integrity of message
        required_keys = ["version", "timestamp_utc", "access", "list"]
        integrity_pass = True

        for each_key in required_keys:
            if each_key not in msg_decrypted_dict:
                logger.error("{}: List message missing '{}'".format(
                    message_id[0:6], each_key))
                integrity_pass = False

        for each_chan in msg_decrypted_dict["list"]:
            if "passphrase" not in msg_decrypted_dict["list"][each_chan]:
                logger.error("{}: Entry in list missing 'passphrase'".format(message_id[0:6]))
                integrity_pass = False
                continue

            errors, dict_info = process_passphrase(msg_decrypted_dict["list"][each_chan]["passphrase"])
            if not dict_info or errors:
                logger.error("{}: List passphrase did not pass integrity check: {}".format(
                    message_id[0:6], msg_decrypted_dict["list"][each_chan]["passphrase"]))
                for err in errors:
                    logger.error(err)
                integrity_pass = False

        if not integrity_pass:
            logger.error("{}: List message failed integrity test: {}".format(message_id[0:6], msg_decrypted_dict))
            self.trash_message(message_id)
            return

        if msg_decrypted_dict["timestamp_utc"] - (60 * 60 * 3) > self.get_utc():
            # message timestamp is in the distant future. Delete.
            logger.info("{}: List message has future timestamp. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return

        log_age_and_expiration(
            message_id,
            self.get_utc(),
            msg_decrypted_dict["timestamp_utc"],
            get_msg_expires_time(message_id))

        if (msg_decrypted_dict["timestamp_utc"] < self.get_utc() and
                ((self.get_utc() - msg_decrypted_dict["timestamp_utc"]) / 60 / 60 / 24) > 28):
            # message timestamp is too old. Delete.
            logger.info("{}: List message is supposedly older than 28 days. Deleting.".format(
                message_id[0:6]))
            self.trash_message(message_id)
            return

        # Check if board is set to automatically clear and message is older than the last clearing
        if chan_auto_clears_and_message_too_old(
                msg_dict[0]['toAddress'], msg_decrypted_dict["timestamp_utc"]):
            logger.info("{}: Message outside current auto clear period. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return

        logger.info("{}: List message passed integrity test".format(message_id[0:6]))
        if msg_dict[0]['toAddress'] not in self._list_by_chan:
            self._list_by_chan[msg_dict[0]['toAddress']] = ChanList(msg_dict[0]['toAddress'])

        chan_list = self._list_by_chan[msg_dict[0]['toAddress']]
        chan_list.add_to_list(msg_decrypted_dict)

        with session_scope(DB_PATH) as new_session:
            list_chan = new_session.query(Chan).filter(and_(
                Chan.type == "list",
                Chan.address == msg_dict[0]['toAddress'])).first()

            if not list_chan:
                return

            # Check if sending address is in primary or secondary address list
            access = get_access(msg_dict[0]['toAddress'])
            sender_is_primary = False
            sender_is_secondary = False
            sender_is_tertiary = False
            sender_is_restricted = False
            if msg_dict[0]['fromAddress'] in access["primary_addresses"]:
                sender_is_primary = True
            if msg_dict[0]['fromAddress'] in access["secondary_addresses"]:
                sender_is_secondary = True
            if msg_dict[0]['fromAddress'] in access["tertiary_addresses"]:
                sender_is_tertiary = True
            if msg_dict[0]['fromAddress'] in access["restricted_addresses"]:
                sender_is_restricted = True

            # Check if address restricted
            if list_chan.access == "public" and sender_is_restricted:
                logger.info("{}: List from restricted sender: {}. Deleting.".format(
                    message_id[0:6], msg_dict[0]['fromAddress']))
                self.trash_message(message_id)
                return

            # Check if rule prevents sending from own address
            try:
                rules = json.loads(list_chan.rules)
            except:
                rules = {}
            if ("require_identity_to_post" in rules and
                    rules["require_identity_to_post"] and
                    msg_dict[0]['toAddress'] == msg_dict[0]['fromAddress']):
                # From address is not different from list address
                logger.info(
                    "{}: List is from its own address {} but requires a "
                    "non-list address to post. Deleting.".format(
                        message_id[0:6], msg_dict[0]['fromAddress']))
                self.trash_message(message_id)
                return

            if list_chan.access == "public":

                if sender_is_primary or sender_is_secondary:
                    # store latest list timestamp from primary/secondary addresses
                    if (list_chan.list_message_timestamp_utc_owner and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_owner):
                        # message timestamp is older than what's in the database
                        logger.info("{}: Owner/Admin of public list message older than DB timestamp. Deleting.".format(
                            message_id[0:6]))
                        self.trash_message(message_id)
                        return
                    else:
                        logger.info("{}: Owner/Admin of public list message newer than DB timestamp. Updating.".format(
                            message_id[0:6]))
                        list_chan.list_message_id_owner = message_id
                        list_chan.list_message_expires_time_owner = get_msg_expires_time(message_id)
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
                            logger.info("{}: Setting user timestamp/expires_time to that of Owner/Admin.".format(
                                message_id[0:6]))
                            list_chan.list_message_id_user = message_id
                            list_chan.list_message_expires_time_user = get_msg_expires_time(message_id)
                            list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                    logger.info(
                        "{}: List {} is public and From address {} "
                        "in primary or secondary access list. Replacing entire list.".format(
                            message_id[0:6], msg_dict[0]['toAddress'], msg_dict[0]['fromAddress']))
                    list_chan.list = json.dumps(msg_decrypted_dict["list"])
                else:
                    # store latest list timestamp from tertiary addresses
                    if (list_chan.list_message_timestamp_utc_user and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_user):
                        # message timestamp is older than what's in the database
                        logger.info("{}: User list message older than DB timestamp. Deleting.".format(
                            message_id[0:6]))
                        self.trash_message(message_id)
                        return
                    else:
                        logger.info("{}: User list message newer than DB timestamp. Updating.".format(
                            message_id[0:6]))
                        list_chan.list_message_id_user = message_id
                        list_chan.list_message_expires_time_user = get_msg_expires_time(message_id)
                        list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                    try:
                        dict_chan_list = json.loads(list_chan.list)
                    except:
                        dict_chan_list = {}
                    logger.info("{}: List {} is public, adding addresses to list".format(
                        message_id[0:6], msg_dict[0]['toAddress']))
                    for each_address in msg_decrypted_dict["list"]:
                        if each_address not in dict_chan_list:
                            logger.info("{}: Adding {} to list".format(message_id[0:6], each_address))
                            dict_chan_list[each_address] = msg_decrypted_dict["list"][each_address]
                        else:
                            logger.info("{}: {} already in list".format(message_id[0:6], each_address))
                    list_chan.list = json.dumps(dict_chan_list)

                new_session.commit()

            elif list_chan.access == "private":
                # Check if private list by checking if any identities match From address
                if not sender_is_primary and not sender_is_secondary and not sender_is_tertiary:
                    logger.error(
                        "{}: List {} is private but From address {} not in primary, secondary, or tertiary access list".format(
                            message_id[0:6], msg_dict[0]['toAddress'], msg_dict[0]['fromAddress']))

                elif sender_is_primary or sender_is_secondary:
                    # store latest list timestamp from primary/secondary addresses
                    if (list_chan.list_message_timestamp_utc_owner and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_owner):
                        # message timestamp is older than what's in the database
                        logger.info("{}: Owner/Admin of private list message older than DB timestamp. Deleting.".format(
                            message_id[0:6]))
                        self.trash_message(message_id)
                        return
                    else:
                        logger.info("{}: Owner/Admin of private list message newer than DB timestamp. Updating.".format(
                            message_id[0:6]))
                        list_chan.list_message_id_owner = message_id
                        list_chan.list_message_expires_time_owner = get_msg_expires_time(message_id)
                        list_chan.list_message_timestamp_utc_owner = msg_decrypted_dict["timestamp_utc"]

                    logger.info(
                        "{}: List {} is private and From address {} "
                        "in primary or secondary access list. Replacing entire list.".format(
                            message_id[0:6], msg_dict[0]['toAddress'], msg_dict[0]['fromAddress']))
                    list_chan = new_session.query(Chan).filter(
                        Chan.address == msg_dict[0]['toAddress']).first()
                    list_chan.list = json.dumps(msg_decrypted_dict["list"])

                elif sender_is_tertiary:
                    # store latest list timestamp from tertiary addresses
                    if (list_chan.list_message_timestamp_utc_user and
                            msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_user):
                        # message timestamp is older than what's in the database
                        logger.info("{}: User list message older than DB timestamp. Deleting.".format(
                            message_id[0:6]))
                        self.trash_message(message_id)
                        return
                    else:
                        logger.info("{}: User list message newer than DB timestamp. Updating.".format(
                            message_id[0:6]))
                        list_chan.list_message_id_user = message_id
                        list_chan.list_message_expires_time_user = get_msg_expires_time(message_id)
                        list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                    logger.info(
                        "{}: List {} is private and From address {} "
                        "in tertiary access list. Adding addresses to list.".format(
                            message_id[0:6], msg_dict[0]['toAddress'], msg_dict[0]['fromAddress']))
                    try:
                        dict_chan_list = json.loads(list_chan.list)
                    except:
                        dict_chan_list = {}
                    for each_address in msg_decrypted_dict["list"]:
                        if each_address not in dict_chan_list:
                            logger.info("{}: Adding {} to list".format(message_id[0:6], each_address))
                            dict_chan_list[each_address] = msg_decrypted_dict["list"][each_address]
                        else:
                            logger.info("{}: {} already in list".format(message_id[0:6], each_address))
                    list_chan.list = json.dumps(dict_chan_list)

                new_session.commit()

        self.trash_message(message_id)

    def parse_message(self, message_id, json_obj):
        file_decoded = None
        file_filename = None
        file_extension = None
        file_url_type = None
        file_url = None
        file_extracts_start_base64 = None
        file_size = None
        file_md5_hash = None
        file_md5_hashes_match = False
        file_download_successful = False
        upload_filename = None
        saved_file_filename = None
        saved_image_thumb_filename = None
        media_width = None
        media_height = None
        image_spoiler = None
        op_md5_hash = None
        message = None
        nation = None
        message_steg = None
        file_do_not_download = False
        file_path = None
        img_thumb_filename = None

        dict_msg = json_obj['message_decrypted']

        # MD5 hash of the original encrypted message payload to identify the OP of the thread.
        # Each reply must identify the thread it's replying to by supplying the OP hash.
        # If the OP hash doesn't exist, a new thread is created.
        # This prevents OP hijacking by impersonating an OP with an earlier send timestamp.
        message_md5_hash = hashlib.md5(json.dumps(json_obj['message']).encode('utf-8')).hexdigest()
        # logger.info("Message MD5: {}".format(message_md5_hash))

        # Check if message properly formatted, delete if not.
        if "subject" not in dict_msg or not dict_msg["subject"]:
            logger.error("{}: Message missing required subject. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return
        else:
            subject = html.escape(base64.b64decode(dict_msg["subject"]).decode('utf-8')).strip()
            if len(subject) > 64:
                logger.error("{}: Subject too large. Deleting".format(message_id[0:6]))
                self.trash_message(message_id)
                return

        if "version" not in dict_msg or not dict_msg["version"]:
            logger.error("{}: Message has no version. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return
        else:
            version = dict_msg["version"]

        # logger.info("dict_msg: {}".format(dict_msg))

        # Determine if message indicates if it's OP or not
        if "is_op" in dict_msg and dict_msg["is_op"]:
            is_op = dict_msg["is_op"]
        else:
            is_op = False

        # Determine if message indicates if it's a reply to an OP by supplying OP hash
        if "op_md5_hash" in dict_msg and dict_msg["op_md5_hash"]:
            op_md5_hash = dict_msg["op_md5_hash"]

        # Determine if message is an OP or a reply
        if is_op:
            thread_id = get_thread_id(message_md5_hash)
        elif op_md5_hash:
            thread_id = get_thread_id(op_md5_hash)
        else:
            logger.error("{}: Message neither OP nor reply: Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return

        # Now that the thread_is id determined, check if there exists an Admin command
        # instructing the deletion of the thread/message
        with session_scope(DB_PATH) as new_session:
            admin_post_delete = new_session.query(Command).filter(and_(
                Command.action == "delete",
                Command.action_type == "post",
                Command.chan_address == json_obj['toAddress'],
                Command.thread_id == thread_id,
                Command.message_id == message_id)).first()

            admin_thread_delete = new_session.query(Command).filter(and_(
                Command.action == "delete",
                Command.action_type == "thread",
                Command.chan_address == json_obj['toAddress'],
                Command.thread_id == thread_id)).first()

            if admin_post_delete or admin_thread_delete:
                logger.error("{}: Admin deleted this post or thread".format(message_id[0:6]))
                self.trash_message(message_id)
                return

        if ("timestamp_utc" in dict_msg and dict_msg["timestamp_utc"] and
                isinstance(dict_msg["timestamp_utc"], int)):
            timestamp_sent = dict_msg["timestamp_utc"]
        else:
            timestamp_sent = int(json_obj['receivedTime'])

        log_age_and_expiration(
            message_id,
            self.get_utc(),
            timestamp_sent,
            get_msg_expires_time(message_id))

        # Check if board is set to automatically clear and message is older than the last clearing
        if chan_auto_clears_and_message_too_old(json_obj['toAddress'], timestamp_sent):
            logger.info("{}: Message outside current auto clear period. Deleting.".format(message_id[0:6]))
            self.trash_message(message_id)
            return

        if "message" in dict_msg and dict_msg["message"]:
            message = dict_msg["message"]
        if "file_filename" in dict_msg and dict_msg["file_filename"]:
            file_filename = dict_msg["file_filename"]
            logger.info("{} Filename on post: {}".format(message_id[0:6], dict_msg["file_filename"]))
        if "nation" in dict_msg and dict_msg["nation"]:
            nation = dict_msg["nation"]
        if "media_width" in dict_msg and dict_msg["media_width"]:
            media_width = dict_msg["media_width"]
        if "media_height" in dict_msg and dict_msg["media_height"]:
            media_height = dict_msg["media_height"]
        if "image_spoiler" in dict_msg and dict_msg["image_spoiler"]:
            image_spoiler = dict_msg["image_spoiler"]
        if "upload_filename" in dict_msg and dict_msg["upload_filename"]:
            upload_filename = dict_msg["upload_filename"]
        if "file_url_type" in dict_msg and dict_msg["file_url_type"]:
            file_url_type = dict_msg["file_url_type"]
        if "file_extension" in dict_msg and dict_msg["file_extension"]:
            file_extension = dict_msg["file_extension"]
        if "file_extracts_start_base64" in dict_msg and dict_msg["file_extracts_start_base64"] is not None:
            file_extracts_start_base64 = json.loads(dict_msg["file_extracts_start_base64"])
        if "file_base64" in dict_msg and dict_msg["file_base64"] is not None:
            try:
                file_decoded = base64.b64decode(dict_msg["file_base64"])
                file_size = len(file_decoded)
            except Exception as err:
                logger.exception("{}: Exception decoding image: {}".format(message_id[0:6], err))
        if "file_md5_hash" in dict_msg and dict_msg["file_md5_hash"]:
            file_md5_hash = dict_msg["file_md5_hash"]

        if "file_url" in dict_msg and dict_msg["file_url"]:
            file_url = dict_msg["file_url"]
            if not file_extension:
                logger.error("{}: File extension not found. Deleting.".format(message_id[0:6]))
                self.trash_message(message_id)
                return
            elif len(file_extension) > 6:
                logger.error("{}: File extension greater than 6 characters. Deleting.".format(message_id[0:6]))
                self.trash_message(message_id)
                return
            if file_extension:
                saved_file_filename = "{}.{}".format(message_id, file_extension)
            file_path = "{}/{}".format(
                config.FILE_DIRECTORY, saved_file_filename)
            if file_extension in config.FILE_EXTENSIONS_IMAGE:
                saved_image_thumb_filename = "{}_thumb.{}".format(message_id, file_extension)
                img_thumb_filename = "{}/{}".format(config.FILE_DIRECTORY, saved_image_thumb_filename)

            logger.info("{}: Filename on disk: {}".format(message_id[0:6], saved_file_filename))

            if os.path.exists(file_path) and os.path.getsize(file_path) != 0:
                logger.info("{}: Downloaded file found. Not attempting to download.".format(message_id[0:6]))
                file_size = os.path.getsize(file_path)
                file_download_successful = True
                if file_extension in config.FILE_EXTENSIONS_IMAGE:
                    generate_thumbnail(message_id, file_path, img_thumb_filename, file_extension)
            else:
                logger.info("{}: File not found. Attempting to download.".format(message_id[0:6]))
                logger.info("{}: Downloading file url: {}".format(message_id[0:6], dict_msg["file_url"]))
                download_path = "/tmp/{}.zip".format(get_random_alphanumeric_string(
                    30, with_punctuation=False, with_spaces=False))

                if (upload_filename and file_url_type and
                        file_url_type in config.DICT_UPLOAD_SERVERS):

                    # Pick a download slot to fill (2 slots per domain)
                    domain = urlparse(file_url).netloc
                    lockfile1 = "/var/lock/upload_{}_1.lock".format(domain)
                    lockfile2 = "/var/lock/upload_{}_2.lock".format(domain)

                    lf = LF()
                    lockfile = random.choice([lockfile1, lockfile2])
                    if lf.lock_acquire(lockfile, to=600):
                        try:
                            (file_download_successful,
                             file_size,
                             file_do_not_download,
                             file_md5_hashes_match,
                             media_height,
                             media_width,
                             message_steg) = download_and_extract(
                                message_id,
                                file_url,
                                file_extracts_start_base64,
                                upload_filename,
                                download_path,
                                file_path,
                                file_extension,
                                file_md5_hash,
                                img_thumb_filename)
                        finally:
                            lf.lock_release(lockfile)

        if file_decoded:
            # If decoded image, check for steg message
            message_steg = check_steg(
                message_id, file_extension, file_decoded=file_decoded)

        # Check for post replies
        replies = []
        if message:
            lines = message.split("\n")
            for line in range(0, len(lines)):
                # Find Reply IDs
                dict_ids_strings = is_post_id_reply(lines[line])
                if dict_ids_strings:
                    for each_string, targetpostid in dict_ids_strings.items():
                        replies.append(targetpostid)

        with session_scope(DB_PATH) as new_session:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_id).first()
            if not thread and is_op:  # OP received, create new thread
                chan = new_session.query(Chan).filter(
                    Chan.address == json_obj['toAddress']).first()
                new_thread = Threads()
                new_thread.thread_hash = thread_id
                new_thread.op_md5_hash = message_md5_hash
                if chan:
                    new_thread.chan_id = chan.id
                new_thread.subject = subject
                new_thread.timestamp_sent = timestamp_sent
                new_thread.timestamp_received = int(json_obj['receivedTime'])
                new_session.add(new_thread)
                new_session.commit()
                id_thread = new_thread.id
            elif not thread and not is_op:  # Reply received before OP, create thread with OP placeholder
                chan = new_session.query(Chan).filter(
                    Chan.address == json_obj['toAddress']).first()
                new_thread = Threads()
                new_thread.thread_hash = thread_id
                new_thread.op_md5_hash = op_md5_hash
                if chan:
                    new_thread.chan_id = chan.id
                new_thread.subject = subject
                new_thread.timestamp_sent = timestamp_sent
                new_thread.timestamp_received = int(json_obj['receivedTime'])
                new_session.add(new_thread)
                new_session.commit()
                id_thread = new_thread.id
            elif thread and not is_op:  # Reply received after OP, add to current thread
                if timestamp_sent > thread.timestamp_sent:
                    thread.timestamp_sent = timestamp_sent
                if int(json_obj['receivedTime']) > thread.timestamp_received:
                    thread.timestamp_received = int(json_obj['receivedTime'])
                new_session.commit()
                id_thread = thread.id
            elif thread and is_op:
                # Post indicating it is OP but thread already exists
                # Could have received reply before OP
                # Add OP to current thread
                id_thread = thread.id

            # Create message
            new_msg = Messages()
            new_msg.version = version
            new_msg.message_id = message_id
            new_msg.expires_time = get_msg_expires_time(message_id)
            new_msg.thread_id = id_thread
            new_msg.address_from = bleach.clean(json_obj['fromAddress'])
            new_msg.message_md5_hash = message_md5_hash
            new_msg.is_op = is_op
            new_msg.message = message
            new_msg.subject = subject
            new_msg.nation = nation
            if file_decoded == b"":  # Empty file
                new_msg.file_decoded = b" "
            else:
                new_msg.file_decoded = file_decoded
            new_msg.file_filename = file_filename
            new_msg.file_extension = file_extension
            new_msg.file_url = file_url
            new_msg.file_extracts_start_base64 = json.dumps(file_extracts_start_base64)
            new_msg.file_size = file_size
            new_msg.file_do_not_download = file_do_not_download
            new_msg.file_md5_hash = file_md5_hash
            new_msg.file_md5_hashes_match = file_md5_hashes_match
            new_msg.file_download_successful = file_download_successful
            new_msg.upload_filename = upload_filename
            new_msg.saved_file_filename = saved_file_filename
            new_msg.saved_image_thumb_filename = saved_image_thumb_filename
            new_msg.media_width = media_width
            new_msg.media_height = media_height
            new_msg.image_spoiler = image_spoiler
            new_msg.timestamp_received = int(json_obj['receivedTime'])
            new_msg.timestamp_sent = timestamp_sent
            new_msg.message_original = json_obj["message"]
            new_msg.passphrase_pgp = config.PASSPHRASE_MSG
            new_msg.decrypted_pgp = True
            new_msg.message_steg = message_steg
            new_msg.replies = json.dumps(replies)
            new_session.add(new_msg)
            new_session.commit()

            # Determine if an admin command to delete with comment is present
            # Replace comment and delete file information
            with session_scope(DB_PATH) as new_session:
                commands = new_session.query(Command).filter(and_(
                    Command.action == "delete_comment",
                    Command.action_type == "post",
                    Command.chan_address == json_obj['toAddress'])).all()
                for each_cmd in commands:
                    try:
                        options = json.loads(each_cmd.options)
                    except:
                        options = {}
                    if ("delete_comment" in options and
                            "message_id" in options["delete_comment"] and
                            options["delete_comment"]["message_id"] == message_id and
                            "comment" in options["delete_comment"]):
                        # replace comment
                        delete_and_replace_comment(
                            options["delete_comment"]["message_id"],
                            options["delete_comment"]["comment"])

    def submit_post(self, form_post, form_steg=None):
        """Process the form for making a post"""
        errors = []

        dict_send = {
            "save_file_path": None,
            "file_filename": None,
            "file_extension": None,
            "file_url_type": None,
            "file_url": None,
            "file_extracts_start_base64": None,
            "file_md5_hash": None,
            "media_height": None,
            "media_width": None,
            "file_uploaded": None,
            "upload_filename": None,
            "op_md5_hash": None,
            "subject": None,
            "message": None,
            "nation": None,
            "post_id": get_random_alphanumeric_string(6, with_punctuation=False, with_spaces=False)
        }

        if form_post.is_op.data != "yes":
            chan_thread = self.get_chan_thread(
                form_post.board_id.data, form_post.thread_id.data)
            with session_scope(DB_PATH) as new_session:
                thread = new_session.query(Threads).filter(
                    Threads.thread_hash == form_post.thread_id.data).first()
                if chan_thread and thread:
                    sub_strip = thread.subject.encode('utf-8').strip()
                    sub_unescape = html.unescape(sub_strip.decode())
                    sub_b64enc = base64.b64encode(sub_unescape.encode())
                    dict_send["subject"] = sub_b64enc.decode()
                else:
                    msg = "Board ({}) ID or Thread ({}) ID invalid".format(
                        form_post.board_id.data, form_post.thread_id.data)
                    logger.error(msg)
                    errors.append(msg)
                    return "Error", errors
        else:
            if not form_post.subject.data:
                logger.error("Subject required")
                return
            subject_test = form_post.subject.data.encode('utf-8').strip()
            if len(subject_test) > 64:
                msg = "Subject too large: {}. Must be less than 64 characters".format(
                    len(subject_test))
                logger.error(msg)
                errors.append(msg)
                return "Error", errors
            dict_send["subject"] = base64.b64encode(subject_test).decode()

        if form_post.nation.data:
            dict_send["nation"] = form_post.nation.data

        if form_post.body.data:
            dict_send["message"] = form_post.body.data.encode('utf-8').strip().decode()

        if form_post.is_op.data == "no" and form_post.op_md5_hash.data:
            dict_send["op_md5_hash"] = form_post.op_md5_hash.data

        if form_post.file.data:
            try:
                dict_send["file_filename"] = form_post.file.data.filename
                dict_send["file_extension"] = os.path.splitext(dict_send["file_filename"])[1].split(".")[1].lower()
            except Exception as e:
                msg = "Error determining file extension: {}".format(e)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                errors.append(msg)
                return "Error", errors

        spawn_send_thread = False
        save_file_size = 0
        if form_post.file.data:
            path_dirs = "/tmp/{}".format(
                get_random_alphanumeric_string(15, with_punctuation=False, with_spaces=False))
            try:
                shutil.rmtree(path_dirs)
            except:
                pass
            os.makedirs(path_dirs)
            dict_send["save_file_path"] = "{}/file.{}".format(path_dirs, dict_send["file_extension"])

            # Save file to disk
            logger.info("{}: Saving file {} to {}".format(
                dict_send["post_id"], dict_send["file_filename"], dict_send["save_file_path"]))
            form_post.file.data.save(dict_send["save_file_path"])
            save_file_size = os.path.getsize(dict_send["save_file_path"])
            logger.info("{}: File size is {}".format(
                dict_send["post_id"], human_readable_size(save_file_size)))
            if save_file_size > config.UPLOAD_SIZE_TO_THREAD:
                spawn_send_thread = True

        if spawn_send_thread:
            # Spawn a thread to send the message if the file is large.
            # This prevents the user's page from either timing out or waiting a very long
            # time to refresh. It's better to give the user feedback about what's happening.
            logger.info("{}: File size above {}. Spawning background upload thread.".format(
                dict_send["post_id"], human_readable_size(config.UPLOAD_SIZE_TO_THREAD)))
            msg_send = Thread(
                target=self.send_message, args=(errors, form_post, form_steg, dict_send,))
            msg_send.daemon = True
            msg_send.start()
            msg = "Your file that will be uploaded is {}, which is above the {} size to wait " \
                  "for the upload to finish. Instead, a thread was spawned to handle the upload " \
                  "and this message was generated to let you know your post is uploading in the" \
                  "background. Depending on the size of your upload and the service it's being" \
                  "uploaded to, the time it takes to send your post will vary. Give your post ample" \
                  "time to send so you don't make duplicate posts.".format(
                    human_readable_size(save_file_size),
                    human_readable_size(config.UPLOAD_SIZE_TO_THREAD))
            return msg, []
        else:
            logger.info("{}: File size below {}. Uploading in foreground.".format(
                dict_send["post_id"], human_readable_size(config.UPLOAD_SIZE_TO_THREAD)))
            return self.send_message(errors, form_post, form_steg, dict_send)

    def send_message(self, errors, form_post, form_steg, dict_send):
        """Conduct the file upload and sending of a message"""
        if form_post.file.data:
            if dict_send["file_extension"] in config.FILE_EXTENSIONS_IMAGE:
                try:
                    PIL.Image.MAX_IMAGE_PIXELS = 500000000
                    im = Image.open(dict_send["save_file_path"])
                    logger.info("{}: Determining image dimensions".format(dict_send["post_id"]))
                    dict_send["media_width"], dict_send["media_height"] = im.size
                    if form_post.strip_exif.data and dict_send["file_extension"] in ["png", "jpeg", "jpg"]:
                        logger.info("{}: Stripping image metadata/exif".format(dict_send["post_id"]))
                        im.save(dict_send["save_file_path"])
                except Exception as e:
                    msg = "{}: Error opening/stripping image: {}".format(dict_send["post_id"], e)
                    errors.append(msg)
                    logger.exception(msg)
            elif dict_send["file_extension"] in config.FILE_EXTENSIONS_VIDEO:
                try:
                    logger.info("{}: Determining video dimensions".format(dict_send["post_id"]))
                    vid = cv2.VideoCapture(dict_send["save_file_path"])
                    dict_send["media_height"] = vid.get(cv2.CAP_PROP_FRAME_HEIGHT)
                    dict_send["media_width"] = vid.get(cv2.CAP_PROP_FRAME_WIDTH)
                except Exception as e:
                    msg = "{}: Error getting video dimensions: {}".format(dict_send["post_id"], e)
                    errors.append(msg)
                    logger.exception(msg)

            # encrypt steg message into image
            if form_steg and dict_send["file_extension"] in config.FILE_EXTENSIONS_IMAGE:
                logger.info("{}: Adding steg message to image".format(dict_send["post_id"]))

                steg_status = steg_encrypt(
                    dict_send["save_file_path"],
                    dict_send["save_file_path"],
                    form_steg.steg_message.data,
                    form_steg.steg_passphrase.data)

                if steg_status != "success":
                    errors.append(steg_status)
                    logger.exception(steg_status)

        if (form_post.file.data and
                form_post.upload.data in config.DICT_UPLOAD_SERVERS):
            dict_send["file_url_type"] = form_post.upload.data

            dict_send["upload_filename"] = "{}.{}".format(
                get_random_alphanumeric_string(
                    30, with_punctuation=False, with_spaces=False),
                get_random_alphanumeric_string(
                    3, with_punctuation=False, with_spaces=False).lower())
            save_zip_path = "/tmp/{}".format(dict_send["upload_filename"])

            # Add image to password protected zip
            logger.info("{}: Creating ZIP file".format(dict_send["post_id"]))
            pyminizip.compress(
                dict_send["save_file_path"],
                None,
                save_zip_path,
                config.PASSPHRASE_ZIP, 1)
            delete_file(dict_send["save_file_path"])

            file_size = os.path.getsize(save_zip_path)

            number_of_extracts = 3

            if file_size < 2000:
                extract_starts_sizes = [{
                    "start": 0,
                    "size": int(file_size * 0.5)
                }]
            else:
                extract_starts_sizes = [{
                    "start": 0,
                    "size": 200
                }]

                sequences = return_non_overlapping_sequences(
                    number_of_extracts, 200, file_size - 200, 200, 1000)

                for pos, size in sequences:
                    extract_starts_sizes.append({
                        "start": pos,
                        "size": size
                    })

                extract_starts_sizes.append({
                    "start": file_size - 200,
                    "size": 200
                })

            logger.info("{}: File extraction positions and sizes: {}".format(
                dict_send["post_id"], extract_starts_sizes))
            logger.info("{}: File size before: {}".format(
                dict_send["post_id"], os.path.getsize(save_zip_path)))

            data_extracted_start_base64 = data_file_multiple_extract(
                save_zip_path, extract_starts_sizes, chunk=4096)

            logger.info("{}: File size after: {}".format(
                dict_send["post_id"], os.path.getsize(save_zip_path)))

            dict_send["file_extracts_start_base64"] = json.dumps(data_extracted_start_base64)

            dict_send["file_md5_hash"] = generate_hash(save_zip_path)
            if dict_send["file_md5_hash"]:
                logger.info("{}: ZIP file hash generated: {}".format(
                    dict_send["post_id"], dict_send["file_md5_hash"]))

            # Upload zip
            try:
                upload_success = None
                if config.DICT_UPLOAD_SERVERS[form_post.upload.data]["uri"]:
                    anon = AnonFile(
                        proxies=config.TOR_PROXIES,
                        custom_timeout=600,
                        uri=config.DICT_UPLOAD_SERVERS[form_post.upload.data]["uri"])
                else:
                    anon = AnonFile(
                        proxies=config.TOR_PROXIES,
                        custom_timeout=600,
                        server=form_post.upload.data)
                for i in range(3):
                    logger.info("{}: Uploading {} ZIP file".format(
                        dict_send["post_id"],
                        human_readable_size(os.path.getsize(save_zip_path))))
                    status, web_url = anon.upload_file(save_zip_path)
                    if not status:
                        logger.error("{}: ZIP file upload failed".format(dict_send["post_id"]))
                    else:
                        logger.info("{}: Upload success: URL: {}".format(dict_send["post_id"], web_url))
                        upload_success = web_url
                        break
                    time.sleep(15)
            finally:
                delete_file(save_zip_path)

            if upload_success:
                dict_send["file_url"] = upload_success
            else:
                msg = "File upload failed after 3 attempts"
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

        elif form_post.upload.data == "bitmessage" and form_post.file.data:
            dict_send["file_uploaded"] = base64.b64encode(
                open(dict_send["save_file_path"], "rb").read()).decode()

        dict_message = {
            "version": config.VERSION_BITCHAN,
            "message_type": "post",
            "is_op": form_post.is_op.data == "yes",
            "op_md5_hash": dict_send["op_md5_hash"],
            "timestamp_utc": self.get_utc(),
            "file_filename": dict_send["file_filename"],
            "file_extension": dict_send["file_extension"],
            "file_url_type": dict_send["file_url_type"],
            "file_url": dict_send["file_url"],
            "file_extracts_start_base64": dict_send["file_extracts_start_base64"],
            "file_base64": dict_send["file_uploaded"],
            "file_md5_hash": dict_send["file_md5_hash"],
            "media_width": dict_send["media_width"],
            "media_height": dict_send["media_height"],
            "image_spoiler": form_post.image_spoiler.data,
            "upload_filename": dict_send["upload_filename"],
            "subject": dict_send["subject"],
            "message": dict_send["message"],
            "nation": dict_send["nation"]
        }

        if dict_send["save_file_path"]:
            delete_file(dict_send["save_file_path"])

        gpg = gnupg.GPG()
        message_encrypted = gpg.encrypt(
            json.dumps(dict_message),
            symmetric=True,
            passphrase=config.PASSPHRASE_MSG,
            recipients=None)

        message_send = base64.b64encode(message_encrypted.data).decode()

        if len(message_send) > config.BM_PAYLOAD_MAX_SIZE:
            msg = "Message payload too large: {}. Must be less than {}".format(
                human_readable_size(len(message_send)),
                human_readable_size(config.BM_PAYLOAD_MAX_SIZE))
            logger.error(msg)
            errors.append(msg)
            return "Error", errors
        else:
            logger.info("{}: Message size: {}".format(dict_send["post_id"], len(message_send)))

        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            return_str = None
            try:
                time.sleep(0.1)
                return_str = self._api.sendMessage(
                    form_post.board_id.data,
                    form_post.from_address.data,
                    "",
                    message_send,
                    2,
                    config.BM_TTL)
                if return_str:
                    logger.info("{}: Message sent from {} to {}".format(
                        dict_send["post_id"], form_post.from_address.data, form_post.board_id.data))
                time.sleep(0.1)
            except Exception:
                pass
            finally:
                lf.lock_release(config.LOCKFILE_API)
                return_msg = "Post of size {} sent. The time it takes to send a message is " \
                             "related to the size of the message due to the proof of work " \
                             "required to send a message. Generally, the larger the message, " \
                             "the longer it takes to send. Messages ~10 KB take around a minute " \
                             "to send, whereas messages >= 100 KB can take several minutes to " \
                             "send. BM returned: {}".format(
                                human_readable_size(len(message_send)), return_str)
                return return_msg, errors

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

    def trash_message(self, message_id):
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=120):
            try:
                return_val = self._api.trashMessage(message_id)
                time.sleep(0.1)

                # Add message ID and TTL expiration in database (for inventory wipes)
                expires = get_msg_expires_time(message_id)
                address_from = get_msg_address_from(message_id)
                with session_scope(DB_PATH) as new_session:
                    test_del = new_session.query(DeletedMessages).filter(
                        DeletedMessages.message_id == message_id).count()
                    if not test_del:
                        logger.info("DeletedMessages table: add {}, {}".format(expires, message_id))
                        del_msg = DeletedMessages()
                        del_msg.message_id = message_id
                        del_msg.address_from = address_from
                        del_msg.expires_time = expires
                        new_session.add(del_msg)
                        new_session.commit()

                return return_val
            except Exception as err:
                logger.error("Exception during message delete: {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_API)
    
    def find_sender(self, address, list_send):
        access = get_access(address)
        for each_sender in list_send:
            for each_ident in self.get_identities():
                if each_ident in access[each_sender]:
                    return each_ident
            for each_chan in self.get_all_chans():
                if each_chan in access[each_sender]:
                    return each_chan

    def expiring_from_expires_time(self, msgid, expire_time):
        """Determine from expires_time if the list is expiring"""
        if not expire_time:
            return
        if expire_time > self.get_utc():
            days = (expire_time - self.get_utc()) / 60 / 60 / 24
            if days < 28 - config.SEND_BEFORE_EXPIRE_DAYS:
                logger.info("{}: List expiring in {:.1f} days. Send list.".format(
                    msgid, days))
                return True
            else:
                logger.info("{}: List expiring in {:.1f} days. Do nothing.".format(
                    msgid, days))
        else:
            days = (self.get_utc() - expire_time) / 60 / 60 / 24
            logger.info("{}: List expired {:.1f} days ago. Send list.".format(
                msgid, days))
            return True

    def expiring_from_timestamp(self, msgid, timestamp):
        """Determine from sent/received timestamp if the list is expiring"""
        if not timestamp:
            return
        days = (self.get_utc() - timestamp) / 60 / 60 / 24
        if days > config.SEND_BEFORE_EXPIRE_DAYS:
            logger.info("{}: List might be expiring: {:.1f} days old.".format(
                msgid, days))
            return True
        else:
            logger.info("{}: List might not be expiring: {:.1f} days old.".format(
                msgid, days))

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
            message_id[0:6], chan, thread_id))
        try:
            board = self._board_by_chan[chan]
            post = self._posts_by_id[message_id]
            # thread = board.get_thread(thread_id)
            # thread.delete_post(post)
            board.delete_post(post)
            del self._posts_by_id[message_id]
        except Exception as err:
            logger.error("Exception deleting post: {}".format(err))
        return self.trash_message(message_id)

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

    def clear_bm_inventory(self):
        logger.info("Deleting BitMessage inventory")
        try:
            self.is_restarting_bitmessage = True
            self.bitmessage_stop()
            time.sleep(20)

            conn = sqlite3.connect('file:{}'.format(config.messages_dat), uri=True)
            c = conn.cursor()
            c.execute('DELETE FROM inventory')
            conn.commit()
            conn.close()

            self.bitmessage_start()
            time.sleep(10)
        finally:
            self.is_restarting_bitmessage = False

    def delete_and_vacuum(self):
        logger.info("Deleting BitMessage Trash items")
        try:
            self._api.deleteAndVacuum()
        except:
            logger.exception("delete_and_vacuum()")

    def signal_clear_inventory(self):
        logger.info("Signaling deletion of BitMessage inventory in {} minutes".format(
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
            logger.error("Exception stopping BitMessage: {}".format(err))

    @staticmethod
    def bitmessage_start():
        try:
            if config.DOCKER:
                logger.info("Starting bitmessage docker container. Please wait.")
                subprocess.Popen('docker start bitmessage 2>&1', shell=True)
                time.sleep(15)
        except Exception as err:
            logger.error("Exception starting BitMessage: {}".format(err))

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
            logger.error("{}: Allowing file to be downloaded".format(message_id[0:6]))
            self.list_start_download.append(message_id)

    def remove_start_download(self, message_id):
        self.list_start_download.remove(message_id)

    def get_post_by_id(self, post_id):
        if post_id in self._posts_by_id:
            return self._posts_by_id[post_id]


bitchan = BitChan()
bitchan.setDaemon(True)
bitchan.start()
