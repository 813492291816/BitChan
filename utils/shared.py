import json
import logging
import sqlite3
import time
from binascii import unhexlify
from urllib.parse import urlparse

from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Command
from database.models import GlobalSettings
from database.models import Messages
from database.models import ModLog
from database.models import PostCards
from database.models import Threads
from database.utils import session_scope

logger = logging.getLogger('bitchan.shared')
daemon_com = DaemonCom()


def add_mod_log_entry(
        description,
        timestamp=None,
        message_id=None,
        user_from=None,
        board_address=None,
        thread_hash=None,
        success=True,
        hidden=False):
    with session_scope(config.DB_PATH) as new_session:
        log_entry = ModLog()
        log_entry.description = description
        log_entry.message_id = message_id
        log_entry.user_from = user_from
        log_entry.board_address = board_address
        log_entry.thread_hash = thread_hash
        log_entry.success = success
        log_entry.hidden = hidden

        if timestamp:
            try:
                ts = int(timestamp)
            except:
                ts = time.time()
        else:
            ts = time.time()

        log_entry.timestamp = ts

        new_session.add(log_entry)
        new_session.commit()


def check_tld_i2p(urls):
    """Ensure list of trackers have i2p TLD"""
    non_i2p_urls = []
    for url in urls:
        try:
            domain = urlparse(url).netloc
            tld = domain.split(".")[-1]
            if tld.lower() != "i2p":
                non_i2p_urls.append(url)
        except:
            non_i2p_urls.append(url)
    return non_i2p_urls


def can_address_create_thread(from_address, chan_address):
    chans_board_info = daemon_com.get_chans_board_info()
    rules = chans_board_info[chan_address]["rules"]
    if ("restrict_thread_creation" in rules and
            "enabled" in rules["restrict_thread_creation"] and
            rules["restrict_thread_creation"]["enabled"]):
        access = get_access(chan_address)
        thread_creation_addresses = []
        if ("addresses" in rules["restrict_thread_creation"] and
                rules["restrict_thread_creation"]["addresses"]):
            thread_creation_addresses = rules["restrict_thread_creation"]["addresses"]
        if from_address not in access["primary_addresses"] + access["secondary_addresses"] + thread_creation_addresses:
            return False
        else:
            return True
    else:
        return True


def diff_list_added_removed(list1, list2):
    set1 = set(list1)
    set2 = set(list2)
    removed = list(sorted(set1 - set2))
    added = list(sorted(set2 - set1))
    return removed, added


def get_access(address):
    with session_scope(config.DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(Chan.address == address).first()
        if chan:
            admin_cmd = new_session.query(Command).filter(and_(
                Command.action == "set",
                Command.action_type == "options",
                Command.chan_address == chan.address)).first()
            return get_combined_access(admin_cmd, chan)
    return {}


def get_combined_access(command, chan):
    """Return chan access, with admin command taking priority"""
    access = {}
    if chan:
        try:
            access["primary_addresses"] = json.loads(chan.primary_addresses)
        except:
            access["primary_addresses"] = []

        try:
            access["secondary_addresses"] = json.loads(chan.secondary_addresses)
        except:
            access["secondary_addresses"] = []

        try:
            access["tertiary_addresses"] = json.loads(chan.tertiary_addresses)
        except:
            access["tertiary_addresses"] = []

        try:
            access["restricted_addresses"] = json.loads(chan.restricted_addresses)
        except:
            access["restricted_addresses"] = []

        if command:
            try:
                options = json.loads(command.options)
            except:
                options = {}
            if "modify_admin_addresses" in options:
                access["secondary_addresses"] = options["modify_admin_addresses"]
            if "modify_user_addresses" in options:
                access["tertiary_addresses"] = options["modify_user_addresses"]
            if "modify_restricted_addresses" in options:
                access["restricted_addresses"] = options["modify_restricted_addresses"]
    return access


def get_msg_expires_time(msg_id: str):
    try:
        conn = sqlite3.connect('file:{}?mode=ro'.format(
            config.BM_MESSAGES_DAT), uri=True, check_same_thread=False)
        conn.text_factory = bytes
        c = conn.cursor()
        c.execute('SELECT expirestime FROM inventory WHERE hash=?', (unhexlify(msg_id),))
        data = c.fetchall()
        if data:
            return data[0][0]
    except Exception:
        logger.exception("except {}".format(msg_id))


def get_post_id(message_id):
    return message_id[-config.ID_LENGTH:].upper()


def get_post_ttl(form_ttl=2419200):
    """Determine post TTL"""
    with session_scope(config.DB_PATH) as new_session:
        settings = new_session.query(GlobalSettings).first()

        if form_ttl < 3600:
            form_ttl = 3600
        elif form_ttl > 2419200:
            form_ttl = 2419200

        if not settings.enable_kiosk_mode:
            return form_ttl

        if settings.kiosk_ttl_option == "selectable_max_28_days":
            ttl = form_ttl
        elif settings.kiosk_ttl_option == "selectable_max_custom":
            if form_ttl <= settings.kiosk_ttl_seconds:
                ttl = form_ttl
            else:
                ttl = settings.kiosk_ttl_seconds
        elif settings.kiosk_ttl_option == "forced_28_days":
            ttl = 2419200
        elif settings.kiosk_ttl_option == "forced_102_hours":
            ttl = 367200
        elif settings.kiosk_ttl_option == "forced_custom":
            ttl = settings.kiosk_ttl_seconds
        else:
            ttl = 2419200

    return ttl


def is_access_same_as_db(options, chan_entry):
    """Check if command access same as chan access"""
    return_dict = {
        "secondary_access": False,
        "tertiary_access": False,
        "restricted_access": False
    }

    if "modify_admin_addresses" in options:
        # sort both lists and compare
        command = sorted(options["modify_admin_addresses"])
        chan = sorted(json.loads(chan_entry.secondary_addresses))
        if command == chan:
            return_dict["secondary_access"] = True

    if "modify_user_addresses" in options:
        # sort both lists and compare
        command = sorted(options["modify_user_addresses"])
        chan = sorted(json.loads(chan_entry.tertiary_addresses))
        if command == chan:
            return_dict["tertiary_access"] = True

    if "modify_restricted_addresses" in options:
        # sort both lists and compare
        command = sorted(options["modify_restricted_addresses"])
        chan = sorted(json.loads(chan_entry.restricted_addresses))
        if command == chan:
            return_dict["restricted_access"] = True

    return return_dict


def post_has_image(message_id):
    with session_scope(config.DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if message:
            try:
                media_info = json.loads(message.media_info)
            except:
                media_info = {}
            for filename, info in media_info.items():
                if info["extension"] in config.FILE_EXTENSIONS_IMAGE:
                    return True


def regenerate_ref_to_from_post(message_id, delete_message=False):
    """Regenerate posts referencing to and from restored post"""
    with session_scope(config.DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if message:
            post_ids_replied_to = message.post_ids_replied_to
            post_ids_replying_to_msg = message.post_ids_replying_to_msg

            if delete_message:
                # Delete message from database
                new_session.delete(message)
                new_session.commit()

            for post_ids_json in [post_ids_replied_to,
                                  post_ids_replying_to_msg]:
                post_ids = json.loads(post_ids_json)
                for post_id in post_ids:
                    post = new_session.query(Messages).filter(
                        Messages.post_id == post_id).first()
                    if post:
                        regenerate_card_popup_post_html(
                            message_id=post.message_id)


def regenerate_card_popup_post_html(
        thread_hash=None,
        message_id=None,
        all_posts_of_board_address=None,
        regenerate_post_html=True,
        regenerate_popup_html=True,
        regenerate_cards=True):

    with session_scope(config.DB_PATH) as new_session:
        # Regenerate OP post of thread
        if thread_hash:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_hash).first()

            if thread:
                message = new_session.query(Messages).filter(and_(
                    Messages.thread_id == thread.id,
                    Messages.is_op.is_(True))).first()
                if message:
                    if regenerate_popup_html:
                        message.regenerate_popup_html = True
                    if regenerate_post_html:
                        message.regenerate_post_html = True

            if thread and regenerate_cards:
                card_test = new_session.query(PostCards).filter(
                    PostCards.thread_id == thread_hash).first()
                if card_test:
                    card_test.regenerate = True

        # Regenerate specific post
        if message_id:
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if message:
                if regenerate_popup_html:
                    message.regenerate_popup_html = True
                if regenerate_post_html:
                    message.regenerate_post_html = True

                if message.thread and regenerate_cards:
                    card_test = new_session.query(PostCards).filter(
                        PostCards.thread_id == message.thread.thread_hash).first()
                    if card_test:
                        card_test.regenerate = True

        # Regenerate all posts of a board
        if all_posts_of_board_address:
            board = new_session.query(Chan).filter(
                Chan.address == all_posts_of_board_address).first()

            for thread in board.threads:
                thread = new_session.query(Threads).filter(
                    Threads.thread_hash == thread.thread_hash).first()
                if thread:
                    for message in thread.messages:
                        if regenerate_popup_html:
                            message.regenerate_popup_html = True
                        if regenerate_post_html:
                            message.regenerate_post_html = True

            if regenerate_cards:
                for thread in board.threads:
                    card_test = new_session.query(PostCards).filter(
                        PostCards.thread_id == thread.thread_hash).first()
                    if card_test:
                        card_test.regenerate = True

        new_session.commit()


def return_list_of_csv_bitmessage_addresses(form_list, status):
    add_list_failed = []
    add_list_passed = []
    try:
        if form_list:
            list_additional = form_list.replace(" ", "").split(",")
            for each_address in list_additional:
                if (not each_address.startswith("BM-") or
                        len(each_address) > 38 or
                        len(each_address) < 34):
                    add_list_failed.append(each_address)
                elif each_address.startswith("BM-"):
                    add_list_passed.append(each_address)
    except:
        logger.exception(1)
        status['status_message'].append(
            "Error parsing additional addresses. "
            "Must only be comma-separated addresses without spaces.")
    return status, add_list_failed, add_list_passed
