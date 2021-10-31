import json
import logging
import sqlite3
import time
from binascii import unhexlify

from sqlalchemy import and_

import config
from database.models import Chan
from database.models import Command
from database.models import Messages
from database.models import ModLog
from database.models import PostCards
from database.models import Threads
from database.utils import session_scope

logger = logging.getLogger('bitchan.shared')

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN


def diff_list_added_removed(list1, list2):
    set1 = set(list1)
    set2 = set(list2)
    removed = list(sorted(set1 - set2))
    added = list(sorted(set2 - set1))
    return removed, added


def add_mod_log_entry(
        description,
        timestamp=None,
        message_id=None,
        user_from=None,
        board_address=None,
        thread_hash=None):
    with session_scope(DB_PATH) as new_session:
        log_entry = ModLog()
        log_entry.description = description

        if message_id:
            log_entry.message_id = message_id

        if timestamp:
            try:
                log_entry.timestamp = int(timestamp)
            except:
                log_entry.timestamp = time.time()
        else:
            log_entry.timestamp = time.time()

        if user_from:
            log_entry.user_from = user_from

        if board_address:
            log_entry.board_address = board_address

        if thread_hash:
            log_entry.thread_hash = thread_hash

        new_session.add(log_entry)
        new_session.commit()


def get_msg_expires_time(msg_id: str):
    try:
        conn = sqlite3.connect('file:{}?mode=ro'.format(
            config.messages_dat), uri=True, check_same_thread=False)
        conn.text_factory = bytes
        c = conn.cursor()
        c.execute('SELECT expirestime FROM inventory WHERE hash=?', (unhexlify(msg_id),))
        data = c.fetchall()
        if data:
            return data[0][0]
    except Exception:
        logger.exception("except {}".format(msg_id))
        return


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


def get_access(address):
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(Chan.address == address).first()
        if chan:
            admin_cmd = new_session.query(Command).filter(and_(
                Command.action == "set",
                Command.action_type == "options",
                Command.chan_address == chan.address)).first()
            return get_combined_access(admin_cmd, chan)
    return {}


def post_has_image(message_id):
    with session_scope(DB_PATH) as new_session:
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


def regenerate_thread_card_and_popup(thread_hash=None, message_id=None):
    with session_scope(DB_PATH) as new_session:
        if thread_hash:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_hash).first()
            if thread:
                message = new_session.query(Messages).filter(and_(
                    Messages.thread_id == thread.id,
                    Messages.is_op.is_(True))).first()
                if message:
                    message.regenerate_popup_html = True

                card_test = new_session.query(PostCards).filter(
                    PostCards.thread_id == thread_hash).first()
                if card_test:
                    card_test.regenerate = True

                if message or card_test:
                    new_session.commit()

        if message_id:
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if message:
                message.regenerate_popup_html = True
                new_session.commit()
