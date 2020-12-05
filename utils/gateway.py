import html
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
from database.utils import session_scope
from utils.files import delete_file
from utils.files import delete_message_files
from utils.shared import get_combined_access

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.utils.gateway')


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


def get_bitmessage_endpoint():
    username = config.username
    password = config.password
    host = config.host
    port = config.port
    return "http://{}:{}@{}:{}/".format(username, password, host, port)


def get_msg_address_from(msg_id: str):
    try:
        conn = sqlite3.connect('file:{}?mode=ro'.format(
            config.messages_dat), uri=True, check_same_thread=False)
        conn.text_factory = bytes
        c = conn.cursor()
        c.execute('SELECT fromaddress FROM inbox WHERE msgid=?', (unhexlify(msg_id),))
        data = c.fetchall()
        if data:
            return data[0][0]
    except Exception:
        logger.exception("except {}".format(msg_id))
        return


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


def chan_auto_clears_and_message_too_old(address, timestamp_sent):
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(Chan.address == address).first()
        if chan and chan.rules:
            try:
                rules = json.loads(chan.rules)
                if "automatic_wipe" in rules:
                    clear_time = rules["automatic_wipe"]["wipe_epoch"]

                    # Find next clear time in the future
                    while clear_time < time.time():
                        clear_time += rules["automatic_wipe"]["interval_seconds"]

                    # Go back one clear interval (last clear time)
                    clear_time -= rules["automatic_wipe"]["interval_seconds"]

                    if timestamp_sent < clear_time:  # If message is from before last clear time
                        return True
            except:
                logger.exception("Exception checking if message out of clear interval")
                return


def delete_and_replace_comment(message_id, new_comment):
    with session_scope(DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if message:
            message.message = '<span class="god-text">ORIGINAL COMMENT DELETED. REASON: {}</span>'.format(
                html.escape(new_comment))
            message.file_url = None
            message.file_decoded = None
            message.file_download_successful = None
            message.message_steg = None
            message.file_size = None
            message.media_width = None
            message.media_width = None
            message.file_filename = None
            message.file_extension = None
            message.file_currently_downloading = None
            message.file_sha256_hash = None
            message.file_sha256_hashes_match = None
            message.file_do_not_download = None
            message.file_download_successful = None
            new_session.commit()
            delete_message_files(message_id)


def delete_db_message(message_id):
    """Delete post from local DB"""
    with session_scope(DB_PATH) as new_session:
        this_message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if this_message:
            file_path = "{}/{}.{}".format(
                config.FILE_DIRECTORY,
                this_message.message_id,
                this_message.file_extension)
            img_thumb_path = "{}/{}_thumb.{}".format(
                config.FILE_DIRECTORY,
                this_message.message_id,
                this_message.file_extension)
            delete_file(file_path)
            delete_file(img_thumb_path)
            new_session.delete(this_message)
            new_session.commit()


def log_age_and_expiration(message_id, time_now, time_sent, time_expires):
    if time_sent < time_now:
        age = (time_now - time_sent) / 60 / 60 / 24
        logger.info("{}: Message {:.1f} days old.".format(message_id[0:6], age))
    else:
        future_age = (time_sent - time_now) / 60 / 60 / 24
        logger.info("{}: Message sent timestamp in the future: {:.1f} days.".format(
            message_id[0:6], future_age))

    if time_expires and time_expires > time_now:
        expires_in = (time_expires - time_now) / 60 / 60 / 24
        logger.info("{}: Message expires in {:.1f} days.".format(
            message_id[0:6], expires_in))
    elif time_expires:
        expired_age = (time_now - time_expires) / 60 / 60 / 24
        logger.info("{}: Message expired {:.1f} days ago.".format(
            message_id[0:6], expired_age))
    else:
        logger.info("{}: Message expire time not found in inventory yet.".format(
            message_id[0:6]))
