import html
import json
import logging
import socket
import sqlite3
import time
import xmlrpc.client
from binascii import unhexlify

import config
from database.models import Chan
from database.models import Messages
from database.utils import session_scope
from utils.files import delete_message_files
from utils.shared import add_mod_log_entry
from utils.shared import regenerate_thread_card_and_popup

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.gateway')

bm_endpoint = "http://{user}:{pw}@{host}:{port}/".format(
    user=config.BM_USERNAME,
    pw=config.BM_PASSWORD,
    host=config.BM_HOST,
    port=config.BM_PORT)

socket.setdefaulttimeout(config.API_TIMEOUT)
api = xmlrpc.client.ServerProxy(bm_endpoint)


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


def delete_and_replace_comment(message_id, new_comment, from_address=None, local_delete=False):
    with session_scope(DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if message:
            if from_address:
                message.message = '<span class="god-text">ORIGINAL COMMENT DELETED BY {}. REASON: {}</span>'.format(
                    html.escape(from_address), html.escape(new_comment))
                user_from = html.escape(from_address)
            else:
                message.message = '<span class="god-text">ORIGINAL COMMENT LOCALLY DELETED. REASON: {}</span>'.format(
                    html.escape(new_comment))
                user_from = None
            message.file_url = None
            message.file_decoded = None
            message.file_download_successful = None
            message.message_steg = "{}"
            message.file_amount = 0
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

            regenerate_thread_card_and_popup(message.thread.thread_hash)

            # Delete all files associated with message
            delete_message_files(message_id)

            # Add mod log entry
            if local_delete:
                log_description = "Post locally deleted with comment: {}".format(
                    html.escape(new_comment))
            else:
                log_description = "Post remotely deleted with comment: {}".format(
                    html.escape(new_comment))

            add_mod_log_entry(
                log_description,
                message_id=message_id,
                user_from=user_from,
                board_address=message.thread.chan.address,
                thread_hash=message.thread.thread_hash)


def log_age_and_expiration(message_id, time_now, time_sent, time_expires):
    if time_sent < time_now:
        age = (time_now - time_sent) / 60 / 60 / 24
        logger.info("{}: Message {:.1f} days old.".format(message_id[-config.ID_LENGTH:].upper(), age))
    else:
        future_age = (time_sent - time_now) / 60 / 60 / 24
        logger.info("{}: Message sent timestamp in the future: {:.1f} days.".format(
            message_id[-config.ID_LENGTH:].upper(), future_age))

    if time_expires and time_expires > time_now:
        expires_in = (time_expires - time_now) / 60 / 60 / 24
        logger.info("{}: Message expires in {:.1f} days.".format(
            message_id[-config.ID_LENGTH:].upper(), expires_in))
    elif time_expires:
        expired_age = (time_now - time_expires) / 60 / 60 / 24
        logger.info("{}: Message expired {:.1f} days ago.".format(
            message_id[-config.ID_LENGTH:].upper(), expired_age))
    else:
        logger.info("{}: Message expire time not found in inventory yet.".format(
            message_id[-config.ID_LENGTH:].upper()))
