import base64
import html
import json
import logging
import socket
import sqlite3
import time
from binascii import unhexlify

import jsonrpclib

import config
from database.models import Chan
from database.models import Messages
from database.utils import session_scope
from utils.files import LF
from utils.files import delete_message_files
from utils.shared import add_mod_log_entry
from utils.shared import regenerate_card_popup_post_html
from utils.shared import regenerate_ref_to_from_post

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.gateway')

bm_endpoint = "http://{user}:{pw}@{host}:{port}/".format(
    user=config.BM_USERNAME,
    pw=config.BM_PASSWORD,
    host=config.BM_HOST,
    port=config.BM_PORT)

socket.setdefaulttimeout(config.API_TIMEOUT)
api = jsonrpclib.Server(bm_endpoint)


def generate_identity(passphrase, short_address):
    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
        try:
            b64_passphrase = base64.b64encode(passphrase.encode())

            if short_address:
                logger.info("Generating shorter Identity address")
                socket.setdefaulttimeout(600)
            return_str = api.createDeterministicAddresses(
                b64_passphrase.decode(), 1, 0, 0, short_address, 0, 0)
            if short_address:
                socket.setdefaulttimeout(config.API_TIMEOUT)

            return return_str
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API, log_info=True)


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


def delete_and_replace_comment(message_id, new_comment, from_address=None, local_delete=False, only_hide=False):
    with session_scope(DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if message:
            if from_address:
                message.delete_comment = '<span class="god-text">ORIGINAL COMMENT DELETED BY {}. REASON: {}</span>'.format(
                    html.escape(from_address), html.escape(new_comment))
                user_from = html.escape(from_address)
            else:
                message.delete_comment = '<span class="god-text">ORIGINAL COMMENT LOCALLY DELETED. REASON: {}</span>'.format(
                    html.escape(new_comment))
                user_from = None

            if only_hide:
                message.hide = True
            else:
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

            regenerate_card_popup_post_html(message_id=message_id)
            regenerate_ref_to_from_post(message_id)

            if not only_hide:
                # Delete all files associated with message
                delete_message_files(message_id)

            # Add mod log entry
            if local_delete:
                log_description = 'Locally delete post with comment: "{}"'.format(
                    html.escape(new_comment))
            else:
                log_description = 'Remotely delete post with comment (locally hidden): "{}"'.format(
                    html.escape(new_comment))

            add_mod_log_entry(
                log_description,
                message_id=message_id,
                user_from=user_from,
                board_address=message.thread.chan.address,
                thread_hash=message.thread.thread_hash,
                hidden=True)


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
