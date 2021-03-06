import base64
import datetime
import hashlib
import html
import json
import logging
import os
import random
from io import BytesIO
from urllib.parse import urlparse

import bleach
from PIL import Image
from sqlalchemy import and_
from sqlalchemy import or_

import config
from chan_objects import ChanBoard
from chan_objects import ChanList
from chan_objects import ChanPost
from database.models import AdminMessageStore
from database.models import Chan
from database.models import Command
from database.models import GlobalSettings
from database.models import Messages
from database.models import Threads
from database.utils import session_scope
from utils.download import download_and_extract
from utils.download import process_attachments
from utils.encryption import crypto_multi_decrypt
from utils.encryption import decrypt_safe_size
from utils.files import LF
from utils.files import count_files_in_zip
from utils.files import delete_file
from utils.files import delete_files_recursive
from utils.files import extract_zip
from utils.files import generate_thumbnail
from utils.gateway import chan_auto_clears_and_message_too_old
from utils.gateway import delete_and_replace_comment
from utils.gateway import get_access
from utils.gateway import log_age_and_expiration
from utils.general import get_random_alphanumeric_string
from utils.general import get_thread_id
from utils.general import process_passphrase
from utils.general import version_checker
from utils.message_admin_command import admin_ban_address_from_board
from utils.message_admin_command import admin_delete_from_board
from utils.message_admin_command import admin_delete_from_board_with_comment
from utils.message_admin_command import admin_set_options
from utils.replacements import is_post_id_reply
from utils.replacements import process_replacements
from utils.replacements import replace_dict_keys_with_values
from utils.shared import get_msg_expires_time

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.process_message')


def process_message(msg_dict):
    """Parse a message to determine if it is valid and add it to bitchan"""
    from bitchan_flask import nexus

    if len(msg_dict) == 0:
        return

    with session_scope(DB_PATH) as new_session:
        admin_store = new_session.query(AdminMessageStore).filter(
            AdminMessageStore.message_id == msg_dict["msgid"]).first()
        if admin_store and not nexus.bm_sync_complete:
            logger.info(
                "{}: Stored message ID detected. "
                "Skipping processing of admin command until synced".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            return

        message_post = new_session.query(Messages).filter(
            Messages.message_id == msg_dict["msgid"]).first()
        if message_post and message_post.thread and message_post.thread.chan:
            logger.info("{}: Adding message from database to chan {}".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), message_post.thread.chan.address))
            post = ChanPost(msg_dict["msgid"])

            if message_post.thread.chan.address not in nexus._board_by_chan:
                nexus._board_by_chan[msg_dict['toAddress']] = ChanBoard(
                    msg_dict['toAddress'])

            nexus._posts_by_id[msg_dict["msgid"]] = post
            chanboard = nexus._board_by_chan[msg_dict['toAddress']]
            chanboard.add_post(post, message_post.thread.thread_hash)
            return

    # Decode message
    message = base64.b64decode(msg_dict['message']).decode()

    # Check if message is an encrypted PGP message
    if not message.startswith("-----BEGIN PGP MESSAGE-----"):
        logger.info("{}: Message doesn't appear to be PGP message. Deleting.".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        nexus.trash_message(msg_dict["msgid"])
        return

    pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == msg_dict['toAddress']).first()
        if chan and chan.pgp_passphrase_msg:
            pgp_passphrase_msg = chan.pgp_passphrase_msg

    # Decrypt the message
    # Protect against explosive PGP message size exploit
    msg_decrypted = decrypt_safe_size(message, pgp_passphrase_msg, 400000)

    if msg_decrypted is not None:
        logger.info("{}: Message decrypted".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        try:
            msg_decrypted_dict = json.loads(msg_decrypted)
        except:
            logger.info("{}: Malformed JSON payload. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            nexus.trash_message(msg_dict["msgid"])
            return
    else:
        logger.info("{}: Could not decrypt message. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        nexus.trash_message(msg_dict["msgid"])
        return

    if "version" not in msg_decrypted_dict:
        logger.error("{}: 'version' not found in message. Deleting.")
        nexus.trash_message(msg_dict["msgid"])
        return
    elif version_checker(config.VERSION_BITCHAN, msg_decrypted_dict["version"])[1] == "less":
        logger.info("{}: Message version greater than BitChan version. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        nexus.trash_message(msg_dict["msgid"])
        with session_scope(DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            settings.messages_newer += 1
            new_session.commit()
        return
    elif version_checker(msg_decrypted_dict["version"], config.VERSION_MIN_MSG)[1] == "less":
        logger.info("{}: Message version too old. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        nexus.trash_message(msg_dict["msgid"])
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
        logger.info("{}: 'message_type' missing from message. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        nexus.trash_message(msg_dict["msgid"])
    elif msg_decrypted_dict["message_type"] == "admin":
        if nexus.bm_sync_complete:
            # check before processing if sync has really completed
            nexus.check_sync()

        with session_scope(DB_PATH) as new_session:
            admin_store = new_session.query(AdminMessageStore).filter(
                AdminMessageStore.message_id == msg_dict["msgid"]).first()
            if not nexus.bm_sync_complete:
                # Add to admin message store DB to indicate to skip processing if not synced
                if not admin_store:
                    with session_scope(DB_PATH) as new_session:
                        new_store = AdminMessageStore()
                        new_store.message_id = msg_dict["msgid"]
                        new_store.time_added = datetime.datetime.now()
                        new_session.add(new_store)
                        new_session.commit()
                logger.info("{}: Skipping processing of admin command until synced".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            else:
                # delete stored admin message ID and process admin command
                if admin_store:
                    new_session.delete(admin_store)
                process_admin(msg_dict, msg_decrypted_dict)
    elif msg_decrypted_dict["message_type"] == "post":
        process_post(msg_dict, msg_decrypted_dict)
    elif msg_decrypted_dict["message_type"] == "list":
        process_list(msg_dict, msg_decrypted_dict)
    else:
        logger.error("{}: Unknown message type: {}".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_decrypted_dict["message_type"]))


def process_post(msg_dict, msg_decrypted_dict):
    """Process message as a post to a board"""
    from bitchan_flask import nexus

    logger.info("{}: Message is a post".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))

    # Determine if board is public and requires an Identity to post
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(and_(
            Chan.access == "public",
            Chan.type == "board",
            Chan.address == msg_dict['toAddress'])).first()
        if chan:
            try:
                rules = json.loads(chan.rules)
            except:
                rules = {}
            if ("require_identity_to_post" in rules and
                    rules["require_identity_to_post"] and
                    msg_dict['toAddress'] == msg_dict['fromAddress']):
                # From address is not different from board address
                logger.info(
                    "{}: Message is from its own board's address {} but requires a "
                    "non-board address to post. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))
                nexus.trash_message(msg_dict["msgid"])
                return

    # Determine if there is a current ban in place for an address
    # If so, delete message and don't process it
    with session_scope(DB_PATH) as new_session:
        admin_bans = new_session.query(Command).filter(and_(
            Command.action == "ban",
            Command.action_type == "ban_address",
            Command.chan_address == msg_dict['toAddress'])).all()
        for each_ban in admin_bans:
            try:
                options = json.loads(each_ban.options)
            except:
                options = {}
            if ("ban_address" in options and
                    options["ban_address"] == msg_dict['fromAddress'] and
                    msg_dict['fromAddress'] not in nexus._identity_dict):
                # If there is a ban and the banned user isn't yourself, delete post
                logger.info("{}: Message is from address {} that's banned from board {}. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress'], msg_dict['toAddress']))
                nexus.trash_message(msg_dict["msgid"])
                return

    # Determine if there is a current block in place for an address
    # If so, delete message and don't process it
    # Note: only affects your local system, not other users
    with session_scope(DB_PATH) as new_session:
        blocks = new_session.query(Command).filter(and_(
            Command.action == "block",
            Command.do_not_send == True,
            Command.action_type == "block_address",
            or_(Command.chan_address == msg_dict['toAddress'],
                Command.chan_address == "all"))).all()
        for each_block in blocks:
            try:
                options = json.loads(each_block.options)
            except:
                options = {}
            if ("block_address" in options and
                    options["block_address"] == msg_dict['fromAddress'] and
                    each_block.chan_address in [msg_dict['toAddress'], "all"] and
                    msg_dict['fromAddress'] not in nexus._identity_dict):
                # If there is a block and the blocked user isn't yourself, delete post
                logger.info("{}: Message is from address {} that's blocked from board {}. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress'], msg_dict['toAddress']))
                nexus.trash_message(msg_dict["msgid"])
                return

    # Determine if board is public and the sender is restricted from posting
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(and_(
            Chan.access == "public",
            Chan.type == "board",
            Chan.address == msg_dict['toAddress'])).first()
        if chan:
            # Check if sender in restricted list
            access = get_access(msg_dict['toAddress'])
            if msg_dict['fromAddress'] in access["restricted_addresses"]:
                logger.info("{}: Post from restricted sender: {}. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))
                nexus.trash_message(msg_dict["msgid"])
                return
            else:
                logger.info("{}: Post from unrestricted sender: {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))

    # Determine if board is private and the sender is allowed to send to the board
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(and_(
            Chan.access == "private",
            Chan.type == "board",
            Chan.address == msg_dict['toAddress'])).first()
        if chan:
            errors, dict_info = process_passphrase(chan.passphrase)
            # Sender must be in at least one address list
            access = get_access(msg_dict['toAddress'])
            if (msg_dict['fromAddress'] not in
                    access["primary_addresses"] +
                    access["secondary_addresses"] +
                    access["tertiary_addresses"]):
                logger.info("{}: Post from unauthorized sender: {}. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))
                nexus.trash_message(msg_dict["msgid"])
                return
            else:
                logger.info("{}: Post from authorized sender: {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))

    # Pre-processing checks passed. Continue processing message.
    with session_scope(DB_PATH) as new_session:
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
                logger.error("Could not complete admin command word replacements: {}".format(err))

            # Perform general text replacements/modifications before saving to the database
            try:
                msg_decrypted_dict["message"] = process_replacements(
                    msg_decrypted_dict["message"], msg_dict["msgid"], msg_dict["msgid"])
            except Exception as err:
                logger.exception("Error processing replacements: {}".format(err))

        msg_dict['message_decrypted'] = msg_decrypted_dict

        #
        # Save message to database
        #
        message = new_session.query(Messages).filter(
            Messages.message_id == msg_dict["msgid"]).first()
        if not message:
            logger.info("{}: Message not in DB. Start processing.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            parse_message(msg_dict["msgid"], msg_dict)

        # Check if message was created by parse_message()
        message = new_session.query(Messages).filter(
            Messages.message_id == msg_dict["msgid"]).first()
        if not message:
            logger.error("{}: Message not created. Don't create post object.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            return
        elif not message.thread or not message.thread.chan:
            # Chan or thread doesn't exist, delete thread and message
            if message.thread:
                new_session.delete(message.thread)
            if message:
                new_session.delete(message)
            new_session.commit()
            logger.error("{}: Thread or board doesn't exist. Deleting DB entries.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            return

        #
        # Create post object
        #
        logger.info("{}: Adding post to chan {}".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
        post = ChanPost(msg_dict["msgid"])

        if msg_dict['toAddress'] not in nexus._board_by_chan:
            nexus._board_by_chan[msg_dict['toAddress']] = ChanBoard(msg_dict['toAddress'])
        nexus._posts_by_id[msg_dict["msgid"]] = post
        chan_board = nexus._board_by_chan[msg_dict['toAddress']]
        chan_board.add_post(post, message.thread.thread_hash)


def process_list(msg_dict, msg_decrypted_dict):
    """Process message as a list"""
    from bitchan_flask import nexus

    logger.info("{}: Message is a list".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))

    # Check integrity of message
    required_keys = ["version", "timestamp_utc", "access", "list"]
    integrity_pass = True

    with session_scope(DB_PATH) as new_session:
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
                logger.error("{}: List message missing '{}'".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), each_key))
                integrity_pass = False

        for each_chan in msg_decrypted_dict["list"]:
            if "passphrase" not in msg_decrypted_dict["list"][each_chan]:
                logger.error("{}: Entry in list missing 'passphrase'".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                integrity_pass = False
                continue

            errors, dict_info = process_passphrase(msg_decrypted_dict["list"][each_chan]["passphrase"])
            if not dict_info or errors:
                logger.error("{}: List passphrase did not pass integrity check: {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                    msg_decrypted_dict["list"][each_chan]["passphrase"]))
                for err in errors:
                    logger.error(err)
                integrity_pass = False

            if "allow_list_pgp_metadata" in rules and rules["allow_list_pgp_metadata"]:
                if ("pgp_passphrase_msg" in msg_decrypted_dict["list"][each_chan] and
                        len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_msg"]) > config.PGP_PASSPHRASE_LENGTH):
                    logger.error("{}: Message PGP Passphrase longer than {}: {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                        config.PGP_PASSPHRASE_LENGTH,
                        len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_msg"])))
                    integrity_pass = False

                if ("pgp_passphrase_attach" in msg_decrypted_dict["list"][each_chan] and
                        len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_attach"]) > config.PGP_PASSPHRASE_LENGTH):
                    logger.error("{}: Attachment PGP Passphrase longer than {}: {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                        config.PGP_PASSPHRASE_LENGTH,
                        len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_attach"])))
                    integrity_pass = False

                if ("pgp_passphrase_steg" in msg_decrypted_dict["list"][each_chan] and
                        len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_steg"]) > config.PGP_PASSPHRASE_LENGTH):
                    logger.error("{}: Steg PGP Passphrase longer than {}: {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                        config.PGP_PASSPHRASE_LENGTH,
                        len(msg_decrypted_dict["list"][each_chan]["pgp_passphrase_steg"])))
                    integrity_pass = False

        if not integrity_pass:
            logger.error("{}: List message failed integrity test: {}".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_decrypted_dict))
            nexus.trash_message(msg_dict["msgid"])
            return

        if msg_decrypted_dict["timestamp_utc"] - (60 * 60 * 3) > nexus.get_utc():
            # message timestamp is in the distant future. Delete.
            logger.info("{}: List message has future timestamp. Deleting.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            nexus.trash_message(msg_dict["msgid"])
            return

        log_age_and_expiration(
            msg_dict["msgid"],
            nexus.get_utc(),
            msg_decrypted_dict["timestamp_utc"],
            get_msg_expires_time(msg_dict["msgid"]))

        if (msg_decrypted_dict["timestamp_utc"] < nexus.get_utc() and
                ((nexus.get_utc() - msg_decrypted_dict["timestamp_utc"]) / 60 / 60 / 24) > 28):
            # message timestamp is too old. Delete.
            logger.info("{}: List message is supposedly older than 28 days. Deleting.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            nexus.trash_message(msg_dict["msgid"])
            return

        # Check if board is set to automatically clear and message is older than the last clearing
        if chan_auto_clears_and_message_too_old(
                msg_dict['toAddress'], msg_decrypted_dict["timestamp_utc"]):
            logger.info("{}: Message outside current auto clear period. Deleting.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            nexus.trash_message(msg_dict["msgid"])
            return

        logger.info("{}: List message passed integrity test".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        if msg_dict['toAddress'] not in nexus._list_by_chan:
            nexus._list_by_chan[msg_dict['toAddress']] = ChanList(msg_dict['toAddress'])

        chan_list = nexus._list_by_chan[msg_dict['toAddress']]
        chan_list.add_to_list(msg_decrypted_dict)

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
            logger.info("{}: List from restricted sender: {}. Deleting.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))
            nexus.trash_message(msg_dict["msgid"])
            return

        # Check if rule prevents sending from own address
        if ("require_identity_to_post" in rules and
                rules["require_identity_to_post"] and
                msg_dict['toAddress'] == msg_dict['fromAddress']):
            # From address is not different from list address
            logger.info(
                "{}: List is from its own address {} but requires a "
                "non-list address to post. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress']))
            nexus.trash_message(msg_dict["msgid"])
            return

        if list_chan.access == "public":

            if sender_is_primary or sender_is_secondary:
                # store latest list timestamp from primary/secondary addresses
                if (list_chan.list_message_timestamp_utc_owner and
                        msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_owner):
                    # message timestamp is older than what's in the database
                    logger.info("{}: Owner/Admin of public list message older than DB timestamp. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    nexus.trash_message(msg_dict["msgid"])
                    return
                else:
                    logger.info("{}: Owner/Admin of public list message newer than DB timestamp. Updating.".format(
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
                        logger.info("{}: Setting user timestamp/expires_time to that of Owner/Admin.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        list_chan.list_message_id_user = msg_dict["msgid"]
                        list_chan.list_message_expires_time_user = get_msg_expires_time(msg_dict["msgid"])
                        list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                logger.info(
                    "{}: List {} is public and From address {} "
                    "in primary or secondary access list. Replacing entire list.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'], msg_dict['fromAddress']))

                # Set the time the list changed
                if list_chan.list != json.dumps(msg_decrypted_dict["list"]):
                    list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                list_chan.list = json.dumps(msg_decrypted_dict["list"])
            else:
                # store latest list timestamp from tertiary addresses
                if (list_chan.list_message_timestamp_utc_user and
                        msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_user):
                    # message timestamp is older than what's in the database
                    logger.info("{}: User list message older than DB timestamp. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    nexus.trash_message(msg_dict["msgid"])
                    return
                else:
                    logger.info("{}: User list message newer than DB timestamp. Updating.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    list_chan.list_message_id_user = msg_dict["msgid"]
                    list_chan.list_message_expires_time_user = get_msg_expires_time(msg_dict["msgid"])
                    list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                try:
                    dict_chan_list = json.loads(list_chan.list)
                except:
                    dict_chan_list = {}
                logger.info("{}: List {} is public, adding addresses to list".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
                for each_address in msg_decrypted_dict["list"]:
                    if each_address not in dict_chan_list:
                        logger.info("{}: Adding {} to list".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), each_address))
                        dict_chan_list[each_address] = msg_decrypted_dict["list"][each_address]
                    else:
                        logger.info("{}: {} already in list".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), each_address))

                # Set the time the list changed
                if list_chan.list != json.dumps(dict_chan_list):
                    list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                list_chan.list = json.dumps(dict_chan_list)

            new_session.commit()

        elif list_chan.access == "private":
            # Check if private list by checking if any identities match From address
            if not sender_is_primary and not sender_is_secondary and not sender_is_tertiary:
                logger.error(
                    "{}: List {} is private but From address {} not in primary, secondary, or tertiary access list".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'], msg_dict['fromAddress']))

            elif sender_is_primary or sender_is_secondary:
                # store latest list timestamp from primary/secondary addresses
                if (list_chan.list_message_timestamp_utc_owner and
                        msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_owner):
                    # message timestamp is older than what's in the database
                    logger.info("{}: Owner/Admin of private list message older than DB timestamp. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    nexus.trash_message(msg_dict["msgid"])
                    return
                else:
                    logger.info("{}: Owner/Admin of private list message newer than DB timestamp. Updating.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    list_chan.list_message_id_owner = msg_dict["msgid"]
                    list_chan.list_message_expires_time_owner = get_msg_expires_time(msg_dict["msgid"])
                    list_chan.list_message_timestamp_utc_owner = msg_decrypted_dict["timestamp_utc"]

                logger.info(
                    "{}: List {} is private and From address {} "
                    "in primary or secondary access list. Replacing entire list.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'], msg_dict['fromAddress']))
                list_chan = new_session.query(Chan).filter(
                    Chan.address == msg_dict['toAddress']).first()

                # Set the time the list changed
                if list_chan.list != json.dumps(msg_decrypted_dict["list"]):
                    list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                list_chan.list = json.dumps(msg_decrypted_dict["list"])

            elif sender_is_tertiary:
                # store latest list timestamp from tertiary addresses
                if (list_chan.list_message_timestamp_utc_user and
                        msg_decrypted_dict["timestamp_utc"] < list_chan.list_message_timestamp_utc_user):
                    # message timestamp is older than what's in the database
                    logger.info("{}: User list message older than DB timestamp. Deleting.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    nexus.trash_message(msg_dict["msgid"])
                    return
                else:
                    logger.info("{}: User list message newer than DB timestamp. Updating.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    list_chan.list_message_id_user = msg_dict["msgid"]
                    list_chan.list_message_expires_time_user = get_msg_expires_time(msg_dict["msgid"])
                    list_chan.list_message_timestamp_utc_user = msg_decrypted_dict["timestamp_utc"]

                logger.info(
                    "{}: List {} is private and From address {} "
                    "in tertiary access list. Adding addresses to list.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress'], msg_dict['fromAddress']))
                try:
                    dict_chan_list = json.loads(list_chan.list)
                except:
                    dict_chan_list = {}
                for each_address in msg_decrypted_dict["list"]:
                    if each_address not in dict_chan_list:
                        logger.info("{}: Adding {} to list".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), each_address))
                        dict_chan_list[each_address] = msg_decrypted_dict["list"][each_address]
                    else:
                        logger.info("{}: {} already in list".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), each_address))

                # Set the time the list changed
                if list_chan.list != json.dumps(dict_chan_list):
                    list_chan.list_timestamp_changed = msg_decrypted_dict["timestamp_utc"]

                list_chan.list = json.dumps(dict_chan_list)

            new_session.commit()

    nexus.trash_message(msg_dict["msgid"])


def process_admin(msg_dict, msg_decrypted_dict):
    """Process message as an admin command"""
    from bitchan_flask import nexus

    logger.info("{}: Message is an admin command".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))

    # Authenticate sender
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == msg_dict['toAddress']).first()
        if chan:
            errors, dict_info = process_passphrase(chan.passphrase)
            # Message must be from address in primary or secondary access list
            access = get_access(msg_dict['toAddress'])
            if errors or (msg_dict['fromAddress'] not in access["primary_addresses"] and
                          msg_dict['fromAddress'] not in access["secondary_addresses"]):
                logger.error("{}: Unauthorized Admin message. Deleting.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                nexus.trash_message(msg_dict["msgid"])
                return
        else:
            logger.error("{}: Admin message: Chan not found".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            nexus.trash_message(msg_dict["msgid"])
            return

    logger.info("{}: Admin message received from {} for {} is authentic".format(
        msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['fromAddress'], msg_dict['toAddress']))

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

    access = get_access(msg_dict['toAddress'])

    # (Owner): set board options
    if (admin_dict["action"] == "set" and
            admin_dict["action_type"] == "options" and
            msg_dict['fromAddress'] in access["primary_addresses"]):
        admin_set_options(msg_dict, admin_dict)

    # (Owner, Admin): delete board thread or post
    elif (admin_dict["action"] == "delete" and
          admin_dict["chan_type"] == "board" and
          (msg_dict['fromAddress'] in access["primary_addresses"] or
           msg_dict['fromAddress'] in access["secondary_addresses"])):
        admin_delete_from_board(msg_dict, admin_dict)

    # (Owner, Admin): delete board post with comment
    elif (admin_dict["action"] == "delete_comment" and
          admin_dict["action_type"] == "post" and
          "options" in admin_dict and
          "delete_comment" in admin_dict["options"] and
          "message_id" in admin_dict["options"]["delete_comment"] and
          "comment" in admin_dict["options"]["delete_comment"] and
          (msg_dict['fromAddress'] in access["primary_addresses"] or
           msg_dict['fromAddress'] in access["secondary_addresses"])):
        admin_delete_from_board_with_comment(msg_dict, admin_dict)

    # (Owner, Admin): Ban user
    elif (admin_dict["action"] == "ban" and
          admin_dict["action_type"] == "ban_address" and
          admin_dict["options"] and
          "ban_address" in admin_dict["action_type"] and
          (msg_dict['fromAddress'] in access["primary_addresses"] or
           msg_dict['fromAddress'] in access["secondary_addresses"])):
        admin_ban_address_from_board(msg_dict, admin_dict)

    else:
        logger.error("{}: Unknown Admin command. Deleting. {}".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict))
        nexus.trash_message(msg_dict["msgid"])


def parse_message(message_id, json_obj):
    from bitchan_flask import nexus

    file_decoded = None
    file_filename = None
    file_url_type = None
    file_url = None
    file_upload_settings = None
    file_extracts_start_base64 = None
    file_size = None
    file_amount = None
    file_sha256_hash = None
    file_enc_cipher = None
    file_enc_key_bytes = None
    file_enc_password = None
    file_sha256_hashes_match = False
    file_download_successful = False
    file_order = None
    media_info = {}
    upload_filename = None
    saved_file_filename = None
    saved_image_thumb_filename = None
    image1_spoiler = None
    image2_spoiler = None
    image3_spoiler = None
    image4_spoiler = None
    op_sha256_hash = None
    message = None
    nation = None
    nation_base64 = None
    nation_name = None
    message_steg = {}
    file_do_not_download = False
    file_path = None

    dict_msg = json_obj['message_decrypted']

    # SHA256 hash of the original encrypted message payload to identify the OP of the thread.
    # Each reply must identify the thread it's replying to by supplying the OP hash.
    # If the OP hash doesn't exist, a new thread is created.
    # This prevents OP hijacking by impersonating an OP with an earlier send timestamp.
    message_sha256_hash = hashlib.sha256(json.dumps(json_obj['message']).encode('utf-8')).hexdigest()
    # logger.info("Message SHA256: {}".format(message_sha256_hash))

    # Check if message properly formatted, delete if not.
    if "subject" not in dict_msg or not dict_msg["subject"]:
        logger.error("{}: Message missing required subject. Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
        nexus.trash_message(message_id)
        return
    else:
        subject = html.escape(base64.b64decode(dict_msg["subject"]).decode('utf-8')).strip()
        if len(base64.b64decode(dict_msg["subject"]).decode('utf-8')) > 64:
            logger.error("{}: Subject too large. Deleting".format(message_id[-config.ID_LENGTH:].upper()))
            nexus.trash_message(message_id)
            return

    if "version" not in dict_msg or not dict_msg["version"]:
        logger.error("{}: Message has no version. Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
        nexus.trash_message(message_id)
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
    if "op_sha256_hash" in dict_msg and dict_msg["op_sha256_hash"]:
        op_sha256_hash = dict_msg["op_sha256_hash"]

    # Determine if message is an OP or a reply
    if is_op:
        thread_id = get_thread_id(message_sha256_hash)
    elif op_sha256_hash:
        thread_id = get_thread_id(op_sha256_hash)
    else:
        logger.error("{}: Message neither OP nor reply: Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
        nexus.trash_message(message_id)
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
            logger.error("{}: Admin deleted this post or thread".format(message_id[-config.ID_LENGTH:].upper()))
            nexus.trash_message(message_id)
            return

    if ("timestamp_utc" in dict_msg and dict_msg["timestamp_utc"] and
            isinstance(dict_msg["timestamp_utc"], int)):
        timestamp_sent = dict_msg["timestamp_utc"]
    else:
        timestamp_sent = int(json_obj['receivedTime'])

    log_age_and_expiration(
        message_id,
        nexus.get_utc(),
        timestamp_sent,
        get_msg_expires_time(message_id))

    # Check if board is set to automatically clear and message is older than the last clearing
    if chan_auto_clears_and_message_too_old(json_obj['toAddress'], timestamp_sent):
        logger.info("{}: Message outside current auto clear period. Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
        nexus.trash_message(message_id)
        return

    if "message" in dict_msg and dict_msg["message"]:
        message = dict_msg["message"]
    if "file_filename" in dict_msg and dict_msg["file_filename"]:
        file_filename = dict_msg["file_filename"]
        logger.info("{} Filename on post: {}".format(message_id[-config.ID_LENGTH:].upper(), dict_msg["file_filename"]))
    if "image1_spoiler" in dict_msg and dict_msg["image1_spoiler"]:
        image1_spoiler = dict_msg["image1_spoiler"]
    if "image2_spoiler" in dict_msg and dict_msg["image2_spoiler"]:
        image2_spoiler = dict_msg["image2_spoiler"]
    if "image3_spoiler" in dict_msg and dict_msg["image3_spoiler"]:
        image3_spoiler = dict_msg["image3_spoiler"]
    if "image4_spoiler" in dict_msg and dict_msg["image4_spoiler"]:
        image4_spoiler = dict_msg["image4_spoiler"]
    if "upload_filename" in dict_msg and dict_msg["upload_filename"]:
        upload_filename = dict_msg["upload_filename"]
    if "file_size" in dict_msg and dict_msg["file_size"]:
        file_size = dict_msg["file_size"]
    if "file_amount" in dict_msg and dict_msg["file_amount"]:
        file_amount = dict_msg["file_amount"]
    if "file_url" in dict_msg and dict_msg["file_url"]:
        file_url = dict_msg["file_url"]
    if "file_url_type" in dict_msg and dict_msg["file_url_type"]:
        file_url_type = dict_msg["file_url_type"]
    if "file_upload_settings" in dict_msg and dict_msg["file_upload_settings"]:
        file_upload_settings = dict_msg["file_upload_settings"]
    if "file_extracts_start_base64" in dict_msg and dict_msg["file_extracts_start_base64"] is not None:
        file_extracts_start_base64 = json.loads(dict_msg["file_extracts_start_base64"])
    if "file_base64" in dict_msg and dict_msg["file_base64"] is not None:
        try:
            file_decoded = base64.b64decode(dict_msg["file_base64"])
            file_size = len(file_decoded)
        except Exception as err:
            logger.exception("{}: Exception decoding attachments: {}".format(message_id[-config.ID_LENGTH:].upper(), err))
    if "file_sha256_hash" in dict_msg and dict_msg["file_sha256_hash"]:
        file_sha256_hash = dict_msg["file_sha256_hash"]
    if "file_enc_cipher" in dict_msg and dict_msg["file_enc_cipher"]:
        file_enc_cipher = dict_msg["file_enc_cipher"]
    if "file_enc_key_bytes" in dict_msg and dict_msg["file_enc_key_bytes"]:
        file_enc_key_bytes = dict_msg["file_enc_key_bytes"]
    if "file_enc_password" in dict_msg and dict_msg["file_enc_password"]:
        file_enc_password = dict_msg["file_enc_password"]
    if "file_order" in dict_msg and dict_msg["file_order"]:
        file_order = dict_msg["file_order"]

    if "nation" in dict_msg and dict_msg["nation"]:
        nation = dict_msg["nation"]
    if "nation_base64" in dict_msg and dict_msg["nation_base64"]:
        nation_base64 = dict_msg["nation_base64"]
    if "nation_name" in dict_msg and dict_msg["nation_name"]:
        nation_name = dict_msg["nation_name"]

    if nation_base64:
        flag_pass = True
        try:
            flag = Image.open(BytesIO(base64.b64decode(nation_base64)))
            flag_width, flag_height = flag.size
            if flag_width > config.FLAG_MAX_WIDTH or flag_height > config.FLAG_MAX_HEIGHT:
                flag_pass = False
                logger.error(
                    "Flag dimensions is too large (max 25x15): {}x{}".format(
                        flag_width, flag_height))
            if len(base64.b64decode(nation_base64)) > config.FLAG_MAX_SIZE:
                flag_pass = False
                logger.error(
                    "Flag file size is too large: {}. Must be less than or equal to 3500 bytes.".format(
                        len(base64.b64decode(nation_base64))))
        except:
            flag_pass = False
            logger.error("Error attempting to open flag image")

        if not nation_name:
            flag_pass = False
            logger.error("{}: Flag name not found".format(message_id[-config.ID_LENGTH:].upper()))
        elif len(nation_name) > 64:
            flag_pass = False
            logger.error("{}: Flag name too long: {}".format(message_id[-config.ID_LENGTH:].upper(), nation_name))

        if not flag_pass:
            logger.error("{}: Base64 flag didn't pass validation. Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
            nexus.trash_message(message_id)
            return

    if file_url or file_decoded:
        save_dir = "{}/{}".format(config.FILE_DIRECTORY, message_id)
        try:
            os.mkdir(save_dir)
        except:
            pass
        saved_file_filename = "{}.zip".format(message_id)
        file_path = "{}/{}".format(config.FILE_DIRECTORY, saved_file_filename)

    if file_url:
        # Create dir to extract files into
        logger.info("{}: Filename on disk: {}".format(message_id[-config.ID_LENGTH:].upper(), saved_file_filename))

        if os.path.exists(file_path) and os.path.getsize(file_path) != 0:
            logger.info("{}: Downloaded zip file found. Not attempting to download.".format(message_id[-config.ID_LENGTH:].upper()))
            file_size_test = os.path.getsize(file_path)
            file_download_successful = True
            extract_zip(message_id, file_path, save_dir)
        else:
            logger.info("{}: File not found. Attempting to download.".format(message_id[-config.ID_LENGTH:].upper()))
            logger.info("{}: Downloading file url: {}".format(message_id[-config.ID_LENGTH:].upper(), file_url))

            if upload_filename and file_url_type and file_upload_settings:
                # Pick a download slot to fill (2 slots per domain)
                domain = urlparse(file_url).netloc
                lockfile1 = "/var/lock/upload_{}_1.lock".format(domain)
                lockfile2 = "/var/lock/upload_{}_2.lock".format(domain)

                lf = LF()
                lockfile = random.choice([lockfile1, lockfile2])
                if lf.lock_acquire(lockfile, to=600):
                    try:
                        (file_download_successful,
                         file_size_test,
                         file_amount_test,
                         file_do_not_download,
                         file_sha256_hashes_match,
                         media_info,
                         message_steg) = download_and_extract(
                            json_obj['toAddress'],
                            message_id,
                            file_url,
                            file_upload_settings,
                            file_extracts_start_base64,
                            upload_filename,
                            file_path,
                            file_sha256_hash,
                            file_enc_cipher,
                            file_enc_key_bytes,
                            file_enc_password)

                        if file_size_test:
                            file_size = file_size_test

                        if file_amount_test:
                            file_amount = file_amount_test
                    finally:
                        lf.lock_release(lockfile)

        if file_download_successful:
            for dirpath, dirnames, filenames in os.walk(save_dir):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if os.path.islink(fp):  # skip symbolic links
                        continue

                    file_extension = html.escape(os.path.splitext(f)[1].split(".")[-1].lower())
                    if not file_extension:
                        logger.error("{}: File extension not found. Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
                        nexus.trash_message(message_id)
                        return
                    elif len(file_extension) >= config.MAX_FILE_EXT_LENGTH:
                        logger.error(
                            "{}: File extension greater than {} characters. Deleting.".format(
                                message_id[-config.ID_LENGTH:].upper(), config.MAX_FILE_EXT_LENGTH))
                        nexus.trash_message(message_id)
                        return
                    if file_extension in config.FILE_EXTENSIONS_IMAGE:
                        saved_image_thumb_filename = "{}_thumb.{}".format(message_id, file_extension)
                        img_thumb_filename = "{}/{}".format(save_dir, saved_image_thumb_filename)
                        generate_thumbnail(message_id, fp, img_thumb_filename, file_extension)

    if file_decoded:
        encrypted_zip = "/tmp/{}.zip".format(
            get_random_alphanumeric_string(12, with_punctuation=False, with_spaces=False))
        # encrypted_zip_object = BytesIO(file_decoded)
        output_file = open(encrypted_zip, 'wb')
        output_file.write(file_decoded)
        output_file.close()

        if file_enc_cipher == "NONE":
            logger.info("{}: File not encrypted".format(message_id[-config.ID_LENGTH:].upper()))
            decrypted_zip = encrypted_zip
        elif file_enc_password:
            # decrypt file
            decrypted_zip = "/tmp/{}.zip".format(
                get_random_alphanumeric_string(12, with_punctuation=False, with_spaces=False))
            delete_file(decrypted_zip)  # make sure no file already exists
            logger.info("{}: Decrypting file".format(message_id[-config.ID_LENGTH:].upper()))

            try:
                ret_crypto = crypto_multi_decrypt(
                    file_enc_cipher,
                    file_enc_password + config.PGP_PASSPHRASE_ATTACH,
                    encrypted_zip,
                    decrypted_zip,
                    key_bytes=file_enc_key_bytes)
                if not ret_crypto:
                    logger.error("{}: Issue decrypting file")
                logger.info("{}: Finished decrypting file".format(message_id[-config.ID_LENGTH:].upper()))

                delete_file(encrypted_zip)
                # z = zipfile.ZipFile(download_path)
                # z.setpassword(config.PGP_PASSPHRASE_ATTACH.encode())
                # z.extract(extract_filename, path=extract_path)
            except Exception:
                logger.exception("Error decrypting file")

        # Get the number of files in the zip archive
        file_amount_test = count_files_in_zip(message_id, decrypted_zip)
        if file_amount_test:
            file_amount = file_amount_test

        if file_amount > config.FILE_ATTACHMENTS_MAX:
            logger.info("{}: Number of attachments ({}) exceed the maximum ({}).".format(
                message_id[-config.ID_LENGTH:].upper(), file_amount, config.FILE_ATTACHMENTS_MAX))
            nexus.trash_message(message_id)
            return

        # Extract zip archive
        extract_path = "{}/{}".format(config.FILE_DIRECTORY, message_id)
        extract_zip(message_id, decrypted_zip, extract_path)
        delete_file(decrypted_zip)  # Secure delete

        errors_files, media_info, message_steg = process_attachments(message_id, extract_path)

        if errors_files:
            logger.error(
                "{}: File extension greater than {} characters. Deleting.".format(
                    message_id[-config.ID_LENGTH:].upper(), config.MAX_FILE_EXT_LENGTH))
            delete_files_recursive(extract_path)
            nexus.trash_message(message_id)
            return

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
        try:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_id).first()
            if not thread and is_op:  # OP received, create new thread
                chan = new_session.query(Chan).filter(
                    Chan.address == json_obj['toAddress']).first()
                new_thread = Threads()
                new_thread.thread_hash = thread_id
                new_thread.op_sha256_hash = message_sha256_hash
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
                new_thread.op_sha256_hash = op_sha256_hash
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
            new_msg.message_sha256_hash = message_sha256_hash
            new_msg.is_op = is_op
            new_msg.message = message
            new_msg.subject = subject
            new_msg.nation = nation
            new_msg.nation_base64 = nation_base64
            new_msg.nation_name = nation_name
            if file_decoded == b"":  # Empty file
                new_msg.file_decoded = b" "
            else:
                new_msg.file_decoded = file_decoded
            new_msg.file_filename = file_filename
            new_msg.file_url = file_url
            new_msg.file_upload_settings = json.dumps(file_upload_settings)
            new_msg.file_extracts_start_base64 = json.dumps(file_extracts_start_base64)
            new_msg.file_size = file_size
            new_msg.file_amount = file_amount
            new_msg.file_do_not_download = file_do_not_download
            new_msg.file_sha256_hash = file_sha256_hash
            new_msg.file_enc_cipher = file_enc_cipher
            new_msg.file_enc_key_bytes = file_enc_key_bytes
            new_msg.file_enc_password = file_enc_password
            new_msg.file_sha256_hashes_match = file_sha256_hashes_match
            new_msg.file_order = json.dumps(file_order)
            new_msg.file_download_successful = file_download_successful
            new_msg.upload_filename = upload_filename
            new_msg.saved_file_filename = saved_file_filename
            new_msg.saved_image_thumb_filename = saved_image_thumb_filename
            new_msg.image1_spoiler = image1_spoiler
            new_msg.image2_spoiler = image2_spoiler
            new_msg.image3_spoiler = image3_spoiler
            new_msg.image4_spoiler = image4_spoiler
            new_msg.timestamp_received = int(json_obj['receivedTime'])
            new_msg.timestamp_sent = timestamp_sent
            new_msg.media_info = json.dumps(media_info)
            new_msg.message_steg = json.dumps(message_steg)
            new_msg.message_original = json_obj["message"]
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
        except:
            logger.error(
                "{}: Could not write to database. Deleting.".format(
                    message_id[-config.ID_LENGTH:].upper()))
            nexus.trash_message(message_id)
            return
