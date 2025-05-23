import base64
import hashlib
import html
import json
import logging
import os
import random
import re
import time
import zipfile
from io import BytesIO
from urllib.parse import urlparse
from sqlalchemy.exc import IntegrityError
import bleach
import qbittorrentapi
from PIL import Image
from sqlalchemy import and_
from torf import Torrent

import config
from bitchan_client import DaemonCom
from database.models import BanedWords
from database.models import Chan
from database.models import Command
from database.models import DeletedThreads
from database.models import Games
from database.models import GlobalSettings
from database.models import Messages
from database.models import PostCards
from database.models import Threads
from database.models import UploadTorrents
from database.utils import session_scope
from utils.download import download_and_extract
from utils.download import process_attachments
from utils.encryption import crypto_multi_decrypt
from utils.files import LF
from utils.files import count_files_in_zip
from utils.files import delete_file
from utils.files import delete_files_recursive
from utils.files import extract_zip
from utils.files import generate_thumbnail_image
from utils.files import human_readable_size
from utils.files import return_file_hashes
from utils.game import update_game
from utils.gateway import api
from utils.gateway import chan_auto_clears_and_message_too_old
from utils.gateway import delete_and_replace_comment
from utils.gateway import log_age_and_expiration
from utils.general import get_random_alphanumeric_string
from utils.general import get_thread_id
from utils.general import process_passphrase
from utils.gpg import find_gpg
from utils.gpg import gpg_decrypt
from utils.hashcash import verify_token
from utils.message_admin_command import admin_ban_address_from_board
from utils.message_admin_command import admin_delete_from_board
from utils.message_admin_command import admin_delete_from_board_with_comment
from utils.message_admin_command import admin_set_options
from utils.message_admin_command import admin_set_thread_options
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.posts import file_hash_banned
from utils.posts import process_message_replies
from utils.replacements import process_replacements
from utils.replacements import replace_strings
from utils.shared import add_mod_log_entry
from utils.shared import can_address_create_thread
from utils.shared import check_tld_i2p
from utils.shared import get_access
from utils.shared import get_msg_expires_time
from utils.shared import get_post_id
from utils.shared import regenerate_card_popup_post_html

logger = logging.getLogger('bitchan.parse')
daemon_com = DaemonCom()


def parse_message(message_id, json_obj):
    file_decoded = None
    file_filename = None
    file_url_type = None
    file_url = None
    file_torrent_file_hash = None
    file_torrent_hash = None
    file_torrent_decoded = None
    file_torrent_magnet = None
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
    file_progress = None
    media_info = {}
    upload_filename = None
    saved_file_filename = None
    saved_image_thumb_filename = None
    image1_spoiler = None
    image2_spoiler = None
    image3_spoiler = None
    image4_spoiler = None
    op_sha256_hash = None
    sage = False
    game = None
    game_hash = None
    original_message = None
    message = None
    nation = None
    nation_base64 = None
    nation_name = None
    message_steg = {}
    file_do_not_download = False
    file_path = None
    delete_password_hash = None
    text_replacements = None
    gpg_texts = {}
    timestamp_sent = None
    pow_method = None
    pow_difficulty = None
    pow_repetitions = None
    pow_token = None
    pow_filter_value = 0
    thread_rules = {}

    game_password_a = None
    game_password_b_hash = None
    game_player_move = None
    game_termination_password = None
    game_termination_pw_hash = None

    orig_op_bm_json_obj = None
    process_op_json_obj = False

    log_id = message_id[-config.ID_LENGTH:].upper()

    if message_id != json_obj["msgid"]:
        logger.error(f"{log_id}: Message ID provided doesn't match what's found in the message payload. Deleting")
        daemon_com.trash_message(message_id)
        return

    dict_msg = json_obj['message_decrypted']

    # logger.info(f"dict_msg: {dict_msg}")

    if ("timestamp_utc" in dict_msg and dict_msg["timestamp_utc"] and
            isinstance(dict_msg["timestamp_utc"], int)):
        timestamp_sent = dict_msg["timestamp_utc"]
    elif 'receivedTime' in json_obj:
        timestamp_sent = int(json_obj['receivedTime'])

    # SHA256 hash of the original encrypted message payload to identify the OP of the thread.
    # Each reply must identify the thread it's replying to by supplying the OP hash.
    # If the OP hash doesn't exist, a new thread is created.
    # This prevents OP hijacking by impersonating an OP with an altered payload.
    message_sha256_hash = hashlib.sha256(json.dumps(json_obj['message']).encode('utf-8')).hexdigest()

    # Check if message properly formatted, delete if not.
    if "subject" not in dict_msg or not dict_msg["subject"]:
        logger.error("{}: Message missing required subject. Deleting.".format(log_id))
        daemon_com.trash_message(message_id)
        return
    else:
        subject = html.escape(base64.b64decode(dict_msg["subject"]).decode('utf-8')).strip()
        if len(base64.b64decode(dict_msg["subject"]).decode('utf-8')) > 64:
            logger.error("{}: Subject too large. Deleting".format(log_id))
            daemon_com.trash_message(message_id)
            return

    if "version" not in dict_msg or not dict_msg["version"]:
        logger.error("{}: Message has no version. Deleting.".format(log_id))
        daemon_com.trash_message(message_id)
        return
    else:
        version = dict_msg["version"]

    # Determine if message indicates it's OP or not
    if "is_op" in dict_msg and dict_msg["is_op"]:
        is_op = dict_msg["is_op"]

        # Check if new threads can be created by this address
        if not can_address_create_thread(json_obj['fromAddress'], json_obj['toAddress']):
            logger.error("{}: {} not permitted to create new thread on {}. Deleting.".format(
                log_id, json_obj['fromAddress'], json_obj['toAddress']))
            daemon_com.trash_message(message_id)
            return
    else:
        is_op = False
        if "sage" in dict_msg and dict_msg["sage"]:
            sage = True

    # Determine if message indicates if it's a reply to an OP by supplying OP hash
    if "op_sha256_hash" in dict_msg and dict_msg["op_sha256_hash"]:
        op_sha256_hash = dict_msg["op_sha256_hash"]

    # Determine if message is an OP or a reply
    if is_op:
        # A thread ID is generated from the hash of the OP message
        # This ensures the authenticity if an OP of a thread is received after a reply
        thread_id = get_thread_id(message_sha256_hash)
    elif op_sha256_hash:
        # A reply provides the OP hash to generate the thread ID
        thread_id = get_thread_id(op_sha256_hash)
    else:
        logger.error(f"{log_id}: Message neither OP nor reply: Deleting.")
        daemon_com.trash_message(message_id)
        return

    # Thread Rules
    if "thread_rules" in dict_msg and dict_msg["thread_rules"]:
        for each_rule in dict_msg["thread_rules"]:
            if each_rule not in config.DICT_THREAD_RULES:
                logger.error(f"{log_id}: Unknown Thread Rule '{each_rule}': Deleting.")
                daemon_com.trash_message(message_id)
                return
        thread_rules = dict_msg["thread_rules"]

    with session_scope(config.DB_PATH) as new_session:
        deleted_thread = new_session.query(DeletedThreads).filter(
            DeletedThreads.thread_hash == thread_id).first()
        if deleted_thread:
            log_description = f"{log_id}: Deleting post that arrived for deleted thread"
            if deleted_thread.subject:
                log_description += f' "{deleted_thread.subject}"'
            log_description += "."
            add_mod_log_entry(
                log_description,
                message_id=message_id,
                board_address=json_obj['toAddress'],
                thread_hash=thread_id)
            logger.error(f"{log_id}: Message is for a deleted thread: Deleting.")
            daemon_com.trash_message(message_id)
            return

    # Now that the thread_is id determined, check if there exists an Admin command
    # instructing the deletion of the thread/message
    with session_scope(config.DB_PATH) as new_session:
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
            logger.error(f"{log_id}: Admin deleted this post or thread")
            daemon_com.trash_message(message_id)
            return

    log_age_and_expiration(
        message_id,
        daemon_com.get_utc(),
        timestamp_sent,
        get_msg_expires_time(message_id))

    # Check if board is set to automatically clear and message is older than the last clearing
    if chan_auto_clears_and_message_too_old(json_obj['toAddress'], timestamp_sent):
        logger.info("{}: Message sent before auto wipe for {}. Deleting.".format(
            log_id, json_obj['toAddress']))
        daemon_com.trash_message(message_id)
        return

    if "message" in dict_msg and dict_msg["message"]:
        message = dict_msg["message"]

    # Check for banned words in message/subject
    with session_scope(config.DB_PATH) as new_session:
        banned_word_table = new_session.query(BanedWords).all()
        banned_words = []
        for word_entry in banned_word_table:
            # Check if board is defined
            if word_entry.only_board_address and json_obj['toAddress'] not in word_entry.only_board_address:
                continue

            if (word_entry.word and not word_entry.is_regex and
                    (
                        (message and word_entry.word in message) or
                        (subject and word_entry.word in subject)
                    )):
                banned_words.append(f'word="{word_entry.word}"')
            elif (word_entry.word and word_entry.is_regex and
                    (
                        (message and re.findall(word_entry.word, message)) or
                        (subject and re.findall(word_entry.word, subject))
                    )):
                banned_words.append(f'regex="{word_entry.word}"')

        if banned_words:
            log_entry = f'Post contains banned word(s)/regex(s): {", ".join(banned_words)}. Deleting'
            logger.info(f"{log_id}: {log_entry}")
            add_mod_log_entry(
                log_entry,
                message_id=message_id,
                board_address=json_obj['toAddress'],
                thread_hash=thread_id)
            daemon_com.trash_message(message_id)
            return

    subject = replace_strings(subject, address=json_obj['toAddress'])  # word replacements

    if "file_filename" in dict_msg and dict_msg["file_filename"]:
        file_filename = dict_msg["file_filename"]
        logger.info(
            "{} Filename on post: {}".format(log_id, dict_msg["file_filename"]))
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
    if "file_torrent_file_hash" in dict_msg and dict_msg["file_torrent_file_hash"]:
        file_torrent_file_hash = dict_msg["file_torrent_file_hash"]
    if "file_torrent_hash" in dict_msg and dict_msg["file_torrent_hash"]:
        file_torrent_hash = dict_msg["file_torrent_hash"]
    if "file_torrent_magnet" in dict_msg and dict_msg["file_torrent_magnet"]:
        file_torrent_magnet = dict_msg["file_torrent_magnet"]
    if "file_torrent_base64" in dict_msg and dict_msg["file_torrent_base64"]:
        try:
            file_torrent_decoded = base64.b64decode(dict_msg["file_torrent_base64"])
            file_torrent_size = len(file_torrent_decoded)
        except Exception as err:
            logger.exception(
                "{}: Exception decoding base64 torrent attachment: {}".format(
                    log_id, err))
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
            logger.exception(
                "{}: Exception decoding attachments: {}".format(
                    log_id, err))
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
    if "delete_password_hash" in dict_msg and dict_msg["delete_password_hash"]:
        delete_password_hash = dict_msg["delete_password_hash"]

    # Games
    if "game" in dict_msg and dict_msg["game"]:
        game = dict_msg["game"]
    if "game_hash" in dict_msg and dict_msg["game_hash"]:
        game_hash = dict_msg["game_hash"]
    if "game_termination_password" in dict_msg and dict_msg["game_termination_password"]:
        game_termination_password = dict_msg["game_termination_password"]
    if "game_termination_pw_hash" in dict_msg and dict_msg["game_termination_pw_hash"]:
        game_termination_pw_hash = dict_msg["game_termination_pw_hash"]
    if "game_password_a" in dict_msg and dict_msg["game_password_a"]:
        game_password_a = dict_msg["game_password_a"]
    if "game_password_b_hash" in dict_msg and dict_msg["game_password_b_hash"]:
        game_password_b_hash = dict_msg["game_password_b_hash"]
    if "game_player_move" in dict_msg and dict_msg["game_player_move"]:
        game_player_move = dict_msg["game_player_move"]

    if "orig_op_bm_json_obj" in dict_msg and dict_msg["orig_op_bm_json_obj"]:
        orig_op_bm_json_obj = dict_msg["orig_op_bm_json_obj"]

    if ((file_amount and file_amount > 4) or
            (file_order and len(file_order) > 4)):
        logger.error("{}: More than 4 files found in message. Deleting.".format(log_id))
        daemon_com.trash_message(message_id)
        return

    # Check if POW required and if token can be verified
    if "pow_method" in dict_msg and dict_msg["pow_method"]:
        pow_method = dict_msg["pow_method"]
    if "pow_difficulty" in dict_msg and dict_msg["pow_difficulty"]:
        pow_difficulty = dict_msg["pow_difficulty"]
    if "pow_repetitions" in dict_msg and dict_msg["pow_repetitions"]:
        pow_repetitions = dict_msg["pow_repetitions"]
    if "pow_token" in dict_msg and dict_msg["pow_token"]:
        pow_token = dict_msg["pow_token"]

    if pow_method and pow_difficulty and pow_repetitions and pow_token:
        logger.info(f"{log_id}: POW Method: {pow_method}, Difficulty: {pow_difficulty}, "
                    f"Repetitions: {pow_repetitions}, Token(s): {pow_token}")

    #
    # Board Rules
    #

    with session_scope(config.DB_PATH) as new_session:
        try:
            chan = new_session.query(Chan).filter(Chan.address == json_obj['toAddress']).first()
            try:
                rules = json.loads(chan.rules)
            except:
                rules = {}

            if "require_attachments" in rules and not file_amount:
                logger.error(f"{log_id}: Message requires attachment and none found. Deleting message.")
                daemon_com.trash_message(message_id)
                return

            # Check if a message with the same POW token(s) exists
            if pow_difficulty and pow_repetitions and pow_token:
                message_test = new_session.query(Messages).filter(and_(
                    Messages.pow_token == json.dumps(pow_token),
                    Messages.pow_difficulty == pow_difficulty,
                    Messages.pow_repetitions == int(pow_repetitions),
                    Messages.timestamp_sent == timestamp_sent)).first()
                if message_test:
                    logger.error(f"{log_id}: Message with POW token already exists. Deleting message.")
                    daemon_com.trash_message(message_id)
                    return

            # If POW Rule found, ensure message conforms to the minimum requirements for the rule
            if "require_pow_to_post" in rules:
                # Check if POW Rule is valid
                if "pow_method" not in rules["require_pow_to_post"]:
                    logger.error(f"{log_id}: Rule missing POW method. Deleting message.")
                    daemon_com.trash_message(message_id)
                    return
                if "pow_difficulty" not in rules["require_pow_to_post"]:
                    logger.error(f"{log_id}: Rule missing POW difficulty. Deleting message.")
                    daemon_com.trash_message(message_id)
                    return
                if "pow_repetitions" not in rules["require_pow_to_post"]:
                    logger.error(f"{log_id}: Rule missing POW repetitions. Deleting message.")
                    daemon_com.trash_message(message_id)
                    return
                if len(pow_token) < int(rules["require_pow_to_post"]["pow_repetitions"]):
                    logger.error(f"{log_id}: Rule specifies {rules['require_pow_to_post']['pow_repetitions']} POW "
                                 f"repetitions, but only {len(pow_token)} tokens provided. Deleting message.")
                    daemon_com.trash_message(message_id)
                    return

                if not pow_method or not pow_difficulty or not pow_repetitions or not pow_token:
                    logger.error(f"{log_id}: Message missing POW method, difficulty, repetitions, or token(s). "
                                 f"Deleting message.")
                    daemon_com.trash_message(message_id)
                    return

                # Check POW meets rule requirements
                if rules["require_pow_to_post"]["pow_method"] == "hashcash":
                    if (int(pow_difficulty) >= int(rules["require_pow_to_post"]["pow_difficulty"]) and
                            len(pow_token) >= int(rules["require_pow_to_post"]["pow_repetitions"])):

                        for i in range(int(rules["require_pow_to_post"]["pow_repetitions"])):
                            challenge = json.dumps({
                                "msg": dict_msg["original_message"],
                                "time": dict_msg["timestamp_utc"],
                                "rep": i
                            }).encode()
                            verify = verify_token(challenge, pow_token[i], int(pow_difficulty))
                            logger.info(f"{log_id}: Rule Post POW verify {i}: {verify}")
                            if not verify:
                                logger.error(f"{log_id}: Invalid POW token {i}. Deleting message.")
                                daemon_com.trash_message(message_id)
                                return
                            else:
                                pow_filter_value = (2**int(pow_difficulty)) * int(rules["require_pow_to_post"]["pow_repetitions"])
                    else:
                        logger.error(f"{log_id}: Message POW difficulty or repetitions too low. Deleting message.")
                        daemon_com.trash_message(message_id)
                        return
                else:
                    logger.error(f"{log_id}: Unknown rule POW method "
                                 f"'{rules['require_pow_to_post']['pow_method']}'. Deleting message.")
                    daemon_com.trash_message(message_id)
                    return

            # No POW rule but found POW data, so simply verify the token that was provided in the message
            elif pow_method and pow_token and pow_difficulty and pow_repetitions:
                if pow_method == "hashcash":
                    for i in range(pow_repetitions):
                        challenge = json.dumps({
                            "msg": dict_msg["original_message"],
                            "time": dict_msg["timestamp_utc"],
                            "rep": i
                        }).encode()
                        verify = verify_token(challenge, pow_token[i], int(pow_difficulty))
                        logger.info(f"{log_id}: Post POW verify {i}: {verify}")
                        if not verify:
                            logger.error(f"{log_id}: Could not verify POW token {i}. Deleting message.")
                            daemon_com.trash_message(message_id)
                            return
                        else:
                            pow_filter_value = (2**int(pow_difficulty)) * pow_repetitions
                else:
                    logger.error(f"{log_id}: Unknown message POW method "
                                 f"'{rules['require_pow_to_post']['pow_method']}'. Deleting message.")
                    daemon_com.trash_message(message_id)
                    return
        except:
            logger.exception(f"{log_id}: Message POW exception. Deleting message.")
            daemon_com.trash_message(message_id)
            return

    # Flag
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
            logger.error("{}: Flag name not found".format(
                log_id))
        elif len(nation_name) > 64:
            flag_pass = False
            logger.error("{}: Flag name too long: {}".format(
                log_id, nation_name))

        if not flag_pass:
            logger.error(
                "{}: Base64 flag didn't pass validation. Deleting.".format(
                    log_id))
            daemon_com.trash_message(message_id)
            return

    # Get attachment info if it needs to be downloaded
    save_dir = None
    if file_url or file_decoded:
        save_dir = "{}/{}".format(config.FILE_DIRECTORY, message_id)
        try:
            os.mkdir(save_dir)
        except:
            pass
        saved_file_filename = "{}.zip".format(message_id)
        file_path = "{}/{}".format(config.FILE_DIRECTORY, saved_file_filename)

    # check for banned file hashes
    banned_hashes = file_hash_banned(return_file_hashes(media_info), address=json_obj['toAddress'])
    if media_info and banned_hashes:
        logger.error(f"{log_id}: File hash banned. Deleting.")
        delete_files_recursive(save_dir)
        daemon_com.trash_message(message_id)
        add_mod_log_entry(
            f"Automatically deleted post with "
            f"banned file attachment hashes {', '.join(map(str, banned_hashes))}",
            message_id=message_id,
            board_address=json_obj['toAddress'],
            thread_hash=thread_id)
        return

    thread_locked = False
    thread_anchored = False
    owner_posting = False
    with session_scope(config.DB_PATH) as new_session:
        try:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_id).first()

            if thread:
                # Lock, anchor options
                admin_cmd = new_session.query(Command).filter(and_(
                    Command.action == "set",
                    Command.action_type == "thread_options",
                    Command.thread_id == thread.thread_hash)).first()
                if admin_cmd:
                    # Check for remote thread lock
                    if (admin_cmd.thread_lock and
                            admin_cmd.thread_lock_ts and
                            timestamp_sent > admin_cmd.thread_lock_ts):
                        thread_locked = "Post timestamp is after remote lock. Deleting."

                    # Check for remote thread anchor
                    if (admin_cmd.thread_anchor and
                            admin_cmd.thread_anchor_ts and
                            timestamp_sent > admin_cmd.thread_anchor_ts):
                        thread_anchored = "Post timestamp is after remote anchor. Not updating thread timestamp."

                # Check for local thread lock
                if thread.locked_local and timestamp_sent > thread.locked_local_ts:
                    thread_locked = "Post timestamp is after local lock. Deleting."

                # Check for local thread anchor
                if thread.anchored_local and timestamp_sent > thread.anchored_local_ts:
                    thread_anchored = "Post timestamp is after local anchor. Not updating thread timestamp."

            if thread_locked:
                chan = new_session.query(Chan).filter(
                    Chan.address == json_obj['toAddress']).first()
                if chan:
                    access = get_access(json_obj['toAddress'])
                    if json_obj['fromAddress'] in access["primary_addresses"]:
                        owner_posting = True
                        logger.error("{}: Owner posting in locked thread. Allowing.".format(
                            log_id))
        except Exception:
            logger.exception("Checking thread lock")

    if thread_locked and not owner_posting:
        logger.info(thread_locked)
        delete_files_recursive(save_dir)
        daemon_com.trash_message(message_id)
        return

    original_message = message

    # Perform general text replacements/modifications before saving to the database
    try:
        text_replacements = process_replacements(message, message_id, message_id, address=json_obj['toAddress'])
        message = text_replacements
    except Exception as err:
        logger.exception("{}: Error processing replacements: {}".format(
            log_id, err))

    # Find GPG strings in message and attempt to decrypt
    if message:
        try:
            message, gpg_texts = find_gpg(message)
            gpg_texts = gpg_decrypt(gpg_texts)
        except Exception as err:
            logger.exception("{}: Error processing gpg: {}".format(
                log_id, err))

    try:
        hide_message = False
        thread_error = False
        thread_created = False

        # First, check Thread Rules
        # Then, check if a thread exists for this post.
        # During this check, a thread may not be found, but may be created before this process creates a thread.
        # If this occurs, there will be a duplicate entry database error.
        # If this error occurs, the next section will check for the thread again.
        try:
            with session_scope(config.DB_PATH) as new_session:
                chan = new_session.query(Chan).filter(
                    Chan.address == json_obj['toAddress']).first()

                thread = new_session.query(Threads).filter(
                    Threads.thread_hash == thread_id).first()

                #
                # Thread Rules
                #

                # Thread rules can only not be checked if the thread doesn't yet exist and a reply is received.
                # This is because only the OP contains the Thread Rules
                # TODO: add periodic check of threads with POW Rules to find replies that don't meet the POW requirement

                thread_rules_ = {}

                if thread:
                    try:
                        thread_rules_ = json.loads(thread.rules)
                    except:
                        thread_rules_ = {}
                elif not thread and is_op:
                    try:
                        thread_rules_ = json.loads(thread_rules)
                    except:
                        thread_rules_ = {}

                if thread_rules_:
                    rule_errors = check_pow_thread_rule(thread_rules_, pow_filter_value)

                    if rule_errors:
                        logger.error(f"{log_id}: POW Thread Rule Error: {', '.join(rule_errors)}")
                        daemon_com.trash_message(message_id)
                        return


                if not thread and is_op:  # OP received, create new thread
                    logger.info(f"{log_id}: Thread doesn't exist and post is OP")

                    new_thread = Threads()
                    new_thread.thread_hash = thread_id
                    new_thread.thread_hash_short = thread_id[-12:]
                    new_thread.op_sha256_hash = message_sha256_hash
                    if chan:
                        new_thread.chan_id = chan.id
                    new_thread.subject = subject
                    new_thread.timestamp_sent = timestamp_sent
                    new_thread.timestamp_received = int(json_obj['receivedTime'])
                    new_thread.orig_op_bm_json_obj = json.dumps(json_obj)
                    new_thread.last_op_json_obj_ts = time.time()
                    new_thread.rules = json.dumps(thread_rules)
                    new_session.add(new_thread)

                    if timestamp_sent > chan.timestamp_sent:
                        chan.timestamp_sent = timestamp_sent
                    if int(json_obj['receivedTime']) > chan.timestamp_received:
                        chan.timestamp_received = int(json_obj['receivedTime'])

                    new_session.commit()
                    thread_created = True

                    id_thread = new_thread.id

                elif not thread and not is_op:  # Reply received before OP, create thread with OP placeholder
                    logger.info(f"{log_id}: Thread doesn't exist and post is a reply")

                    new_thread = Threads()
                    new_thread.thread_hash = thread_id
                    new_thread.thread_hash_short = thread_id[-12:]
                    new_thread.op_sha256_hash = op_sha256_hash
                    if chan:
                        new_thread.chan_id = chan.id
                    new_thread.subject = subject
                    if not sage:
                        new_thread.timestamp_sent = timestamp_sent
                    else:
                        new_thread.timestamp_sent = 0
                    new_thread.timestamp_received = int(json_obj['receivedTime'])
                    new_session.add(new_thread)

                    if timestamp_sent > chan.timestamp_sent and not sage:
                        chan.timestamp_sent = timestamp_sent
                    if int(json_obj['receivedTime']) > chan.timestamp_received:
                        chan.timestamp_received = int(json_obj['receivedTime'])

                    new_session.commit()
                    thread_created = True

                    id_thread = new_thread.id

                    if orig_op_bm_json_obj and 'message' in orig_op_bm_json_obj:
                        logger.info("Found OP data in reply post, checking authenticity.")
                        test_message_sha256_hash = hashlib.sha256(
                            json.dumps(orig_op_bm_json_obj['message']).encode('utf-8')).hexdigest()

                        if op_sha256_hash != test_message_sha256_hash:
                            logger.error(
                                f"OP data hash ({test_message_sha256_hash}) does not match thread hash ({op_sha256_hash}).")
                        else:
                            logger.info("OP data hash matches thread hash.")
                            # process OP json_obj after post added
                            logger.info("Instructing to process OP data found in reply post to heal OP")
                            process_op_json_obj = True

                elif thread and is_op:  # OP received, but reply received beforehand and already created thread
                    logger.info(f"{log_id}: Thread does exist and post is OP")

                    thread.op_sha256_hash = message_sha256_hash
                    if chan:
                        thread.chan_id = chan.id
                    thread.subject = subject
                    thread.timestamp_sent = timestamp_sent
                    thread.timestamp_received = int(json_obj['receivedTime'])
                    thread.orig_op_bm_json_obj = json.dumps(json_obj)
                    thread.last_op_json_obj_ts = time.time()
                    thread.rules = json.dumps(thread_rules)
                    new_session.commit()

        except IntegrityError:
            thread_error = True
            logger.error(
                f"{log_id}: Potential duplicate thread_hash "
                f"(thread created while processing this message?)")
        except Exception as err:
            logger.error(f"{log_id}: Thread check exception: {err}")

        # If thread_error is True and the thread is found, then continue processing the post normally.
        # If thread_error is False and a thread is not found, then log an error and return (don't create post).
        with session_scope(config.DB_PATH) as new_session:
            chan = new_session.query(Chan).filter(
                Chan.address == json_obj['toAddress']).first()

            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_id).first()

            if thread_error and not thread:
                # Unexpected scenario, discard post
                return

            if (thread_error or not thread_created) and thread and not is_op:  # Reply received after OP, add to current thread
                logger.info(f"{log_id}: Thread exists and post is not OP")

                if timestamp_sent > thread.timestamp_sent and not sage and not thread_anchored:
                    thread.timestamp_sent = timestamp_sent
                if int(json_obj['receivedTime']) > thread.timestamp_received and not sage and not thread_anchored:
                    thread.timestamp_received = int(json_obj['receivedTime'])

                if timestamp_sent > chan.timestamp_sent and not sage and not thread_anchored:
                    chan.timestamp_sent = timestamp_sent
                if int(json_obj['receivedTime']) > chan.timestamp_received and not sage and not thread_anchored:
                    chan.timestamp_received = int(json_obj['receivedTime'])

                new_session.commit()

                id_thread = thread.id
                hide_message = thread.hide

                if orig_op_bm_json_obj and 'message' in orig_op_bm_json_obj:
                    logger.info("Found OP data in reply post, checking authenticity.")
                    test_message_sha256_hash = hashlib.sha256(json.dumps(orig_op_bm_json_obj['message']).encode('utf-8')).hexdigest()

                    if thread.op_sha256_hash != test_message_sha256_hash:
                        logger.error(
                            f"OP data hash ({test_message_sha256_hash}) does not match thread hash ({thread.op_sha256_hash}).")
                    else:
                        logger.info("OP data hash matches thread hash.")
                        logger.info("Updating last_op_json_obj_ts with current time")
                        thread.last_op_json_obj_ts = time.time()
                        new_session.commit()

                        # Check if existing thread doesn't have OP json_obj or OP doesn't exist.
                        # If not, process OP json_obj after post added
                        thread_op = new_session.query(Messages).filter(and_(
                            Messages.is_op.is_(True),
                            Messages.thread_id == thread.id)).first()
                        if not thread_op:
                            logger.info("OP for this thread does not exist")
                        else:
                            logger.info("OP for thread exists, not processing OP data found in reply")

                        if thread_op and not thread.orig_op_bm_json_obj:
                            logger.info("Thread is missing orig_op_bm_json_obj. Populating from reply post.")
                            thread.orig_op_bm_json_obj = json.dumps(json_obj)
                            new_session.commit()

                        if not thread_op:
                            logger.info("Instructing to process OP data found in reply post to heal OP")
                            process_op_json_obj = True

            elif (thread_error or not thread_created) and thread and is_op:
                logger.info(f"{log_id}: Thread exists and post is OP")

                # Post indicating it is OP but thread already exists
                # Could have received reply before OP
                # Add OP to current thread
                id_thread = thread.id
                hide_message = thread.hide

                # Check if existing thread has OP json_obj
                if not thread.orig_op_bm_json_obj and json_obj:
                    logger.info(
                        f"{log_id}: Thread found with empty orig_op_bm_json_obj "
                        f"while processing OP. Populating with OP data.")
                    thread.orig_op_bm_json_obj = json.dumps(json_obj)

                thread.last_op_json_obj_ts = time.time()
                new_session.commit()

                thread_op = new_session.query(Messages).filter(and_(
                    Messages.is_op.is_(True),
                    Messages.thread_id == thread.id)).first()
                if thread_op:
                    logger.info(f"{log_id}: OP for thread already present. "
                                "Skipping creation new message entry and updating last_op_json_obj_ts.")
                    return
                else:
                    logger.info("OP not found for thread, continuing to process message as OP")

            elif thread_error or not thread_created:
                # Duplicate thread hash wasn't the previous exception and required rechecking thread
                # Some other error occurred and this post likely needs to be trashed
                # In any case, it's advised to check the log
                logger.error(f"{log_id}: Some other error prevented this message "
                             f"from being processed. Review the log.")
                return

            # Create message
            new_msg = Messages()
            new_msg.version = version
            new_msg.message_id = message_id
            new_msg.post_id = get_post_id(message_id)
            new_msg.expires_time = get_msg_expires_time(message_id)
            new_msg.thread_id = id_thread
            new_msg.address_from = bleach.clean(json_obj['fromAddress'])
            new_msg.message_sha256_hash = message_sha256_hash
            new_msg.is_op = is_op
            new_msg.sage = sage
            new_msg.original_message = original_message
            new_msg.message = message
            new_msg.subject = subject
            new_msg.nation = nation
            new_msg.nation_base64 = nation_base64
            new_msg.nation_name = nation_name
            new_msg.file_decoded = file_decoded
            new_msg.file_filename = file_filename
            new_msg.file_url = file_url
            new_msg.file_torrent_file_hash = file_torrent_file_hash
            new_msg.file_torrent_hash = file_torrent_hash
            new_msg.file_torrent_magnet = file_torrent_magnet
            new_msg.file_torrent_decoded = file_torrent_decoded
            new_msg.file_upload_settings = json.dumps(file_upload_settings)
            new_msg.file_extracts_start_base64 = json.dumps(file_extracts_start_base64)
            new_msg.file_size = file_size
            new_msg.file_amount = file_amount
            new_msg.file_do_not_download = file_do_not_download
            new_msg.file_progress = file_progress
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
            new_msg.delete_password_hash = delete_password_hash
            new_msg.message_steg = json.dumps(message_steg)
            new_msg.message_original = json_obj["message"]
            new_msg.text_replacements = text_replacements
            new_msg.gpg_texts = json.dumps(gpg_texts)
            new_msg.hide = hide_message
            new_msg.pow_method = pow_method
            new_msg.pow_difficulty = pow_difficulty
            new_msg.pow_repetitions = pow_repetitions
            new_msg.pow_token = json.dumps(pow_token)
            new_msg.pow_filter_value = pow_filter_value

            # Games
            new_msg.game_password_a = game_password_a
            new_msg.game_password_b_hash = game_password_b_hash
            new_msg.game_player_move = game_player_move

            # Initialize game
            try:
                test_game = new_session.query(Games).filter(and_(
                    Games.thread_hash == thread_id,
                    Games.game_over.is_(False))).first()

                if game_hash and test_game and test_game.is_host and test_game.game_initiated is None:
                    logger.info("Game found that I'm hosting. Starting initiation.")
                    test_game.game_initiated = "uninitiated"
                elif not test_game and bleach.clean(json_obj['fromAddress']) and game:
                    logger.info("Game not found. I must not be hosting.")
                    new_game = Games()
                    new_game.game_hash = game_hash
                    new_game.thread_hash = thread_id
                    new_game.is_host = False
                    new_game.host_from_address = bleach.clean(json_obj['fromAddress'])
                    new_game.game_type = game
                    new_game.game_termination_pw_hash = game_termination_pw_hash
                    new_session.add(new_game)

                # Generate post
                if game or game_player_move:
                    if new_msg.message is None:
                        new_msg.message = '<span class="god-text">== Game =='
                    else:
                        new_msg.message += '<br/><br/><span class="god-text">== Game =='
                    if game and game in config.GAMES:
                        new_msg.message += '<br/>New Game: {}'.format(config.GAMES[game])
                    if game_termination_password or game_termination_pw_hash:
                        new_msg.message += '<br/>Password (termination): *'
                    if game_password_a:
                        new_msg.message += '<br/>Password (previous): *'
                    if game_password_b_hash:
                        new_msg.message += '<br/>Password (new): *'
                    if game_player_move:
                        new_msg.message += '<br/>Command: {}'.format(game_player_move)
                    new_msg.message += '<br/>==========</span>'
            except:
                logger.exception("parsing message to game post")

            new_msg.post_ids_replied_to = json.dumps(
                process_message_replies(message_id, message, thread_id, json_obj['toAddress']))

            new_session.add(new_msg)

            # Determine if an admin command to delete with comment is present
            # Replace comment and delete file information
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

                    if "from_address" in options["delete_comment"]:
                        from_address = options["delete_comment"]["from_address"]
                    else:
                        from_address = json_obj['fromAddress']

                    # replace comment
                    delete_and_replace_comment(
                        options["delete_comment"]["message_id"],
                        options["delete_comment"]["comment"],
                        from_address=from_address,
                        local_delete=False)

            # regenerate card
            card_test = new_session.query(PostCards).filter(
                PostCards.thread_id == thread_id).first()
            if card_test and not card_test.regenerate:
                card_test.regenerate = True

            new_session.commit()

            # check ongoing games
            if not is_op:
                try:
                    update_game(message_id, dict_msg,
                                game_termination_password=game_termination_password,
                                game_player_move=game_player_move)
                except:
                    logger.exception("update_game()")

            # Delete message from Bitmessage after parsing and adding to BitChan database
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=120):
                try:
                    return_val = api.trashMessage(message_id)
                except Exception as err:
                    logger.error("{}: Exception during message delete: {}".format(
                        log_id, err))
                finally:
                    time.sleep(config.API_PAUSE)
                    lf.lock_release(config.LOCKFILE_API)

    except Exception as err:
        logger.exception(f"{log_id}: Saving message to DB")
        delete_files_recursive(save_dir)
        daemon_com.trash_message(message_id)
    finally:
        time.sleep(config.API_PAUSE)

    #
    # Get Attachments (after post creation to not delay showing post)
    #

    with session_scope(config.DB_PATH) as new_session:
        settings = new_session.query(GlobalSettings).first()

        #
        # Bitmessage attachment
        #
        if file_decoded:
            encrypted_zip = "/tmp/{}.zip".format(
                get_random_alphanumeric_string(12, with_punctuation=False, with_spaces=False))
            # encrypted_zip_object = BytesIO(file_decoded)
            output_file = open(encrypted_zip, 'wb')
            output_file.write(file_decoded)
            output_file.close()

            status, media_info, message_steg = decrypt_and_process_attachments(
                message_id, file_enc_cipher, file_enc_key_bytes, file_enc_password, encrypted_zip)

            if not status:
                msg = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if not msg:
                    return
                msg.media_info = json.dumps(media_info)
                msg.message_steg = json.dumps(message_steg)
                new_session.commit()

        #
        # i2p torrent attachment
        #
        elif (file_torrent_decoded and
                file_torrent_file_hash and
                not settings.disable_downloading_i2p_torrent):
            torrent_prop = None
            torrent_filename = f"{file_torrent_file_hash}.torrent"
            path_torrent_tmp = os.path.join("/tmp", torrent_filename)

            with open(path_torrent_tmp, mode='wb') as f:  # Save torrent file to temporary directory
                f.write(file_torrent_decoded)

            # Ensure all trackers have i2p as the TLD
            t = Torrent.read(path_torrent_tmp)
            logger.info(f"Torrent file with hash {t.infohash}")

            list_trackers = []
            for tracker in t.trackers:
                list_trackers += tracker
            non_i2p_urls = check_tld_i2p(list_trackers)
            if non_i2p_urls:  # Don't allow non-i2p trackers
                update_msg = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if update_msg:
                    update_msg.file_currently_downloading = False
                    update_msg.file_progress = "Non-i2p trackers found in torrent. Torrent discarded."
                    new_session.commit()
                logger.error(f"Found non-i2p tracker in attachment torrent! Not downloading. Found: {non_i2p_urls}")
                return

            # Set proper UID and GID and move to autodownload directory to begin downloading
            uid = 1001
            gid = 1001
            os.chown(path_torrent_tmp, uid, gid)
            os.chmod(path_torrent_tmp, 0o666)

            # Check if torrent exists already
            conn_info = dict(host=config.QBITTORRENT_HOST, port=8080)
            qbt_client = qbittorrentapi.Client(**conn_info)
            qbt_client.auth_log_in()

            if not file_torrent_hash and t.infohash:  # If torrent hash isn't with message, get from torrent file
                file_torrent_hash = t.infohash

            if file_torrent_hash:  # May not receive from other posts, but will with posts made by this BC instance
                try:
                    torrent_prop = qbt_client.torrents_info(torrent_hashes=file_torrent_hash)[0]
                except:
                    pass

            # Do not log here to prevent log analysis from determining if a post came from this instance or not
            if torrent_prop:  # Torrent is already in client
                pass
            else:  # Torrent not already in client. Add paused.
                try:
                    ret = qbt_client.torrents_add(torrent_files=path_torrent_tmp, is_paused=True)
                    if ret != "Ok.":
                        logger.error("{}: Error adding paused torrent {}".format(
                            log_id, path_torrent_tmp))
                except:
                    logger.exception("Adding torrent file")

            qbt_client.auth_log_out()

            delete_file(path_torrent_tmp)

            update_msg = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if update_msg:
                update_msg.file_currently_downloading = True
                update_msg.file_progress = "I2P BitTorrent Download Started"
                new_session.commit()

            # check if torrent DB entry already exists
            torrent_check = new_session.query(UploadTorrents).filter(
                UploadTorrents.torrent_hash == file_torrent_hash).first()

            if not torrent_check:  # Add torrent entry
                new_torrent = UploadTorrents()
                new_torrent.file_hash = file_torrent_file_hash
                new_torrent.torrent_hash = t.infohash
                new_torrent.message_id = message_id
                new_torrent.timestamp_started = time.time()
                new_session.add(new_torrent)
                new_session.commit()
            elif not torrent_check.message_id:  # torrent exists, update message_id
                torrent_check.message_id = message_id
                new_session.commit()

        #
        # upload site attachment
        #
        elif file_url and not settings.disable_downloading_upload_site:
            # Create dir to extract files into
            logger.info("{}: Filename on disk: {}".format(
                log_id, saved_file_filename))

            if os.path.exists(file_path) and os.path.getsize(file_path) != 0 and save_dir:
                logger.info("{}: Downloaded zip file found. Not attempting to download.".format(
                    log_id))
                file_size_test = os.path.getsize(file_path)
                file_download_successful = True
                extract_zip(message_id, file_path, save_dir)
            else:
                settings = new_session.query(GlobalSettings).first()
                if settings.maintenance_mode:
                    # If under maintenance, don't download now but set to download when maintenance ends
                    logger.info("{}: Maintenance mode enabled. "
                                "Waiting until maintenance ends to download attachments.".format(
                                    log_id))
                    msg = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if msg:
                        msg.start_download = True
                        new_session.commit()
                    return

                logger.info(
                    "{}: File not found. Attempting to download.".format(
                        log_id))
                logger.info("{}: Downloading file url: {}".format(
                    log_id, file_url))

                if upload_filename and file_url_type and file_upload_settings:
                    # Set post status to downloading and attempt to start the download
                    try:
                        msg = new_session.query(Messages).filter(
                            Messages.message_id == message_id).first()
                        if not msg:
                            return
                        msg.file_currently_downloading = True
                        msg.file_progress = "Starting download"
                        new_session.commit()
                    except Exception as err:
                        logger.error(
                            "{}: Could not write to database. Deleting. Error: {}".format(
                                log_id, err))
                        logger.exception("Editing message in DB")
                    finally:
                        time.sleep(config.API_PAUSE)

                    # Pick a download slot to fill (2 slots per domain)
                    domain = urlparse(file_url).netloc
                    lockfile1 = "/var/lock/download_{}_1.lock".format(domain)
                    lockfile2 = "/var/lock/download_{}_2.lock".format(domain)

                    lf = LF()
                    lockfile = random.choice([lockfile1, lockfile2])
                    if lf.lock_acquire(lockfile, to=600):
                        try:
                            (file_download_successful,
                             file_size_test,
                             file_amount_test,
                             file_do_not_download,
                             file_sha256_hashes_match,
                             file_progress,
                             media_info,
                             message_steg) = download_and_extract(
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

            # check for banned file hashes
            banned_hashes = file_hash_banned(return_file_hashes(media_info), address=json_obj['toAddress'])
            if media_info and banned_hashes:
                message = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if message:
                    logger.error(f"{message.post_id}: File hash banned. Deleting.")
                    log_mod = "Automatically deleted "
                    if is_op:
                        delete_thread(message.thread.thread_hash)
                        log_mod += "OP (and thread) "
                    else:
                        delete_post(message.message_id)
                        log_mod += "post "
                    log_mod += f"with banned file attachment hashes {', '.join(map(str, banned_hashes))}"
                    add_mod_log_entry(
                        log_mod,
                        message_id=message.message_id,
                        board_address=message.thread.chan.address,
                        thread_hash=message.thread.thread_hash)
                    return

            if file_download_successful:
                for dirpath, dirnames, filenames in os.walk(save_dir):
                    for f in filenames:
                        fp = os.path.join(dirpath, f)
                        if os.path.islink(fp):  # skip symbolic links
                            continue

                        file_extension = html.escape(os.path.splitext(f)[1].split(".")[-1].lower())
                        if not file_extension:
                            logger.error("{}: File extension not found. Deleting.".format(
                                log_id))
                            delete_post(message_id)
                            return
                        elif len(file_extension) >= config.MAX_FILE_EXT_LENGTH:
                            logger.error(
                                "{}: File extension greater than {} characters. Deleting.".format(
                                    log_id, config.MAX_FILE_EXT_LENGTH))
                            delete_post(message_id)
                            return
                        if file_extension in config.FILE_EXTENSIONS_IMAGE:
                            saved_image_thumb_filename = "{}_thumb.{}".format(message_id, file_extension)
                            img_thumb_filename = "{}/{}".format(save_dir, saved_image_thumb_filename)
                            generate_thumbnail_image(message_id, fp, img_thumb_filename, file_extension)

            try:
                msg = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if not msg:
                    return
                msg.file_amount = file_amount
                msg.file_size = file_size
                msg.file_download_successful = file_download_successful
                msg.file_do_not_download = file_do_not_download
                msg.file_sha256_hashes_match = file_sha256_hashes_match
                msg.file_progress = file_progress
                msg.media_info = json.dumps(media_info)
                msg.message_steg = json.dumps(message_steg)
                msg.file_currently_downloading = False
                new_session.commit()

                time.sleep(20)
                regenerate_card_popup_post_html(message_id=message_id)
            except Exception as err:
                logger.error(
                    "{}: Could not write to database. Deleting. Error: {}".format(
                        log_id, err))
                logger.exception("Editing message in DB")
            finally:
                time.sleep(config.API_PAUSE)

    # Return OP message ID, bool to process OP, and OP json_obj
    if (process_op_json_obj and
            orig_op_bm_json_obj and "msgid" in orig_op_bm_json_obj and orig_op_bm_json_obj["msgid"]):
        return_dict = {
            "process_op_json_obj": process_op_json_obj,
            "orig_op_bm_json_obj": orig_op_bm_json_obj
        }
        return return_dict


def process_admin(msg_dict, msg_decrypted_dict):
    """Process message as an admin command"""
    log_id = msg_dict["msgid"][-config.ID_LENGTH:].upper()

    logger.info(f"{log_id}: Message is an admin command")

    # Authenticate sender
    with session_scope(config.DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == msg_dict['toAddress']).first()
        if chan:
            errors, dict_info = process_passphrase(chan.passphrase)
            # Message must be from address in primary or secondary access list
            access = get_access(msg_dict['toAddress'])
            if errors or (msg_dict['fromAddress'] not in access["primary_addresses"] and
                          msg_dict['fromAddress'] not in access["secondary_addresses"]):
                logger.error("{}: Unauthorized Admin message. Deleting.".format(log_id))
                daemon_com.trash_message(msg_dict["msgid"])
                return
        else:
            logger.error("{}: Admin message: Chan not found".format(log_id))
            daemon_com.trash_message(msg_dict["msgid"])
            return

    logger.info("{}: Admin message received from {} for {} is authentic".format(
        log_id, msg_dict['fromAddress'], msg_dict['toAddress']))

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

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_ADMIN_CMD, to=20):
        try:
            # (Owner): set board options
            if (admin_dict["action"] == "set" and
                    admin_dict["action_type"] == "options" and
                    msg_dict['fromAddress'] in access["primary_addresses"]):
                admin_set_options(msg_dict, admin_dict)

            # (Owner, Admin): set thread options
            elif (admin_dict["action"] == "set" and
                  admin_dict["action_type"] == "thread_options" and
                  (msg_dict['fromAddress'] in access["primary_addresses"] or
                   msg_dict['fromAddress'] in access["secondary_addresses"])):
                admin_set_thread_options(msg_dict, admin_dict)

            # (Owner, Admin): delete board thread or post
            elif (admin_dict["action"] == "delete" and
                  (admin_dict["action_type"] == "delete_thread" or admin_dict["action_type"] == "delete_post") and
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
            elif (admin_dict["action"] in ["board_ban_silent", "board_ban_public"] and
                  admin_dict["action_type"] in "ban_address" and
                  admin_dict["options"] and
                  "ban_address" in admin_dict["action_type"] and
                  (msg_dict['fromAddress'] in access["primary_addresses"] or
                   msg_dict['fromAddress'] in access["secondary_addresses"])):
                admin_ban_address_from_board(msg_dict, admin_dict)

            else:
                logger.error("{}: Unknown Admin command: action: {}, action_type: {}. Deleting. {}".format(
                    log_id,
                    admin_dict["action"],
                    admin_dict["action_type"],
                    admin_dict))
                daemon_com.trash_message(msg_dict["msgid"])
        except Exception:
            logger.exception("{}: Exception processing Admin command. Deleting.".format(log_id))
            daemon_com.trash_message(msg_dict["msgid"])
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API)


def decrypt_and_process_attachments(
        message_id, file_enc_cipher, file_enc_key_bytes, file_enc_password, encrypted_zip, skip_size_check=False):
    decrypted_zip = None
    file_amount = None
    media_info = {}
    message_steg = {}

    log_id = message_id[-config.ID_LENGTH:].upper()

    if file_enc_cipher == "NONE":
        logger.info("{}: File not encrypted".format(log_id))
        decrypted_zip = encrypted_zip
    elif file_enc_password:
        # decrypt file
        decrypted_zip = "/tmp/{}.zip".format(
            get_random_alphanumeric_string(12, with_punctuation=False, with_spaces=False))
        delete_file(decrypted_zip)  # make sure no file already exists
        logger.info("{}: Decrypting file {}".format(log_id, encrypted_zip))

        try:
            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                ret_crypto, error_msg = crypto_multi_decrypt(
                    file_enc_cipher,
                    file_enc_password + config.PGP_PASSPHRASE_ATTACH,
                    encrypted_zip,
                    decrypted_zip,
                    key_bytes=file_enc_key_bytes,
                    max_size_bytes=settings.max_extract_size * 1024 * 1024,
                    skip_size_check=skip_size_check)
                if not ret_crypto:
                    logger.error(f"Issue decrypting file: {error_msg}")
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        message.file_progress = error_msg
                        message.regenerate_post_html = True
                        new_session.commit()
                    return 1, media_info, message_steg
                else:
                    logger.info("{}: Finished decrypting file".format(log_id))

                delete_file(encrypted_zip)
        except Exception:
            logger.exception("Error decrypting file")
            return 1, media_info, message_steg

    if decrypted_zip:
        # Get the number of files in the zip archive
        try:
            file_amount_test = count_files_in_zip(message_id, decrypted_zip)
        except Exception as err:
            file_amount_test = None
            logger.error("{}: Error checking zip: {}".format(log_id, err))

        if file_amount_test:
            file_amount = file_amount_test

        if file_amount > config.FILE_ATTACHMENTS_MAX:
            logger.info("{}: Number of attachments ({}) exceed the maximum ({}).".format(
                log_id, file_amount, config.FILE_ATTACHMENTS_MAX))
            daemon_com.trash_message(message_id)
            return 1, media_info, message_steg

        # Check size of zip contents before extraction
        can_extract = True
        with zipfile.ZipFile(decrypted_zip, 'r') as zipObj:
            total_size = 0
            for each_file in zipObj.infolist():
                total_size += each_file.file_size
            logger.info("ZIP contents size: {}".format(total_size))
            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                max_extract_size = settings.max_extract_size * 1024 * 1024

                if not skip_size_check and settings.max_extract_size and total_size > max_extract_size:
                    can_extract = False
                    msg = "During extraction, max attachment size exceeded ({} > {}).".format(
                        human_readable_size(total_size), human_readable_size(max_extract_size))
                    logger.error(msg)
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        message.file_progress = msg
                        message.regenerate_post_html = True
                        message.file_download_successful = False
                        new_session.commit()

        if can_extract:
            # Extract zip archive
            extract_path = "{}/{}".format(config.FILE_DIRECTORY, message_id)
            extract_zip(message_id, decrypted_zip, extract_path)
            delete_file(decrypted_zip)  # Secure delete

            errors_files, media_info, message_steg = process_attachments(message_id, extract_path)

            if errors_files:
                logger.error(
                    "{}: Encountered errors processing attachments. Deleting".format(
                        log_id, config.MAX_FILE_EXT_LENGTH))
                for err in errors_files:
                    logger.error("{}: Error: {}".format(log_id, err))
                delete_files_recursive(extract_path)
                daemon_com.trash_message(message_id)
                return 1, media_info, message_steg
            else:
                # Decryption and extraction successful
                with session_scope(config.DB_PATH) as new_session:
                    msg = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if msg:
                        msg.file_progress = None
                        new_session.commit()
                regenerate_card_popup_post_html(message_id=message_id)
                return 0, media_info, message_steg

    return 1, media_info, message_steg


def check_pow_thread_rule(thread_rules_, pow_filter_value):
    list_errors = []
    try:
        if "require_pow_to_reply" in thread_rules_:
            if ("pow_method" not in thread_rules_["require_pow_to_reply"] or
                    thread_rules_["require_pow_to_reply"]["pow_method"] != "hashcash"):
                list_errors.append("Missing method")
            if ("pow_difficulty" not in thread_rules_["require_pow_to_reply"] or
                    int(thread_rules_["require_pow_to_reply"]["pow_difficulty"]) < 1):
                list_errors.append("Invalid difficulty")
            if ("pow_repetitions" not in thread_rules_["require_pow_to_reply"] or
                    int(thread_rules_["require_pow_to_reply"]["pow_repetitions"]) < 1):
                list_errors.append("Invalid repetitions")

            # Check if post meets minimum POW requirements
            required_pow_filter_value = (2 ** int(thread_rules_["require_pow_to_reply"]["pow_difficulty"])) * int(thread_rules_["require_pow_to_reply"]["pow_repetitions"])

            if pow_filter_value < required_pow_filter_value:
                list_errors.append("Reply doesn't meet minimum POW requirements")
    except Exception as error:
        logger.exception("POW Thread Rule")
        list_errors.append(f"POW Thread Rule Exception: {error}")

    return list_errors
