import base64
import hashlib
import html
import json
import logging
import os
import random
import time
import zipfile
from io import BytesIO
from urllib.parse import urlparse

import bleach
from PIL import Image
from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Command
from database.models import GlobalSettings
from database.models import Messages
from database.models import Threads
from database.utils import session_scope
from utils.cards import generate_card
from utils.download import download_and_extract
from utils.download import process_attachments
from utils.encryption import crypto_multi_decrypt
from utils.files import LF
from utils.files import count_files_in_zip
from utils.files import delete_file
from utils.files import delete_files_recursive
from utils.files import extract_zip
from utils.files import generate_thumbnail
from utils.gateway import api
from utils.gateway import chan_auto_clears_and_message_too_old
from utils.gateway import delete_and_replace_comment
from utils.gateway import log_age_and_expiration
from utils.general import get_random_alphanumeric_string
from utils.general import get_thread_id
from utils.general import process_passphrase
from utils.message_admin_command import admin_ban_address_from_board
from utils.message_admin_command import admin_delete_from_board
from utils.message_admin_command import admin_delete_from_board_with_comment
from utils.message_admin_command import admin_set_options
from utils.message_admin_command import admin_set_thread_options
from utils.message_summary import generate_reply_link_html
from utils.message_summary import get_post_id
from utils.posts import process_message_replies
from utils.shared import get_access
from utils.shared import get_msg_expires_time

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.parse')
daemon_com = DaemonCom()


def parse_message(message_id, json_obj):
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
    sage = None
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
        logger.error(
            "{}: Message missing required subject. Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(message_id)
        return
    else:
        subject = html.escape(base64.b64decode(dict_msg["subject"]).decode('utf-8')).strip()
        if len(base64.b64decode(dict_msg["subject"]).decode('utf-8')) > 64:
            logger.error("{}: Subject too large. Deleting".format(message_id[-config.ID_LENGTH:].upper()))
            daemon_com.trash_message(message_id)
            return

    if "version" not in dict_msg or not dict_msg["version"]:
        logger.error("{}: Message has no version. Deleting.".format(message_id[-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(message_id)
        return
    else:
        version = dict_msg["version"]

    # logger.info("dict_msg: {}".format(dict_msg))

    # Determine if message indicates if it's OP or not
    if "is_op" in dict_msg and dict_msg["is_op"]:
        is_op = dict_msg["is_op"]
    else:
        is_op = False
        if "sage" in dict_msg and dict_msg["sage"]:
            sage = True

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
        daemon_com.trash_message(message_id)
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
            daemon_com.trash_message(message_id)
            return

    if ("timestamp_utc" in dict_msg and dict_msg["timestamp_utc"] and
            isinstance(dict_msg["timestamp_utc"], int)):
        timestamp_sent = dict_msg["timestamp_utc"]
    else:
        timestamp_sent = int(json_obj['receivedTime'])

    log_age_and_expiration(
        message_id,
        daemon_com.get_utc(),
        timestamp_sent,
        get_msg_expires_time(message_id))

    # Check if board is set to automatically clear and message is older than the last clearing
    if chan_auto_clears_and_message_too_old(json_obj['toAddress'], timestamp_sent):
        logger.info("{}: Message outside current auto clear period. Deleting.".format(
            message_id[-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(message_id)
        return

    if "message" in dict_msg and dict_msg["message"]:
        message = dict_msg["message"]
    if "file_filename" in dict_msg and dict_msg["file_filename"]:
        file_filename = dict_msg["file_filename"]
        logger.info(
            "{} Filename on post: {}".format(message_id[-config.ID_LENGTH:].upper(), dict_msg["file_filename"]))
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
            logger.exception(
                "{}: Exception decoding attachments: {}".format(
                    message_id[-config.ID_LENGTH:].upper(), err))
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

    if ((file_amount and file_amount > 4) or
            (file_order and len(file_order) > 4)):
        logger.error(
            "{}: More than 4 files found in message. Deleting.".format(
                message_id[-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(message_id)
        return

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
                message_id[-config.ID_LENGTH:].upper()))
        elif len(nation_name) > 64:
            flag_pass = False
            logger.error("{}: Flag name too long: {}".format(
                message_id[-config.ID_LENGTH:].upper(), nation_name))

        if not flag_pass:
            logger.error(
                "{}: Base64 flag didn't pass validation. Deleting.".format(
                    message_id[-config.ID_LENGTH:].upper()))
            daemon_com.trash_message(message_id)
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
        logger.info("{}: Filename on disk: {}".format(
            message_id[-config.ID_LENGTH:].upper(), saved_file_filename))

        if os.path.exists(file_path) and os.path.getsize(file_path) != 0:
            logger.info("{}: Downloaded zip file found. Not attempting to download.".format(
                message_id[-config.ID_LENGTH:].upper()))
            file_size_test = os.path.getsize(file_path)
            file_download_successful = True
            extract_zip(message_id, file_path, save_dir)
        else:
            logger.info(
                "{}: File not found. Attempting to download.".format(
                    message_id[-config.ID_LENGTH:].upper()))
            logger.info("{}: Downloading file url: {}".format(
                message_id[-config.ID_LENGTH:].upper(), file_url))

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
                         file_progress,
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
                        logger.error("{}: File extension not found. Deleting.".format(
                            message_id[-config.ID_LENGTH:].upper()))
                        daemon_com.trash_message(message_id)
                        return
                    elif len(file_extension) >= config.MAX_FILE_EXT_LENGTH:
                        logger.error(
                            "{}: File extension greater than {} characters. Deleting.".format(
                                message_id[-config.ID_LENGTH:].upper(), config.MAX_FILE_EXT_LENGTH))
                        daemon_com.trash_message(message_id)
                        return
                    if file_extension in config.FILE_EXTENSIONS_IMAGE:
                        saved_image_thumb_filename = "{}_thumb.{}".format(message_id, file_extension)
                        img_thumb_filename = "{}/{}".format(save_dir, saved_image_thumb_filename)
                        generate_thumbnail(message_id, fp, img_thumb_filename, file_extension)

    # Bitmessage attachment
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
                with session_scope(DB_PATH) as new_session:
                    settings = new_session.query(GlobalSettings).first()
                    ret_crypto = crypto_multi_decrypt(
                        file_enc_cipher,
                        file_enc_password + config.PGP_PASSPHRASE_ATTACH,
                        encrypted_zip,
                        decrypted_zip,
                        key_bytes=file_enc_key_bytes,
                        max_size_bytes=settings.max_extract_size * 1024 * 1024)
                    if not ret_crypto:
                        logger.error("{}: Issue decrypting file")
                        return
                    else:
                        logger.info("{}: Finished decrypting file".format(message_id[-config.ID_LENGTH:].upper()))

                    delete_file(encrypted_zip)
                    # z = zipfile.ZipFile(download_path)
                    # z.setpassword(config.PGP_PASSPHRASE_ATTACH.encode())
                    # z.extract(extract_filename, path=extract_path)
            except Exception:
                logger.exception("Error decrypting file")

        # Get the number of files in the zip archive
        try:
            file_amount_test = count_files_in_zip(message_id, decrypted_zip)
        except Exception as err:
            file_amount_test = None
            logger.error("{}: Error checking zip: {}".format(
                message_id[-config.ID_LENGTH:].upper(), err))

        if file_amount_test:
            file_amount = file_amount_test

        if file_amount > config.FILE_ATTACHMENTS_MAX:
            logger.info("{}: Number of attachments ({}) exceed the maximum ({}).".format(
                message_id[-config.ID_LENGTH:].upper(), file_amount, config.FILE_ATTACHMENTS_MAX))
            daemon_com.trash_message(message_id)
            return

        # Check size of zip contents before extraction
        can_extract = True
        with zipfile.ZipFile(decrypted_zip, 'r') as zipObj:
            total_size = 0
            for each_file in zipObj.infolist():
                total_size += each_file.file_size
            logger.info("ZIP contents size: {}".format(total_size))
            with session_scope(DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                if (settings.max_extract_size and
                        total_size > settings.max_extract_size * 1024 * 1024):
                    can_extract = False
                    logger.error(
                        "ZIP content size greater than max allowed ({} bytes). "
                        "Not extracting.".format(settings.max_extract_size * 1024 * 1024))

        if can_extract:
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
                daemon_com.trash_message(message_id)
                return

    thread_locked = False
    thread_anchored = False
    owner_posting = False
    with session_scope(DB_PATH) as new_session:
        try:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_id).first()

            if thread:
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
                            message_id[-config.ID_LENGTH:].upper()))
        except Exception:
            logger.exception("Checking thread lock")

    if thread_locked and not owner_posting:
        logger.info(thread_locked)
        daemon_com.trash_message(message_id)
        return

    with session_scope(DB_PATH) as new_session:
        try:
            chan = new_session.query(Chan).filter(
                Chan.address == json_obj['toAddress']).first()
            chan.last_post_number = chan.last_post_number + 1

            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_id).first()

            if not thread and is_op:  # OP received, create new thread
                new_thread = Threads()
                new_thread.thread_hash = thread_id
                new_thread.thread_hash_short = thread_id[-12:]
                new_thread.op_sha256_hash = message_sha256_hash
                if chan:
                    new_thread.chan_id = chan.id
                new_thread.subject = subject
                new_thread.timestamp_sent = timestamp_sent
                new_thread.timestamp_received = int(json_obj['receivedTime'])
                new_session.add(new_thread)

                if timestamp_sent > chan.timestamp_sent:
                    chan.timestamp_sent = timestamp_sent
                if int(json_obj['receivedTime']) > chan.timestamp_received:
                    chan.timestamp_received = int(json_obj['receivedTime'])

                new_session.commit()
                id_thread = new_thread.id

            elif not thread and not is_op:  # Reply received before OP, create thread with OP placeholder
                new_thread = Threads()
                new_thread.thread_hash = thread_id
                new_thread.thread_hash_short = thread_id[-12:]
                new_thread.op_sha256_hash = op_sha256_hash
                if chan:
                    new_thread.chan_id = chan.id
                new_thread.subject = subject
                new_thread.timestamp_sent = timestamp_sent
                new_thread.timestamp_received = int(json_obj['receivedTime'])
                new_session.add(new_thread)

                if timestamp_sent > chan.timestamp_sent:
                    chan.timestamp_sent = timestamp_sent
                if int(json_obj['receivedTime']) > chan.timestamp_received:
                    chan.timestamp_received = int(json_obj['receivedTime'])

                new_session.commit()
                id_thread = new_thread.id

            elif thread and not is_op:  # Reply received after OP, add to current thread
                if thread_anchored:
                    logger.info(thread_anchored)

                if timestamp_sent > thread.timestamp_sent:
                    if not sage and not thread_anchored:
                        thread.timestamp_sent = timestamp_sent
                if int(json_obj['receivedTime']) > thread.timestamp_received:
                    if not sage and thread_anchored:
                        thread.timestamp_received = int(json_obj['receivedTime'])

                if timestamp_sent > chan.timestamp_sent:
                    if not sage and not thread_anchored:
                        chan.timestamp_sent = timestamp_sent
                if int(json_obj['receivedTime']) > chan.timestamp_received:
                    if not sage and not thread_anchored:
                        chan.timestamp_received = int(json_obj['receivedTime'])

                new_session.commit()
                id_thread = thread.id

            elif thread and is_op:
                # Post indicating it is OP but thread already exists
                # Could have received reply before OP
                # Add OP to current thread
                id_thread = thread.id

            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_STORE_POST, to=20):
                try:
                    # Create message
                    new_msg = Messages()
                    new_msg.version = version
                    new_msg.message_id = message_id
                    new_msg.post_id = get_post_id(message_id)
                    new_msg.post_number = chan.last_post_number
                    new_msg.expires_time = get_msg_expires_time(message_id)
                    new_msg.thread_id = id_thread
                    new_msg.address_from = bleach.clean(json_obj['fromAddress'])
                    new_msg.message_sha256_hash = message_sha256_hash
                    new_msg.is_op = is_op
                    if sage:
                        new_msg.sage = sage
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
                    new_msg.message_steg = json.dumps(message_steg)
                    new_msg.message_original = json_obj["message"]
                    new_session.add(new_msg)

                    if timestamp_sent > chan.timestamp_sent:
                        chan.timestamp_sent = timestamp_sent
                    if int(json_obj['receivedTime']) > chan.timestamp_received:
                        chan.timestamp_received = int(json_obj['receivedTime'])

                    new_session.commit()

                    message_edit = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    try:
                        message_edit.popup_html = generate_reply_link_html(message_edit)
                        new_session.commit()
                    except Exception as err:
                        logger.exception("{}: Couldn't generate popup HTML: {}".format(
                            message_id[-config.ID_LENGTH:].upper(), err))

                    process_message_replies(message_id, message)

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

                    # Generate card
                    generate_card(thread_id, force_generate=True)
                except Exception:
                    logger.exception("Saving message to DB")
                finally:
                    time.sleep(config.API_PAUSE)
                    lf.lock_release(config.LOCKFILE_API)

            # Delete message from Bitmessage after parsing and adding to BitChan database
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=120):
                try:
                    return_val = api.trashMessage(message_id)
                except Exception as err:
                    logger.error("{}: Exception during message delete: {}".format(
                        message_id[-config.ID_LENGTH:].upper(), err))
                finally:
                    time.sleep(config.API_PAUSE)
                    lf.lock_release(config.LOCKFILE_API)
        except Exception as err:
            logger.error(
                "{}: Could not write to database. Deleting. Error: {}".format(
                    message_id[-config.ID_LENGTH:].upper(), err))
            logger.exception("1")
            daemon_com.trash_message(message_id)
            return


def process_admin(msg_dict, msg_decrypted_dict):
    """Process message as an admin command"""
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
                daemon_com.trash_message(msg_dict["msgid"])
                return
        else:
            logger.error("{}: Admin message: Chan not found".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            daemon_com.trash_message(msg_dict["msgid"])
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
            elif (admin_dict["action"] in ["board_ban_silent", "board_ban_public"] and
                  admin_dict["action_type"] in "ban_address" and
                  admin_dict["options"] and
                  "ban_address" in admin_dict["action_type"] and
                  (msg_dict['fromAddress'] in access["primary_addresses"] or
                   msg_dict['fromAddress'] in access["secondary_addresses"])):
                admin_ban_address_from_board(msg_dict, admin_dict)

            else:
                logger.error("{}: Unknown Admin command. Deleting. {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict))
                daemon_com.trash_message(msg_dict["msgid"])
        except Exception:
            logger.exception("{}: Exception processing Admin command. Deleting.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            daemon_com.trash_message(msg_dict["msgid"])
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API)
