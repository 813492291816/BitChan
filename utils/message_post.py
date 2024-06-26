import base64
import hashlib
import html
import json
import logging
import os
import random
import shutil
import time
import zipfile
from threading import Thread

import PIL
import gnupg
import qbittorrentapi
from PIL import Image
from sqlalchemy import and_
from torf import Torrent

import config
from bitchan_client import DaemonCom
from config import GPG_DIR
from database.models import Chan
from database.models import Command
from database.models import Flags
from database.models import Games
from database.models import GlobalSettings
from database.models import PGP
from database.models import Threads
from database.models import UploadProgress
from database.models import UploadSites
from database.models import UploadTorrents
from database.utils import session_scope
from utils.anonfile import AnonFile
from utils.download import generate_hash
from utils.encryption import crypto_multi_enc
from utils.files import LF
from utils.files import data_file_multiple_extract
from utils.files import delete_file
from utils.files import delete_files_recursive
from utils.files import human_readable_size
from utils.files import return_non_overlapping_sequences
from utils.gateway import api
from utils.general import get_random_alphanumeric_string
from utils.gpg import find_gpg
from utils.gpg import get_keyring_name
from utils.gpg import gpg_decrypt
from utils.message_check import check_msg_dict_post
from utils.replacements import format_body
from utils.replacements import process_replacements
from utils.routes import has_permission
from utils.routes import is_logged_in
from utils.shared import check_tld_i2p
from utils.shared import get_access
from utils.shared import get_post_ttl
from utils.steg import steg_encrypt
from utils.upload import UploadCurl

logger = logging.getLogger('bitchan.message_post')
daemon_com = DaemonCom()


def post_message(form_post, status_msg):
    form_populate = {}
    return_str = None
    status_msg = status_msg
    settings = GlobalSettings.query.first()
    thread = None

    if settings.maintenance_mode:
        status_msg['status_message'].append("Maintenance Mode is Active. Disabled: creating new posts.")

    if settings.enable_kiosk_mode:
        if is_logged_in() and has_permission("is_global_admin"):
            pass
        else:
            # Can posting occur
            if settings.kiosk_allow_posting or has_permission("can_post"):
                now = time.time()
                last_post_ts = daemon_com.get_last_post_ts()
                if now < last_post_ts + settings.kiosk_post_rate_limit:
                    status_msg['status_message'].append(
                        "Posting is limited to 1 post per {} second period. Wait {:.0f} more seconds.".format(
                            settings.kiosk_post_rate_limit,
                            (last_post_ts + settings.kiosk_post_rate_limit) - now))

            # Check if allowed to encrypt PGP messages
            if (form_post.gpg_sign_post.data or form_post.gpg_encrypt_msg.data) and not settings.kiosk_allow_gpg:
                status_msg['status_message'].append(
                    "Encrypting or signing PGP messages in posts is not allowed in kiosk mode")

        if settings.kiosk_disable_bm_attach and form_post.upload.data == "bitmessage":
            status_msg['status_message'].append(
                "The Bitmessage upload method is not permitted while in Kiosk Mode")
        if settings.kiosk_disable_i2p_torrent_attach and form_post.upload.data == "i2p_torrent":
            status_msg['status_message'].append(
                "The I2P Torrent upload method is not permitted while in Kiosk Mode")

    if not form_post.from_address.data:
        status_msg['status_message'].append("A From Address is required.")

    # Check if thread currently locked
    if form_post.thread_id.data and form_post.board_id.data:
        thread = Threads.query.filter(
            Threads.thread_hash == form_post.thread_id.data).first()

        if not thread:
            status_msg['status_message'].append("Cannot post to nonexistent thread.")
        else:
            if thread.hide:
                status_msg['status_message'].append(
                    "Cannot post to a hidden thread. Restore the thread before posting.")

            if thread.chan:
                admin_cmd = Command.query.filter(and_(
                    Command.action == "set",
                    Command.action_type == "thread_options",
                    Command.thread_id == thread.thread_hash)).first()
                try:
                    options = json.loads(admin_cmd.options)
                except:
                    options = {}
                if ("lock" in options and options["lock"]) or thread.locked_local:
                    access = get_access(thread.chan.address)
                    if form_post.from_address.data not in access["primary_addresses"]:
                        status_msg['status_message'].append(
                            "Only Owner address can post to a locked thread.")

    if form_post.is_op.data == "yes":
        if len(form_post.subject.data.strip()) == 0:
            status_msg['status_message'].append("A Subject is required.")
        if not form_post.body.data:
            status_msg['status_message'].append("A Comment is required.")
    else:
        if form_post.game_player_move.data or form_post.game.data:
            # A comment is not required if a game command is given
            pass
        elif (not form_post.body.data and
                not form_post.gpg_body.data and
                (not form_post.file1.data[0] and
                 not form_post.file2.data[0] and
                 not form_post.file3.data[0] and
                 not form_post.file4.data[0])):
            status_msg['status_message'].append("A Comment or File or PGP Message is required.")

    gpg_body = ""
    if form_post.gpg_body.data:
        gpg_body = form_post.gpg_body.data

    if len(gpg_body + form_post.body.data + form_post.subject.data.strip()) > config.MAX_SUBJECT_COMMENT:
        status_msg['status_message'].append(
            "Limit of {} characters exceeded for Subject + Comment + PGP Message: {}".format(
                config.MAX_SUBJECT_COMMENT, len(form_post.body.data)))

    if form_post.ttl.data > 2419200 or form_post.ttl.data < 3600:
        status_msg['status_message'].append("TTL must be between 3600 seconds (1 hour) and 2419200 seconds (28 days)")

    if form_post.delete_password.data and len(form_post.delete_password.data) > 512:
        status_msg['status_message'].append("Password to delete post can be a maximum of 512 characters")

    if form_post.game_password_a.data and len(form_post.game_password_a.data) > 512:
        status_msg['status_message'].append("Game Previous Password can be a maximum of 512 characters")

    if form_post.game_password_b.data and len(form_post.game_password_b.data) > 512:
        status_msg['status_message'].append("Game New Password can be a maximum of 512 characters")

    if form_post.game_password_a.data and not form_post.game_password_b.data:
        status_msg['status_message'].append("If entering Previous Password, you must provide New Password")

    if form_post.game_password_a.data and form_post.game_password_b.data and not form_post.game_player_move.data:
        status_msg['status_message'].append(
            "If entering Previous Password and New Password, you must provide a Game Command")

    if form_post.game.data and form_post.game.data not in config.GAMES:
        status_msg['status_message'].append("Unknown game: {}".format(form_post.game.data))

    if form_post.gpg_encrypt_msg.data and not form_post.gpg_select_to.data:
        status_msg['status_message'].append("At least one recipient is required to GPG encrypt a message")

    if form_post.gpg_encrypt_msg.data and not form_post.gpg_body.data:
        status_msg['status_message'].append("A message is required to GPG encrypt a message")

    def append_file(form, list_append):
        test = False
        try:
            test = bool(form.data[0])
        except:
            pass
        if test:
            list_append.append(form.data[0])
        else:
            list_append.append(None)
        return list_append

    file_list = []
    file_list = append_file(form_post.file1, file_list)
    file_list = append_file(form_post.file2, file_list)
    file_list = append_file(form_post.file3, file_list)
    file_list = append_file(form_post.file4, file_list)

    filenames = []
    if file_list:
        for i, each_file in enumerate(file_list, start=1):
            if each_file is None:
                if (int(form_post.image_steg_insert.data) == i and
                        form_post.steg_message.data):
                    status_msg['status_message'].append(
                        "Steg Comment requires Image to Insert Steg to select a JPG image attachment.")
                continue
            try:
                filenames.append(each_file.filename)
                file_extension = each_file.filename.split(".")[-1].lower()
                if len(file_extension) >= config.MAX_FILE_EXT_LENGTH:
                    status_msg['status_message'].append(
                        "File extension lengths must be less than {}.".format(config.MAX_FILE_EXT_LENGTH))
                if (int(form_post.image_steg_insert.data) == i and
                        form_post.steg_message.data and
                        file_extension not in ["jpg", "jpeg"]):
                    status_msg['status_message'].append("Steg Comment requires a JPG image attachment.")
            except Exception as e:
                status_msg['status_message'].append("Error determining file extension. {}".format(e))

    if len(filenames) > 1 and len(filenames) != len(set(filenames)):
        status_msg['status_message'].append("Attachment filenames must be unique.")

    # Check game password conditions
    if form_post.game_password_a.data and len(form_post.game_password_a.data) > 512:
        status_msg['status_message'].append("Game Previous Password too long. Max characters is 512.")
    if form_post.game_password_b.data and len(form_post.game_password_b.data) > 512:
        status_msg['status_message'].append("Game New Password too long. Max characters is 512.")
    if form_post.game_termination_password.data and len(form_post.game_termination_password.data) > 512:
        status_msg['status_message'].append("Game Termination Password too long. Max characters is 512.")

    if form_post.preview_post.data:
        return_str = ""
        if 'status_title' not in status_msg:
            status_msg['status_title'] = "Preview"
            status_msg['status_message'].append("Post Preview generated.")
        form_populate = generate_post_form_populate(form_post)
        form_populate["preview"] = process_replacements(
            html.escape(form_populate["comment"].encode('utf-8').strip().decode()),
            str(random.randint(1, 10**10)),
            "0",
            preview=True)

        form_populate["preview"], gpg_texts = find_gpg(form_populate["preview"])
        gpg_texts = gpg_decrypt(gpg_texts)

        if thread:
            form_populate["preview"] = format_body(
                "preview", form_populate["preview"], False, True,
                preview=True, this_thread_hash=thread.thread_hash, gpg_texts=gpg_texts)
        else:
            form_populate["preview"] = format_body(
                "preview", form_populate["preview"], False, True,
                preview=True, gpg_texts=gpg_texts)
    elif "status_message" not in status_msg or not status_msg["status_message"]:
        if settings.enable_kiosk_mode:
            if settings.kiosk_allow_posting or has_permission("can_post"):
                daemon_com.set_last_post_ts(time.time())

        return_str, errors = submit_post(form_post)

        if return_str == "Error":
            status_msg['status_title'] = "Error"
            status_msg['status_message'] = status_msg['status_message'] + errors
            form_populate = generate_post_form_populate(form_post)
        else:
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(return_str)
    else:
        status_msg['status_title'] = "Error"
        form_populate = generate_post_form_populate(form_post)

    return status_msg, return_str, form_populate


def generate_post_form_populate(form_post):
    try:
        form_populate = {
            "from_address": form_post.from_address.data,
            "subject": form_post.subject.data,
            "comment": form_post.body.data,
            "sage": form_post.sage.data,
            "file1": bool(form_post.file1.data),
            "file2": bool(form_post.file2.data),
            "file3": bool(form_post.file3.data),
            "file4": bool(form_post.file4.data),
            "upload": form_post.upload.data,
            "strip_exif": form_post.strip_exif.data,
            "image1_spoiler": form_post.image1_spoiler.data,
            "image2_spoiler": form_post.image2_spoiler.data,
            "image3_spoiler": form_post.image3_spoiler.data,
            "image4_spoiler": form_post.image4_spoiler.data,
            "image_steg_insert": form_post.image_steg_insert.data,
            "steg_comment": form_post.steg_message.data,
            "delete_password": form_post.delete_password.data,
            "ttl": form_post.ttl.data,
            "game": form_post.game.data,
            "game_password_a": form_post.game_password_a.data,
            "game_password_b": form_post.game_password_b.data,
            "game_player_move": form_post.game_player_move.data,
            "game_termination_password": form_post.game_termination_password.data,
            "upload_cipher_and_key": form_post.upload_cipher_and_key.data,
            "gpg_body": form_post.gpg_body.data,
            "gpg_encrypt_msg": form_post.gpg_encrypt_msg.data,
            "gpg_sign_post": form_post.gpg_sign_post.data,
            "gpg_hide_all_recipients": form_post.gpg_hide_all_recipients.data,
            "gpg_select_from":form_post.gpg_select_from.data,
            "gpg_select_to": form_post.gpg_select_to.data
        }
        return form_populate
    except:
        return None


def submit_post(form_post):
    """Process the form for making a post"""
    errors = []
    file_list = []
    file_upload = False

    dict_send = {
        "save_dir": None,
        "zip_file": None,
        "file_size": None,
        "file_amount": None,
        "file_filename": None,
        "file_extension": None,
        "file_url_type": None,
        "file_url": None,
        "file_torrent_file_hash": None,
        "file_torrent_base64": None,
        "file_upload_settings": {},
        "file_extracts_start_base64": None,
        "file_sha256_hash": None,
        "file_enc_cipher": None,
        "file_enc_key_bytes": None,
        "file_enc_password": None,
        "file_order": [],
        "media_height": None,
        "media_width": None,
        "file_base64": None,
        "upload_filename": None,
        "op_sha256_hash": None,
        "sage": None,
        "game": None,
        "game_hash": None,
        "game_password_a": None,
        "game_password_b_hash": None,
        "game_player_move": None,
        "game_termination_pw_hash": None,
        "game_termination_password": None,
        "subject": None,
        "message": None,
        "nation": None,
        "nation_base64": None,
        "nation_name": None,
        "thread_hash": None,
        "delete_password_hash": None,
        "post_id": get_random_alphanumeric_string(6, with_punctuation=False, with_spaces=False)
    }

    if form_post.delete_password.data:
        dict_send["delete_password_hash"] = hashlib.sha512(form_post.delete_password.data.encode('utf-8')).hexdigest()

    #
    # Games
    #
    if form_post.game_hash.data:
        dict_send["game_hash"] = form_post.game_hash.data
    else:
        dict_send["game_hash"] = get_random_alphanumeric_string(
            15, with_punctuation=False, with_spaces=False)

    if form_post.game_password_a.data:
        dict_send["game_password_a"] = form_post.game_password_a.data
    if form_post.game_password_b.data:
        dict_send["game_password_b_hash"] = hashlib.sha512(
            form_post.game_password_b.data.encode('utf-8')).hexdigest()
    if form_post.game_player_move.data:
        dict_send["game_player_move"] = form_post.game_player_move.data
    if (form_post.game_termination_password.data and
            (not form_post.game_player_move.data or
             (form_post.game_player_move.data and
              form_post.game_player_move.data.lower() != "terminate"))):
        dict_send["game_termination_pw_hash"] = hashlib.sha512(
            form_post.game_termination_password.data.encode('utf-8')).hexdigest()
    if (form_post.game_termination_password.data and
            form_post.game_player_move.data and
            form_post.game_player_move.data.lower() == "terminate"):
        dict_send["game_termination_password"] = form_post.game_termination_password.data

    if form_post.is_op.data != "yes":
        with session_scope(config.DB_PATH) as new_session:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == form_post.thread_id.data).first()
            if thread:
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
        if (form_post.nation.data.startswith("customflag") and
                len(form_post.nation.data.split("_")) == 2):
            flag_id = int(form_post.nation.data.split("_")[1])
            with session_scope(config.DB_PATH) as new_session:
                flag = new_session.query(Flags).filter(Flags.id == flag_id).first()
                if flag:
                    dict_send["nation_name"] = flag.name
                    dict_send["nation_base64"] = flag.flag_base64
        else:
            dict_send["nation"] = form_post.nation.data

    if form_post.thread_id.data:
        dict_send["thread_hash"] = form_post.thread_id.data

    if form_post.sage.data:
        dict_send["sage"] = True

    if form_post.game.data:
        dict_send["game"] = form_post.game.data

    if form_post.body.data:
        dict_send["message"] = form_post.body.data.encode('utf-8').strip().decode()

    #
    # PGP Encryption
    #

    # Sign and encrypt message
    if (form_post.gpg_sign_post.data and
            form_post.gpg_encrypt_msg.data and
            form_post.gpg_select_from.data and
            form_post.gpg_select_to.data and
            form_post.gpg_body.data):
        list_keyring_from = get_keyring_name(form_post.gpg_select_from.data)
        list_keyring_to = get_keyring_name(form_post.gpg_select_to.data)
        if list_keyring_from and list_keyring_to:
            list_keyrings = list_keyring_from + list_keyring_to
            if form_post.gpg_hide_all_recipients.data:
                gpg_enc = gnupg.GPG(gnupghome=GPG_DIR, keyring=list_keyrings, options=['--throw-keyids'])
            else:
                gpg_enc = gnupg.GPG(gnupghome=GPG_DIR, keyring=list_keyrings)
            with session_scope(config.DB_PATH) as new_session:
                gpg_entry = new_session.query(PGP).filter(
                    PGP.fingerprint == form_post.gpg_select_from.data).first()
                if gpg_entry:
                    encrypted_ascii_data = gpg_enc.encrypt(
                        form_post.gpg_body.data,
                        form_post.gpg_select_to.data,
                        sign=form_post.gpg_select_from.data,
                        passphrase=gpg_entry.passphrase)
                    dict_send["message"] += f"\n\n{str(encrypted_ascii_data)}"
        else:
            msg = "Key fingerprint not found"
            logger.error(msg)
            errors.append(msg)
            return "Error", errors

    # Sign message
    elif form_post.gpg_sign_post.data and form_post.gpg_select_from.data and form_post.gpg_body.data:
        list_keyring_names = get_keyring_name(form_post.gpg_select_from.data)
        if list_keyring_names:
            with session_scope(config.DB_PATH) as new_session:
                gpg_entry = new_session.query(PGP).filter(
                    PGP.fingerprint == form_post.gpg_select_from.data).first()
                if gpg_entry:
                    gpg_sign = gnupg.GPG(gnupghome=GPG_DIR, keyring=list_keyring_names)
                    sign_data = gpg_sign.sign(
                        form_post.gpg_body.data,
                        keyid=form_post.gpg_select_from.data,
                        passphrase=gpg_entry.passphrase)
                    dict_send["message"] += f"\n\n{str(sign_data)}"
        else:
            msg = "Key fingerprint not found"
            logger.error(msg)
            errors.append(msg)
            return "Error", errors

    # Encrypt message
    elif form_post.gpg_encrypt_msg.data and form_post.gpg_select_to.data and form_post.gpg_body.data:
        list_keyring_names = get_keyring_name(form_post.gpg_select_to.data)
        if list_keyring_names:
            if form_post.gpg_hide_all_recipients.data:
                gpg_enc = gnupg.GPG(gnupghome=GPG_DIR, keyring=list_keyring_names, options=['--throw-keyids'])
            else:
                gpg_enc = gnupg.GPG(gnupghome=GPG_DIR, keyring=list_keyring_names)
            encrypted_ascii_data = gpg_enc.encrypt(
                form_post.gpg_body.data, form_post.gpg_select_to.data)
            dict_send["message"] += f"\n\n{str(encrypted_ascii_data)}"
        else:
            msg = "Key fingerprint not found"
            logger.error(msg)
            errors.append(msg)
            return "Error", errors

    if form_post.is_op.data == "no" and form_post.op_sha256_hash.data:
        dict_send["op_sha256_hash"] = form_post.op_sha256_hash.data

    if bool(form_post.file1.data[0]):
        file_list.append(form_post.file1.data[0])
    else:
        file_list.append(None)

    if bool(form_post.file2.data[0]):
        file_list.append(form_post.file2.data[0])
    else:
        file_list.append(None)

    if bool(form_post.file3.data[0]):
        file_list.append(form_post.file3.data[0])
    else:
        file_list.append(None)

    if bool(form_post.file4.data[0]):
        file_list.append(form_post.file4.data[0])
    else:
        file_list.append(None)

    if file_list:
        file_upload = True
        for each_file in file_list:
            if not each_file:
                continue
            try:
                file_filename = html.escape(each_file.filename)
                file_extension = html.escape(os.path.splitext(file_filename)[1].split(".")[-1].lower())
            except Exception as e:
                msg = "Error determining file extension: {}".format(e)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                errors.append(msg)
                return "Error", errors

    spawn_send_thread = False
    save_file_size = 0
    if file_upload:
        # get number of files being sent
        dict_send["file_amount"] = sum([bool(form_post.file1.data[0]),
                                        bool(form_post.file2.data[0]),
                                        bool(form_post.file3.data[0]),
                                        bool(form_post.file4.data[0])])

        dict_send["save_dir"] = "/tmp/{}".format(
            get_random_alphanumeric_string(15, with_punctuation=False, with_spaces=False))
        os.mkdir(dict_send["save_dir"])
        for each_file in file_list:
            if not each_file:
                dict_send["file_order"].append(None)
                continue
            save_file_path = "{}/{}".format(dict_send["save_dir"], each_file.filename)
            delete_file(save_file_path)
            # Save file to disk
            logger.info("{}: Saving file to {}".format(dict_send["post_id"], save_file_path))
            each_file.save(save_file_path)
            dict_send["file_order"].append(each_file.filename)

        def get_size(start_path):
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(start_path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    # skip if it is symbolic link
                    if not os.path.islink(fp):
                        total_size += os.path.getsize(fp)

            return total_size

        save_file_size = get_size(dict_send["save_dir"])
        logger.info("{}: Upload size is {}".format(
            dict_send["post_id"], human_readable_size(save_file_size)))

        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            max_size_bytes = settings.max_extract_size * 1024 * 1024
            if save_file_size > max_size_bytes:
                err = "Attachments size is larger than max allowed ({} > {}).".format(
                    human_readable_size(save_file_size), human_readable_size(max_size_bytes))
                logger.error("{}: {}".format(dict_send["post_id"], err))
                errors.append(err)
                return "Error", errors

    # Check upload site
    if any(dict_send["file_order"]) and form_post.upload.data not in ["bitmessage", "i2p_torrent"]:
        if save_file_size > config.UPLOAD_SIZE_TO_THREAD:
            # If using 3rd party upload site to upload large attachment, spawn background thread to upload
            spawn_send_thread = True

        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            upload_info = new_session.query(UploadSites).filter(
                UploadSites.id == form_post.upload.data).first()

            if (upload_info and
                    (upload_info.enabled or
                     (settings.enable_kiosk_mode and is_logged_in() and has_permission("is_global_admin")))):
                dict_send["file_url_type"] = upload_info.domain
                dict_send["file_upload_settings"] = {
                    "domain": upload_info.domain,
                    "type": upload_info.type,
                    "subtype": upload_info.subtype,
                    "uri": upload_info.uri,
                    "download_prefix": upload_info.download_prefix,
                    "response": upload_info.response,
                    "json_key": upload_info.json_key,
                    "direct_dl_url": upload_info.direct_dl_url,
                    "extra_curl_options": upload_info.extra_curl_options,
                    "upload_word": upload_info.upload_word,
                    "form_name": upload_info.form_name,
                    "http_headers": upload_info.http_headers,
                    "proxy_type": upload_info.proxy_type,
                    "replace_download_domain": upload_info.replace_download_domain
                }
            else:
                msg = f"{dict_send['post_id']}: Upload site (ID {form_post.upload.data}) not found or enabled"
                logger.error(f"{dict_send['post_id']}: {msg}")
                errors.append(msg)
                return "Error", errors

    # Generate the dict that will be sent in the message
    dict_message = {
        "version": config.VERSION_MSG,
        "message_type": "post",
        "is_op": form_post.is_op.data == "yes",
        "op_sha256_hash": dict_send["op_sha256_hash"],
        "timestamp_utc": daemon_com.get_utc(),
        "file_size": dict_send["file_size"],
        "file_amount": dict_send["file_amount"],
        "file_url_type": dict_send["file_url_type"],
        "file_url": dict_send["file_url"],
        "file_torrent_file_hash": dict_send["file_torrent_file_hash"],
        "file_torrent_base64": dict_send["file_torrent_base64"],
        "file_upload_settings": dict_send["file_upload_settings"],
        "file_extracts_start_base64": dict_send["file_extracts_start_base64"],
        "file_base64": dict_send["file_base64"],
        "file_sha256_hash": dict_send["file_sha256_hash"],
        "file_enc_cipher": dict_send["file_enc_cipher"],
        "file_enc_key_bytes": dict_send["file_enc_key_bytes"],
        "file_enc_password": dict_send["file_enc_password"],
        "file_order": dict_send["file_order"],
        "image1_spoiler": form_post.image1_spoiler.data,
        "image2_spoiler": form_post.image2_spoiler.data,
        "image3_spoiler": form_post.image3_spoiler.data,
        "image4_spoiler": form_post.image4_spoiler.data,
        "delete_password_hash": dict_send["delete_password_hash"],
        "upload_filename": dict_send["upload_filename"],
        "sage": dict_send["sage"],
        "game": dict_send["game"],
        "game_over": False,
        "game_hash": dict_send["game_hash"],
        "game_password_a": dict_send["game_password_a"],
        "game_password_b_hash": dict_send["game_password_b_hash"],
        "game_player_move": dict_send["game_player_move"],
        "game_termination_password": dict_send["game_termination_password"],
        "game_termination_pw_hash": dict_send["game_termination_pw_hash"],
        "subject": dict_send["subject"],
        "message": dict_send["message"],
        "nation": dict_send["nation"],
        "nation_base64": dict_send["nation_base64"],
        "nation_name": dict_send["nation_name"],
        "thread_hash": dict_send["thread_hash"],
        "orig_op_bm_json_obj": None
    }

    if form_post.is_op.data != "yes":
        with session_scope(config.DB_PATH) as new_session:
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == form_post.thread_id.data).first()
            now = time.time()
            if (thread and
                    thread.orig_op_bm_json_obj and
                    thread.last_op_json_obj_ts is not None and
                    now > thread.last_op_json_obj_ts and
                    now - thread.last_op_json_obj_ts > config.OP_RESEND_JSON_OBJ_SEC):
                # Send OP original BM json_obj to heal potentially missing OP
                logger.info(f"Post is not OP and original OP found and time since last OP send is greater "
                            f"than {config.OP_RESEND_JSON_OBJ_SEC / 60 / 60:.1f} hours "
                            f"({(now - thread.last_op_json_obj_ts) / 60 / 60:.1f}). Sending original OP with post.")
                dict_message["orig_op_bm_json_obj"] = json.loads(thread.orig_op_bm_json_obj)

    # Check generated message dict for validity
    errors = check_msg_dict_post(errors, dict_message)
    if errors:
        return "", errors

    if spawn_send_thread:
        # Spawn a thread to send the message if the file is large.
        # This prevents the user's page from either timing out or waiting a very long
        # time to refresh. It's better to give the user feedback about what's happening.
        logger.info("{}: File size above {}. Spawning background upload thread.".format(
            dict_send["post_id"], human_readable_size(config.UPLOAD_SIZE_TO_THREAD)))
        upload_id = get_random_alphanumeric_string(
            32, with_punctuation=False, with_spaces=False)
        msg_send = Thread(
            target=send_message,
            args=(errors, form_post, dict_send, dict_message,),
            kwargs={'upload_id': upload_id})
        msg_send.daemon = True
        msg_send.start()
        msg = "Your file that will be uploaded is {}, which is above the {} size to wait " \
              "for the upload to finish. Instead, a thread was spawned to handle the upload " \
              "and this message was generated to let you know your post is uploading in the " \
              "background. The upload progress can be viewed (after encryption and any other " \
              'processing) on the status page or by clicking ' \
              '<a class="link" href="/upload_progress/{}">here</a>. Depending on the size of your upload ' \
              "and the service it's being uploaded to, the time it takes to send your post will " \
              "vary. Give your post ample time to send so you don't make duplicate posts.".format(
                human_readable_size(save_file_size),
                human_readable_size(config.UPLOAD_SIZE_TO_THREAD),
                upload_id)
        return msg, []
    else:
        logger.info("{}: Sending in foreground.".format(dict_send["post_id"]))
        return send_message(errors, form_post, dict_send, dict_message)


def send_message(errors, form_post, dict_send, dict_message, upload_id=None):
    """Conduct the file upload and sending of a message"""
    save_encrypted_path = None

    if not upload_id:
        upload_id = get_random_alphanumeric_string(
            16, with_spaces=False, with_punctuation=False)

    with session_scope(config.DB_PATH) as new_session:
        try:
            upl = UploadProgress()
            upl.upload_id = upload_id
            upl.uploading = False
            upl.subject = base64.b64decode(dict_send["subject"]).decode()
            upl.total_size_bytes = None
            upl.progress_ts = int(time.time())
            upl.progress = "Organizing attachment(s)"
            upl.post_message = dict_message["message"]
            new_session.add(upl)
            new_session.commit()
        except:
            logger.exception("Couldn't send post")

    zip_file = "/tmp/{}".format(
        get_random_alphanumeric_string(15, with_punctuation=False, with_spaces=False))

    if dict_send["save_dir"]:
        try:
            dict_message["file_enc_cipher"] = form_post.upload_cipher_and_key.data.split(",")[0]
            dict_message["file_enc_key_bytes"] = int(form_post.upload_cipher_and_key.data.split(",")[1])
        except:
            msg = "Unknown cannot parse cipher and key length: {}".format(form_post.upload_cipher_and_key.data)
            errors.append(msg)
            logger.error("{}: {}".format(dict_send["post_id"], msg))
            return "Error", errors

        steg_inserted = False
        for i, f in enumerate(dict_send["file_order"], start=1):
            if not f:
                continue

            fp = os.path.join(dict_send["save_dir"], f)
            file_extension = html.escape(os.path.splitext(f)[1].split(".")[-1].lower())
            try:
                if form_post.strip_exif.data and file_extension in ["png", "jpeg", "jpg"]:
                    PIL.Image.MAX_IMAGE_PIXELS = 500000000
                    im = Image.open(fp)
                    logger.info("{}: Stripping image metadata/exif from {}".format(dict_send["post_id"], fp))
                    im.save(fp)
            except Exception as e:
                msg = "{}: Error opening image/stripping exif: {}".format(dict_send["post_id"], e)
                errors.append(msg)
                logger.exception(msg)

            # encrypt steg message into image
            # Get first image that steg can be inserted into
            if (form_post.steg_message.data and i == form_post.image_steg_insert.data and
                    file_extension in ["jpg", "jpeg"] and
                    not steg_inserted):
                logger.info("{}: Adding steg message to image {}".format(dict_send["post_id"], fp))

                pgp_passphrase_steg = config.PGP_PASSPHRASE_STEG
                with session_scope(config.DB_PATH) as new_session:
                    chan = new_session.query(Chan).filter(
                        Chan.address == form_post.board_id.data).first()
                    if chan and chan.pgp_passphrase_steg:
                        pgp_passphrase_steg = chan.pgp_passphrase_steg

                steg_status = steg_encrypt(
                    fp,
                    fp,
                    form_post.steg_message.data,
                    pgp_passphrase_steg)

                if steg_status != "success":
                    errors.append(steg_status)
                    logger.exception(steg_status)
                else:
                    steg_inserted = True

        # Create zip archive of files
        def zipdir(path, ziph):
            # ziph is zipfile handle
            for root, dirs, files in os.walk(path):
                for file in files:
                    ziph.write(os.path.join(root, file), file)

        try:
            zipf = zipfile.ZipFile(zip_file, 'w', zipfile.ZIP_LZMA)
            zipdir(dict_send["save_dir"], zipf)
            zipf.close()
        except:
            logger.error("{}: Could not zip file")

        # Delete tmp directory
        delete_files_recursive(dict_send["save_dir"])

    if any(dict_send["file_order"]):
        # Generate random filename and extension
        file_extension = ""
        while file_extension in [""] + config.UPLOAD_BANNED_EXT:
            file_name = get_random_alphanumeric_string(
                16, with_punctuation=False, with_spaces=False)
            file_extension = get_random_alphanumeric_string(
                3, with_punctuation=False, with_digits=False, with_spaces=False).lower()
            dict_message["upload_filename"] = "{}.{}".format(file_name, file_extension)
        save_encrypted_path = "/tmp/{}".format(dict_message["upload_filename"])

    logger.info("Upload info: {}, {}".format(dict_send["file_order"], form_post.upload.data))

    #
    # Upload Method
    #

    if any(dict_send["file_order"]) and form_post.upload.data == "bitmessage":
        with session_scope(config.DB_PATH) as new_session:
            settings = new_session.query(GlobalSettings).first()
            if settings.enable_kiosk_mode and settings.kiosk_disable_bm_attach:
                msg = "Attaching files using the Bitmessage Upload Method is currently prohibited. " \
                      "Use one of the alternate upload methods."
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

        # encrypt file
        try:
            dict_message["file_enc_cipher"] = form_post.upload_cipher_and_key.data.split(",")[0]
            dict_message["file_enc_key_bytes"] = int(form_post.upload_cipher_and_key.data.split(",")[1])
        except:
            msg = "Unknown cannot parse cipher and key length: {}".format(form_post.upload_cipher_and_key.data)
            errors.append(msg)
            logger.error("{}: {}".format(dict_send["post_id"], msg))
            return "Error", errors

        if dict_message["file_enc_cipher"] == "NONE":
            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                if settings and not settings.allow_unencrypted_encryption_option:
                    msg = "Encryption is required. Not sending."
                    errors.append(msg)
                    logger.error("{}: {}".format(dict_send["post_id"], msg))
                    return "Error", errors

            logger.info("{}: Not encrypting attachment(s)".format(dict_send["post_id"]))
            os.rename(zip_file, save_encrypted_path)
        else:
            upl = new_session.query(UploadProgress).filter(
                UploadProgress.upload_id == upload_id).first()
            if upl:
                upl.uploading = False
                upl.progress_ts = int(time.time())
                upl.progress = "Encrypting attachment(s)"
                new_session.commit()
            dict_message["file_enc_password"] = get_random_alphanumeric_string(300)
            logger.info("{}: Encrypting attachment(s) with {} and {}-bit key".format(
                dict_send["post_id"],
                dict_message["file_enc_cipher"],
                dict_message["file_enc_key_bytes"] * 8))
            ret_crypto = crypto_multi_enc(
                dict_message["file_enc_cipher"],
                dict_message["file_enc_password"] + config.PGP_PASSPHRASE_ATTACH,
                zip_file,
                save_encrypted_path,
                key_bytes=dict_message["file_enc_key_bytes"])
            if not ret_crypto:
                msg = "Unknown encryption cipher: {}".format(dict_message["file_enc_cipher"])
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

            delete_file(zip_file)

        dict_message["file_base64"] = base64.b64encode(
            open(save_encrypted_path, "rb").read()).decode()

        delete_file(save_encrypted_path)

    elif any(dict_send["file_order"]) and form_post.upload.data == "i2p_torrent":
        with session_scope(config.DB_PATH) as new_session:
            try:
                uid = 1001
                gid = 1001

                # Create encrypted file
                if dict_message["file_enc_cipher"] == "NONE":
                    # Don't extract parts if not encrypted
                    errors, dict_message, dict_send = create_encrypted_upload_zip(
                        errors, dict_message, dict_send, save_encrypted_path, zip_file, make_extracts=False)
                else:
                    errors, dict_message, dict_send = create_encrypted_upload_zip(
                        errors, dict_message, dict_send, save_encrypted_path, zip_file)

                # Generate SHA 256 hash from encrypted file
                hash_encrypted_file = generate_hash(save_encrypted_path)

                # Determine paths
                encrypted_file_filename = f"{hash_encrypted_file}"
                if dict_message["file_enc_cipher"] == "NONE":  # Add zip extension if not encrypted
                    encrypted_file_filename += ".zip"
                path_data = os.path.join('/i2p_qb/Downloads', encrypted_file_filename)
                torrent_filename = f"{hash_encrypted_file}.torrent"
                path_torrent_tmp = os.path.join("/tmp", torrent_filename)

                # Move data to where it will be seeded from
                shutil.move(save_encrypted_path, path_data)  # Move files into tmp directory
                os.chown(path_data, uid, gid)  # Set to proper UID and GID
                os.chmod(path_data, 0o666)

                # Check if torrent already exists
                test_entry_exists = new_session.query(UploadTorrents).filter(
                    UploadTorrents.file_hash == hash_encrypted_file).first()
                if test_entry_exists and os.path.exists(path_data):
                    # Only reset timestamp to wait 28 days to delete
                    logger.error("Torrent already exists. Skipping creation and updating timestamp.")
                    test_entry_exists.timestamp_started = time.time()
                    test_entry_exists.save()
                else:
                    settings = new_session.query(GlobalSettings).first()
                    list_trackers = json.loads(settings.i2p_trackers)

                    # Ensure all trackers have i2p TLD
                    non_i2p_urls = check_tld_i2p(list_trackers)
                    if non_i2p_urls:
                        msg = f"Found non-i2p trackers: {non_i2p_urls}"
                        errors.append(msg)
                        logger.error("{}: {}".format(dict_send["post_id"], msg))
                        return "Error", errors

                    # Create torrent
                    t = Torrent(path=path_data, trackers=list_trackers)
                    t.generate()
                    t.write(path_torrent_tmp)

                    dict_message["file_torrent_magnet"] = str(t.magnet())

                    # Add torrent to client and start seeding
                    conn_info = dict(host=config.QBITTORRENT_HOST, port=8080)
                    qbt_client = qbittorrentapi.Client(**conn_info)
                    qbt_client.auth_log_in()
                    try:
                        ret = qbt_client.torrents_add(torrent_files=path_torrent_tmp, is_paused=True)
                        logger.info(f"Adding paused torrent: {ret}")
                        if ret != "Ok.":
                            logger.error(
                                "{}: Error adding torrent {}".format(dict_send["post_id"], path_torrent_tmp))
                    except:
                        logger.exception("Adding torrent file")

                    qbt_client.auth_log_out()

                    # Save data to database for reference and removal form seeding after 28 days
                    new_torrent = UploadTorrents()
                    new_torrent.file_hash = hash_encrypted_file
                    new_torrent.timestamp_started = time.time()
                    new_session.add(new_torrent)
                    new_session.commit()

                # Convert torrent file to b64
                dict_message["file_torrent_file_hash"] = hash_encrypted_file
                dict_message["file_torrent_base64"] = base64.b64encode(
                    open(path_torrent_tmp, "rb").read()).decode()

                upl = new_session.query(UploadProgress).filter(
                    UploadProgress.upload_id == upload_id).first()
                if upl:
                    upl.progress = "Torrent created and seeding"
                    new_session.commit()
            except:
                logger.exception("Torrent creation failed")
                msg = "Torrent creation failed"
                upl = new_session.query(UploadProgress).filter(
                    UploadProgress.upload_id == upload_id).first()
                if upl:
                    upl.progress = msg
                    new_session.commit()
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))

                # Delete files if not successful
                delete_file(path_data)
                delete_file(path_torrent_tmp)

                return "Error", errors
            finally:
                delete_file(save_encrypted_path)

            upl = new_session.query(UploadProgress).filter(
                UploadProgress.upload_id == upload_id).first()
            if upl:
                upl.uploading = False
                new_session.commit()

    elif any(dict_send["file_order"]) and form_post.upload.data not in ["bitmessage", "i2p_torrent"]:
        with session_scope(config.DB_PATH) as new_session:
            upl = new_session.query(UploadProgress).filter(
                UploadProgress.upload_id == upload_id).first()
            if upl:
                upl.uploading = False
                upl.progress_ts = int(time.time())
                upl.progress = "Encrypting attachment(s)"
                new_session.commit()

            # Create encrypted ZIP file
            errors, dict_message, dict_send = create_encrypted_upload_zip(
                errors, dict_message, dict_send, save_encrypted_path, zip_file)

            # Upload file
            if not upload_id:
                upload_id = get_random_alphanumeric_string(
                    16, with_spaces=False, with_punctuation=False)
            try:
                upl = new_session.query(UploadProgress).filter(
                    UploadProgress.upload_id == upload_id).first()
                if upl:
                    upl.uploading = True
                    upl.total_size_bytes = dict_message["file_size"]
                    upl.progress_ts = int(time.time())
                    upl.progress = "Uploading attachment(s)"
                    new_session.commit()

                upload_success = None
                curl_options = None
                if ("type" in dict_message["file_upload_settings"] and
                        dict_message["file_upload_settings"]["type"] == "anonfile"):
                    if dict_message["file_upload_settings"]["uri"]:
                        anon = AnonFile(
                            proxies=config.TOR_PROXIES,
                            custom_timeout=432000,
                            uri=dict_message["file_upload_settings"]["uri"],
                            upload_id=upload_id)
                    else:
                        anon = AnonFile(
                            proxies=config.TOR_PROXIES,
                            custom_timeout=432000,
                            server=form_post.upload.data,
                            upload_id=upload_id)
                elif ("type" in dict_message["file_upload_settings"] and
                        dict_message["file_upload_settings"]["type"] == "curl"):
                    curl_options = dict_message["file_upload_settings"]
                    curl_upload = UploadCurl(upload_id=upload_id)

                for i in range(3):
                    status = None
                    logger.info("{}: Uploading {} file".format(
                        dict_send["post_id"],
                        human_readable_size(os.path.getsize(save_encrypted_path))))

                    if curl_options and "uri" in curl_options:
                        logger.info("{}: Uploading to {}".format(
                            dict_send["post_id"], curl_options["uri"]))

                    if ("type" in dict_message["file_upload_settings"] and
                            dict_message["file_upload_settings"]["type"] == "anonfile"):
                        status, web_url = anon.upload_file(save_encrypted_path)
                    elif (curl_options and
                            "type" in dict_message["file_upload_settings"] and
                            dict_message["file_upload_settings"]["type"] == "curl"):
                        status, web_url = curl_upload.upload_curl(
                            dict_send["post_id"], save_encrypted_path, curl_options)

                    if not status:
                        logger.error("{}: File upload failed".format(dict_send["post_id"]))
                    else:
                        logger.info("{}: Upload success: URL: {}".format(dict_send["post_id"], web_url.strip()))
                        upload_success = web_url
                        if upl:
                            upl.progress_size_bytes = os.path.getsize(save_encrypted_path)
                            upl.progress_percent = 100
                            new_session.commit()
                        break
                    time.sleep(15)
            except:
                logger.exception("uploading file")
            finally:
                delete_file(save_encrypted_path)
                upl = new_session.query(UploadProgress).filter(
                    UploadProgress.upload_id == upload_id).first()
                if upl:
                    upl.uploading = False
                    new_session.commit()

            upl = new_session.query(UploadProgress).filter(
                UploadProgress.upload_id == upload_id).first()
            upl.progress_ts = int(time.time())

            if upload_success:
                if upl:
                    upl.progress = "Upload success"
                    new_session.commit()
                dict_message["file_url"] = upload_success
            else:
                msg = "File upload failed after 3 attempts"
                if upl:
                    upl.progress = msg
                    new_session.commit()
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

    if zip_file:
        delete_file(zip_file)

    pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
    with session_scope(config.DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == form_post.board_id.data).first()
        if chan and chan.pgp_passphrase_msg:
            pgp_passphrase_msg = chan.pgp_passphrase_msg

    logger.info("{}: Raw Message: {}".format(dict_send["post_id"], dict_message))

    logger.info("{}: Raw Message Size: {}".format(dict_send["post_id"], len(json.dumps(dict_message))))

    # Generate message to send
    gpg = gnupg.GPG()
    message_encrypted = gpg.encrypt(
        json.dumps(dict_message),
        symmetric="AES256",
        passphrase=pgp_passphrase_msg,
        recipients=None)

    logger.info("{}: Encrypted Message Size: {}".format(dict_send["post_id"], len(message_encrypted.data)))

    message_send = base64.b64encode(message_encrypted.data).decode()

    logger.info("{}: Encrypted/B64-encoded Message size: {}".format(dict_send["post_id"], len(message_send)))

    # If OP included in reply, generate new message to send without OP
    message_send_wo_op = None
    orig_op_bm_json_obj = False
    if dict_message["orig_op_bm_json_obj"]:
        orig_op_bm_json_obj = True
        dict_message["orig_op_bm_json_obj"] = None
        gpg = gnupg.GPG()
        message_encrypted_wo_op = gpg.encrypt(
            json.dumps(dict_message),
            symmetric="AES256",
            passphrase=pgp_passphrase_msg,
            recipients=None)
        message_send_wo_op = base64.b64encode(message_encrypted_wo_op.data).decode()

    # Check if the size of the message is too large to be sent
    with session_scope(config.DB_PATH) as new_session:
        settings = new_session.query(GlobalSettings).first()
        if len(message_send) > config.BM_PAYLOAD_MAX_SIZE:
            # Message too large, but check if removing OP from reply (if exists) makes it an acceptable size
            if orig_op_bm_json_obj and message_send_wo_op and len(message_send_wo_op) < config.BM_PAYLOAD_MAX_SIZE:
                logger.info("Message too large with orig_op_bm_json_obj, but not too large without it. "
                            "Sending without it.")
                message_send = message_send_wo_op
            else:
                msg = "Message payload too large: {}. Must be less than {}.".format(
                    human_readable_size(len(message_send)),
                    human_readable_size(config.BM_PAYLOAD_MAX_SIZE))
                logger.error(msg)
                errors.append(msg)
                return "Error", errors
        elif settings.kiosk_max_post_size_bytes != 0 and len(message_send) > settings.kiosk_max_post_size_bytes:
            # Message too large, but check if removing OP from reply (if exists) makes it an acceptable size
            if orig_op_bm_json_obj and len(message_send_wo_op) < settings.kiosk_max_post_size_bytes:
                logger.info("Message too large with orig_op_bm_json_obj, but not too large without it. "
                            "Sending without it.")
                message_send = message_send_wo_op
            else:
                msg = "Message payload too large: {}. Must be less than {}.".format(
                    human_readable_size(len(message_send)),
                    human_readable_size(settings.kiosk_max_post_size_bytes))
                logger.error(msg)
                errors.append(msg)
                return "Error", errors

    # Create new game
    if dict_message["game"]:
        if form_post.thread_id.data:
            test_game = Games.query.filter(and_(
                Games.thread_hash == form_post.thread_id.data,
                Games.game_over.is_(False))).first()
            if test_game:
                errors.append("Cannot start a game in a thread that already has an active game.")
                return "Error", errors
        else:
            errors.append("Cannot start a game without a thread already "
                          "existing. Create an OP, then start a game.")
            return "Error", errors

        test_game = Games.query.filter(
            and_(
                Games.game_hash == dict_message["game_hash"],
                Games.game_over.is_(False)
            )).first()
        if test_game:
            logger.info("Game already found with submitted hash. "
                        "Generating a new hash for a new game.")
            dict_message["game_hash"] = get_random_alphanumeric_string(
                15, with_punctuation=False, with_spaces=False)

        logger.info("Starting game as host with game_hash {}".format(
            dict_message["game_hash"]))
        new_game = Games()
        new_game.is_host = True
        new_game.game_over = False
        new_game.host_from_address = form_post.from_address.data
        new_game.thread_hash = form_post.thread_id.data
        new_game.game_hash = dict_message["game_hash"]
        new_game.game_type = dict_message["game"]
        players = {
            "player_a": {
                "name": "",
                "address": None
            },
            "player_b": {
                "name": "",
                "address": None
            }
        }

        if dict_message["game"] == "chess":
            players["player_a"]["name"] = "White (uppercase)"
            players["player_b"]["name"] = "Black (lowercase)"
        elif dict_message["game"] == "tic_tac_toe":
            players["player_a"]["name"] = "X"
            players["player_b"]["name"] = "O"
        else:
            logger.error("Unknown game: {}".format(dict_message["game"]))

        if form_post.game_password_b.data:
            players["player_a"]["password_b_hash"] = hashlib.sha512(
                form_post.game_password_b.data.encode('utf-8')).hexdigest()
        if form_post.game_termination_password.data:
            new_game.game_termination_pw_hash = hashlib.sha512(
                form_post.game_termination_password.data.encode('utf-8')).hexdigest()
        new_game.players = json.dumps(players)
        new_game.save()
        logger.info("Storing new game (uninitiated): {}".format(dict_message["game"]))

    # prolong inventory clear if sending a message
    now = time.time()
    if daemon_com.get_timer_clear_inventory() > now:
        daemon_com.update_timer_clear_inventory(config.CLEAR_INVENTORY_WAIT)

    # Don't allow a message to send while Bitmessage is restarting
    allow_send = False
    timer = time.time()
    while not allow_send:
        if daemon_com.bitmessage_restarting() is False:
            allow_send = True
        if time.time() - timer > config.BM_WAIT_DELAY:
            logger.error(
                "{}: Unable to send message: "
                "Could not detect Bitmessage running.".format(dict_send["post_id"]))
            msg = "Unable to send message."
            errors.append("Unable to send message: Could not detect Bitmessage running.")
            return msg, errors
        time.sleep(1)

    ttl = get_post_ttl(form_post.ttl.data)

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
        return_str = None
        try:
            return_str = api.sendMessage(
                form_post.board_id.data,
                form_post.from_address.data,
                "",
                message_send,
                2,
                ttl)
            if return_str:
                logger.info("{}: Message sent from {} to {} with TTL of {} sec: {}".format(
                    dict_send["post_id"],
                    form_post.from_address.data,
                    form_post.board_id.data,
                    ttl,
                    return_str))
        except Exception:
            pass
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API)
            return_msg = "Post of {} size and {} second TTL placed in send queue. The time it " \
                         "takes to send a message is dependent on the size and TTL of the " \
                         "post due to the proof of work required to send. " \
                         "Generally, the larger the size and longer the TTL, the longer it takes to " \
                         "send. Posts ~10 KB take around a minute or less to send, " \
                         "whereas messages >= 100 KB can take several minutes to " \
                         "send. BM returned: {}".format(
                            human_readable_size(len(message_send)), ttl, return_str)
            return return_msg, errors


def send_post_delete_request(from_address, to_address, message_id, thread_hash, delete_password):
    errors = []
    run_id = get_random_alphanumeric_string(
        6, with_punctuation=False, with_spaces=False)

    dict_message = {
        "version": config.VERSION_MSG,
        "message_type": "post_delete_password",
        "timestamp_utc": daemon_com.get_utc(),
        "message_id": message_id,
        "thread_hash": thread_hash,
        "delete_password": delete_password,
    }

    pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
    with session_scope(config.DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == to_address).first()
        if chan and chan.pgp_passphrase_msg:
            pgp_passphrase_msg = chan.pgp_passphrase_msg

    gpg = gnupg.GPG()
    message_encrypted = gpg.encrypt(
        json.dumps(dict_message),
        symmetric="AES256",
        passphrase=pgp_passphrase_msg,
        recipients=None)

    message_send = base64.b64encode(message_encrypted.data).decode()

    with session_scope(config.DB_PATH) as new_session:
        settings = new_session.query(GlobalSettings).first()
        if len(message_send) > config.BM_PAYLOAD_MAX_SIZE:
            msg = "Message payload too large: {}. Must be less than {}.".format(
                human_readable_size(len(message_send)),
                human_readable_size(config.BM_PAYLOAD_MAX_SIZE))
            logger.error(msg)
            errors.append(msg)
            return "Error", errors
        elif settings.kiosk_max_post_size_bytes != 0 and len(message_send) > settings.kiosk_max_post_size_bytes:
            msg = "Message payload too large: {}. Must be less than {}.".format(
                human_readable_size(len(message_send)),
                human_readable_size(settings.kiosk_max_post_size_bytes))
            logger.error(msg)
            errors.append(msg)
            return "Error", errors
        else:
            logger.info("{}: Message size: {}".format(run_id, len(message_send)))

    # prolong inventory clear if sending a message
    now = time.time()
    if daemon_com.get_timer_clear_inventory() > now:
        daemon_com.update_timer_clear_inventory(config.CLEAR_INVENTORY_WAIT)

    # Don't allow a message to send while Bitmessage is restarting
    allow_send = False
    timer = time.time()
    while not allow_send:
        if daemon_com.bitmessage_restarting() is False:
            allow_send = True
        if time.time() - timer > config.BM_WAIT_DELAY:
            logger.error(
                "{}: Unable to send message: "
                "Could not detect Bitmessage running.".format(run_id))
            msg = "Unable to send message."
            errors = ["Could not detect Bitmessage running."]
            return msg, errors
        time.sleep(1)

    ttl = get_post_ttl()

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
        return_str = None
        try:
            return_str = api.sendMessage(
                to_address,
                from_address,
                "",
                message_send,
                2,
                ttl)
            if return_str:
                logger.info("{}: Message sent from {} to {} with TTL of {} sec: {}".format(
                    run_id,
                    from_address,
                    to_address,
                    ttl,
                    return_str))
        except Exception:
            pass
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API)
            return_msg = "Post of {} size and {} second TTL placed in send queue. The time it " \
                         "takes to send a message is dependent on the size and TTL of the " \
                         "post due to the proof of work required to send. " \
                         "Generally, the larger the size and longer the TTL, the longer it takes to " \
                         "send. Posts ~10 KB take around a minute or less to send, " \
                         "whereas messages >= 100 KB can take several minutes to " \
                         "send. BM returned: {}".format(
                human_readable_size(len(message_send)), ttl, return_str)
            return return_msg, errors


def create_encrypted_upload_zip(errors, dict_message, dict_send, save_encrypted_path, zip_file, make_extracts=True):
    with session_scope(config.DB_PATH) as new_session:
        # encrypt file
        if dict_message["file_enc_cipher"] == "NONE":
            settings = new_session.query(GlobalSettings).first()
            if settings and not settings.allow_unencrypted_encryption_option:
                msg = "Encryption is required. Not sending."
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

            logger.info("{}: Not encrypting attachment(s)".format(dict_send["post_id"]))
            os.rename(zip_file, save_encrypted_path)
        else:
            dict_message["file_enc_password"] = get_random_alphanumeric_string(300)
            logger.info("{}: Encrypting attachment(s) with {} and {}-bit key".format(
                dict_send["post_id"],
                dict_message["file_enc_cipher"],
                dict_message["file_enc_key_bytes"] * 8))
            ret_crypto = crypto_multi_enc(
                dict_message["file_enc_cipher"],
                dict_message["file_enc_password"] + config.PGP_PASSPHRASE_ATTACH,
                zip_file,
                save_encrypted_path,
                key_bytes=dict_message["file_enc_key_bytes"])
            if not ret_crypto:
                msg = "Unknown encryption cipher: {}".format(dict_message["file_enc_cipher"])
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

            delete_file(zip_file)

    # Generate hash before parts removed
    dict_message["file_sha256_hash"] = generate_hash(save_encrypted_path)
    if dict_message["file_sha256_hash"]:
        logger.info("{}: Attachment hash generated: {}".format(
            dict_send["post_id"], dict_message["file_sha256_hash"]))

    if make_extracts:
        file_size = os.path.getsize(save_encrypted_path)
        number_of_extracts = config.UPLOAD_FRAG_AMT
        if file_size < 2000:
            extract_starts_sizes = [{
                "start": 0,
                "size": int(file_size * 0.5)
            }]
        else:
            extract_starts_sizes = [{
                "start": 0,
                "size": config.UPLOAD_FRAG_START_BYTES
            }]
            sequences = return_non_overlapping_sequences(
                number_of_extracts,
                config.UPLOAD_FRAG_START_BYTES,
                file_size - config.UPLOAD_FRAG_END_BYTES,
                config.UPLOAD_FRAG_MIN_BYTES,
                config.UPLOAD_FRAG_MAX_BYTES)
            for pos, size in sequences:
                extract_starts_sizes.append({
                    "start": pos,
                    "size": size
                })
            extract_starts_sizes.append({
                "start": file_size - config.UPLOAD_FRAG_END_BYTES,
                "size": config.UPLOAD_FRAG_END_BYTES
            })
        logger.info("{}: File extraction positions and sizes: {}".format(
            dict_send["post_id"], extract_starts_sizes))
        logger.info("{}: File size before: {}".format(
            dict_send["post_id"], os.path.getsize(save_encrypted_path)))

        data_extracted_start_base64 = data_file_multiple_extract(
            save_encrypted_path, extract_starts_sizes, chunk=4096)

        dict_message["file_extracts_start_base64"] = json.dumps(data_extracted_start_base64)

    dict_message["file_size"] = os.path.getsize(save_encrypted_path)
    logger.info("{}: Final file size: {}".format(
        dict_send["post_id"], dict_message["file_size"]))

    return errors, dict_message, dict_send
