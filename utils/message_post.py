import base64
import html
import json
import logging
import os
import time
import zipfile
from threading import Thread

import PIL
import gnupg
from PIL import Image

import config
from database.models import Chan
from database.models import UploadSites
from database.models import Flags
from database.models import Threads
from database.models import UploadProgress
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
from utils.general import get_random_alphanumeric_string
from utils.steg import steg_encrypt
from utils.upload import upload_curl

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.message_post')


def post_message(form_post, form_steg):
    form_populate = {}
    return_str = None
    status_msg = {"status_message": []}

    if not form_post.from_address.data:
        status_msg['status_message'].append("A From Address is required.")

    if form_post.is_op.data == "yes":
        if len(form_post.subject.data.strip()) == 0:
            status_msg['status_message'].append("A Subject is required.")
        if not form_post.body.data:
            status_msg['status_message'].append("A Comment is required.")
    else:
        if (not form_post.body.data and
                (not form_post.file1.data[0] and
                 not form_post.file2.data[0] and
                 not form_post.file3.data[0] and
                 not form_post.file4.data[0])):
            status_msg['status_message'].append("A Comment or File is required.")

    if len(form_post.body.data + form_post.subject.data.strip()) > config.MAX_SUBJECT_COMMENT:
        status_msg['status_message'].append(
            "Limit of {} characters exceeded for Subject + Comment: {}".format(
                config.MAX_SUBJECT_COMMENT, len(form_post.body.data)))

    if form_post.ttl.data > 2419200 or form_post.ttl.data < 3600:
        status_msg['status_message'].append("TTL must be between 3600 seconds (1 hour) and 2419200 seconds (28 days)")

    steg_submit = None
    file_list = []
    if bool(form_post.file1.data[0]):
        file_list.append(form_post.file1.data[0])
    if bool(form_post.file2.data[0]):
        file_list.append(form_post.file2.data[0])
    if bool(form_post.file3.data[0]):
        file_list.append(form_post.file3.data[0])
    if bool(form_post.file4.data[0]):
        file_list.append(form_post.file4.data[0])

    if file_list:
        found_image = False
        for each_file in file_list:
            try:
                file_extension = each_file.filename.split(".")[-1].lower()
                if len(file_extension) >= config.MAX_FILE_EXT_LENGTH:
                    status_msg['status_message'].append(
                        "File extension lengths must be less than {}.".format(config.MAX_FILE_EXT_LENGTH))
                if file_extension in config.FILE_EXTENSIONS_IMAGE:
                    found_image = True
            except Exception as e:
                status_msg['status_message'].append("Error determining file extension. {}".format(e))

        if form_steg.steg_message.data:
            steg_submit = form_steg
            if not found_image:
                status_msg['status_message'].append("Steg comments require an image attachment.")

    if "status_message" not in status_msg or not status_msg["status_message"]:
        return_str, errors = submit_post(form_post, form_steg=steg_submit)
        if return_str == "Error":
            status_msg['status_title'] = "Error"
            status_msg['status_message'] = status_msg['status_message'] + errors
        else:
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(return_str)
    else:
        status_msg['status_title'] = "Error"

    if status_msg['status_title'] == "Error":
        form_populate = {
            "from_address": form_post.from_address.data,
            "subject": form_post.subject.data,
            "comment": form_post.body.data,
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
            "steg_comment": form_steg.steg_message.data,
            "ttl": form_post.ttl.data
        }

    return status_msg, return_str, form_populate


def submit_post(form_post, form_steg=None):
    """Process the form for making a post"""
    from bitchan_flask import nexus

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
        "file_upload_settings": {},
        "file_extracts_start_base64": None,
        "file_sha256_hash": None,
        "file_enc_cipher": None,
        "file_enc_key_bytes": None,
        "file_enc_password": None,
        "file_order": [],
        "media_height": None,
        "media_width": None,
        "file_uploaded": None,
        "upload_filename": None,
        "op_sha256_hash": None,
        "subject": None,
        "message": None,
        "nation": None,
        "nation_base64": None,
        "nation_name": None,
        "post_id": get_random_alphanumeric_string(6, with_punctuation=False, with_spaces=False)
    }

    if form_post.is_op.data != "yes":
        chan_thread = nexus.get_chan_thread(
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
        if (form_post.nation.data.startswith("customflag") and
                len(form_post.nation.data.split("_")) == 2):
            flag_id = int(form_post.nation.data.split("_")[1])
            with session_scope(DB_PATH) as new_session:
                flag = new_session.query(Flags).filter(Flags.id == flag_id).first()
                if flag:
                    dict_send["nation_name"] = flag.name
                    dict_send["nation_base64"] = flag.flag_base64
        else:
            dict_send["nation"] = form_post.nation.data

    if form_post.body.data:
        dict_send["message"] = form_post.body.data.encode('utf-8').strip().decode()

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
        if save_file_size > config.UPLOAD_SIZE_TO_THREAD:
            spawn_send_thread = True

    if spawn_send_thread:
        # Spawn a thread to send the message if the file is large.
        # This prevents the user's page from either timing out or waiting a very long
        # time to refresh. It's better to give the user feedback about what's happening.
        logger.info("{}: File size above {}. Spawning background upload thread.".format(
            dict_send["post_id"], human_readable_size(config.UPLOAD_SIZE_TO_THREAD)))
        msg_send = Thread(
            target=send_message, args=(errors, form_post, form_steg, dict_send,))
        msg_send.daemon = True
        msg_send.start()
        msg = "Your file that will be uploaded is {}, which is above the {} size to wait " \
              "for the upload to finish. Instead, a thread was spawned to handle the upload " \
              "and this message was generated to let you know your post is uploading in the " \
              "background. The upload progress can be viewed (after encryption and any other " \
              "processing) on the status page). Depending on the size of your upload and the " \
              "service it's being uploaded to, the time it takes to send your post will vary. " \
              "Give your post ample time to send so you don't make duplicate posts.".format(
                human_readable_size(save_file_size),
                human_readable_size(config.UPLOAD_SIZE_TO_THREAD))
        return msg, []
    else:
        logger.info("{}: No files or total file size below {}. Sending in foreground.".format(
            dict_send["post_id"], human_readable_size(config.UPLOAD_SIZE_TO_THREAD)))
        return send_message(errors, form_post, form_steg, dict_send)


def send_message(errors, form_post, form_steg, dict_send):
    """Conduct the file upload and sending of a message"""
    from bitchan_flask import nexus

    zip_file = "/tmp/{}".format(
        get_random_alphanumeric_string(15, with_punctuation=False, with_spaces=False))

    if dict_send["save_dir"]:
        try:
            dict_send["file_enc_cipher"] = form_post.upload_cipher_and_key.data.split(",")[0]
            dict_send["file_enc_key_bytes"] = int(form_post.upload_cipher_and_key.data.split(",")[1])
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
            if (form_steg and i == form_steg.image_steg_insert.data and
                    file_extension in ["jpg", "jpeg", "png"] and
                    not steg_inserted):
                logger.info("{}: Adding steg message to image {}".format(dict_send["post_id"], fp))

                pgp_passphrase_steg = config.PGP_PASSPHRASE_STEG
                with session_scope(DB_PATH) as new_session:
                    chan = new_session.query(Chan).filter(
                        Chan.address == form_post.board_id.data).first()
                    if chan and chan.pgp_passphrase_steg:
                        pgp_passphrase_steg = chan.pgp_passphrase_steg

                steg_status = steg_encrypt(
                    fp,
                    fp,
                    form_steg.steg_message.data,
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
                30, with_punctuation=False, with_spaces=False)
            file_extension = get_random_alphanumeric_string(
                3, with_punctuation=False, with_digits=False, with_spaces=False).lower()
            dict_send["upload_filename"] = "{}.{}".format(file_name, file_extension)
        save_encrypted_path = "/tmp/{}".format(dict_send["upload_filename"])

    if any(dict_send["file_order"]) and form_post.upload.data != "bitmessage":
        with session_scope(DB_PATH) as new_session:
            upload_info = new_session.query(UploadSites).filter(
                UploadSites.domain == form_post.upload.data).first()

            if upload_info:
                dict_send["file_url_type"] = upload_info.domain
                dict_send["file_upload_settings"] = {
                    "domain": upload_info.domain,
                    "type": upload_info.type,
                    "uri": upload_info.uri,
                    "download_prefix": upload_info.download_prefix,
                    "response": upload_info.response,
                    "direct_dl_url": upload_info.direct_dl_url,
                    "extra_curl_options": upload_info.extra_curl_options,
                    "upload_word": upload_info.upload_word,
                    "form_name": upload_info.form_name
                }
            else:
                logger.error("{}: Upload domain not found".format(dict_send["post_id"]))

            # encrypt file
            if dict_send["file_enc_cipher"] == "NONE":
                logger.info("{}: Not encrypting attachment(s)".format(dict_send["post_id"]))
                os.rename(zip_file, save_encrypted_path)
            else:
                dict_send["file_enc_password"] = get_random_alphanumeric_string(300)
                logger.info("{}: Encrypting attachment(s) with {} and {}-bit key".format(
                    dict_send["post_id"],
                    dict_send["file_enc_cipher"],
                    dict_send["file_enc_key_bytes"] * 8))
                ret_crypto = crypto_multi_enc(
                    dict_send["file_enc_cipher"],
                    dict_send["file_enc_password"] + config.PGP_PASSPHRASE_ATTACH,
                    zip_file,
                    save_encrypted_path,
                    key_bytes=dict_send["file_enc_key_bytes"])
                if not ret_crypto:
                    msg = "Unknown encryption cipher: {}".format(dict_send["file_enc_cipher"])
                    errors.append(msg)
                    logger.error("{}: {}".format(dict_send["post_id"], msg))
                    return "Error", errors

                delete_file(zip_file)

            # Generate hash before parts removed
            dict_send["file_sha256_hash"] = generate_hash(save_encrypted_path)
            if dict_send["file_sha256_hash"]:
                logger.info("{}: Attachment hash generated: {}".format(
                    dict_send["post_id"], dict_send["file_sha256_hash"]))

            file_size = os.path.getsize(save_encrypted_path)
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
                dict_send["post_id"], os.path.getsize(save_encrypted_path)))

            data_extracted_start_base64 = data_file_multiple_extract(
                save_encrypted_path, extract_starts_sizes, chunk=4096)

            dict_send["file_size"] = os.path.getsize(save_encrypted_path)
            logger.info("{}: File size after: {}".format(
                dict_send["post_id"], dict_send["file_size"]))

            dict_send["file_extracts_start_base64"] = json.dumps(data_extracted_start_base64)

            # Upload file
            upload_id = get_random_alphanumeric_string(
                12, with_spaces=False, with_punctuation=False)
            try:
                with session_scope(DB_PATH) as new_session:
                    upl = UploadProgress()
                    upl.upload_id = upload_id
                    upl.uploading = True
                    upl.subject = base64.b64decode(dict_send["subject"]).decode()
                    upl.total_size_bytes = dict_send["file_size"]
                    new_session.add(upl)
                    new_session.commit()

                upload_success = None
                curl_options = None
                if ("type" in dict_send["file_upload_settings"] and
                        dict_send["file_upload_settings"]["type"] == "anonfile"):
                    if dict_send["file_upload_settings"]["uri"]:
                        anon = AnonFile(
                            proxies=config.TOR_PROXIES,
                            custom_timeout=432000,
                            uri=dict_send["file_upload_settings"]["uri"],
                            upload_id=upload_id)
                    else:
                        anon = AnonFile(
                            proxies=config.TOR_PROXIES,
                            custom_timeout=432000,
                            server=form_post.upload.data,
                            upload_id=upload_id)
                elif ("type" in dict_send["file_upload_settings"] and
                        dict_send["file_upload_settings"]["type"] == "curl"):
                    curl_options = dict_send["file_upload_settings"]

                for i in range(3):
                    logger.info("{}: Uploading {} file".format(
                        dict_send["post_id"],
                        human_readable_size(os.path.getsize(save_encrypted_path))))
                    if ("type" in dict_send["file_upload_settings"] and
                            dict_send["file_upload_settings"]["type"] == "anonfile"):
                        status, web_url = anon.upload_file(save_encrypted_path)
                    elif (curl_options and
                            "type" in dict_send["file_upload_settings"] and
                            dict_send["file_upload_settings"]["type"] == "curl"):
                        status, web_url = upload_curl(
                            dict_send["post_id"],
                            curl_options["domain"],
                            curl_options["uri"],
                            save_encrypted_path,
                            download_prefix=curl_options["download_prefix"],
                            extra_curl_options=curl_options["extra_curl_options"],
                            upload_word=curl_options["upload_word"],
                            response=curl_options["response"])

                    if not status:
                        logger.error("{}: File upload failed".format(dict_send["post_id"]))
                    else:
                        logger.info("{}: Upload success: URL: {}".format(dict_send["post_id"], web_url))
                        upload_success = web_url
                        with session_scope(DB_PATH) as new_session:
                            upl = new_session.query(UploadProgress).filter(
                                UploadProgress.upload_id == upload_id).first()
                            if upl:
                                upl.progress_size_bytes = os.path.getsize(save_encrypted_path)
                                upl.progress_percent = 100
                                upl.uploading = False
                                new_session.commit()
                        break
                    time.sleep(15)
            finally:
                delete_file(save_encrypted_path)
                with session_scope(DB_PATH) as new_session:
                    upl = new_session.query(UploadProgress).filter(
                        UploadProgress.upload_id == upload_id).first()
                    if upl:
                        upl.uploading = False
                        new_session.commit()

            if upload_success:
                dict_send["file_url"] = upload_success
            else:
                msg = "File upload failed after 3 attempts"
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

    elif any(dict_send["file_order"]) and form_post.upload.data == "bitmessage":
        # encrypt file
        try:
            dict_send["file_enc_cipher"] = form_post.upload_cipher_and_key.data.split(",")[0]
            dict_send["file_enc_key_bytes"] = int(form_post.upload_cipher_and_key.data.split(",")[1])
        except:
            msg = "Unknown cannot parse cipher and key length: {}".format(form_post.upload_cipher_and_key.data)
            errors.append(msg)
            logger.error("{}: {}".format(dict_send["post_id"], msg))
            return "Error", errors

        if dict_send["file_enc_cipher"] == "NONE":
            logger.info("{}: Not encrypting attachment(s)".format(dict_send["post_id"]))
            os.rename(zip_file, save_encrypted_path)
        else:
            dict_send["file_enc_password"] = get_random_alphanumeric_string(300)
            logger.info("{}: Encrypting attachment(s) with {} and {}-bit key".format(
                dict_send["post_id"],
                dict_send["file_enc_cipher"],
                dict_send["file_enc_key_bytes"] * 8))
            ret_crypto = crypto_multi_enc(
                dict_send["file_enc_cipher"],
                dict_send["file_enc_password"] + config.PGP_PASSPHRASE_ATTACH,
                zip_file,
                save_encrypted_path,
                key_bytes=dict_send["file_enc_key_bytes"])
            if not ret_crypto:
                msg = "Unknown encryption cipher: {}".format(dict_send["file_enc_cipher"])
                errors.append(msg)
                logger.error("{}: {}".format(dict_send["post_id"], msg))
                return "Error", errors

            delete_file(zip_file)

        dict_send["file_uploaded"] = base64.b64encode(
            open(save_encrypted_path, "rb").read()).decode()

        delete_file(save_encrypted_path)

    dict_message = {
        "version": config.VERSION_BITCHAN,
        "message_type": "post",
        "is_op": form_post.is_op.data == "yes",
        "op_sha256_hash": dict_send["op_sha256_hash"],
        "timestamp_utc": nexus.get_utc(),
        "file_size": dict_send["file_size"],
        "file_amount": dict_send["file_amount"],
        "file_url_type": dict_send["file_url_type"],
        "file_url": dict_send["file_url"],
        "file_upload_settings": dict_send["file_upload_settings"],
        "file_extracts_start_base64": dict_send["file_extracts_start_base64"],
        "file_base64": dict_send["file_uploaded"],
        "file_sha256_hash": dict_send["file_sha256_hash"],
        "file_enc_cipher": dict_send["file_enc_cipher"],
        "file_enc_key_bytes": dict_send["file_enc_key_bytes"],
        "file_enc_password": dict_send["file_enc_password"],
        "file_order": dict_send["file_order"],
        "image1_spoiler": form_post.image1_spoiler.data,
        "image2_spoiler": form_post.image2_spoiler.data,
        "image3_spoiler": form_post.image3_spoiler.data,
        "image4_spoiler": form_post.image4_spoiler.data,
        "upload_filename": dict_send["upload_filename"],
        "subject": dict_send["subject"],
        "message": dict_send["message"],
        "nation": dict_send["nation"],
        "nation_base64": dict_send["nation_base64"],
        "nation_name": dict_send["nation_name"],
    }

    if zip_file:
        delete_file(zip_file)

    pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == form_post.board_id.data).first()
        if chan and chan.pgp_passphrase_msg:
            pgp_passphrase_msg = chan.pgp_passphrase_msg

    gpg = gnupg.GPG()
    message_encrypted = gpg.encrypt(
        json.dumps(dict_message),
        symmetric="AES256",
        passphrase=pgp_passphrase_msg,
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

    # prolong inventory clear if sending a message
    now = time.time()
    if nexus.timer_clear_inventory > now:
        nexus.timer_clear_inventory = now + config.CLEAR_INVENTORY_WAIT

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_API, to=60):
        return_str = None
        try:
            time.sleep(0.1)
            return_str = nexus._api.sendMessage(
                form_post.board_id.data,
                form_post.from_address.data,
                "",
                message_send,
                2,
                form_post.ttl.data)
            if return_str:
                logger.info("{}: Message sent from {} to {} with TTL of {} sec: {}".format(
                    dict_send["post_id"],
                    form_post.from_address.data,
                    form_post.board_id.data,
                    form_post.ttl.data,
                    return_str))
                nexus.post_delete_queue(form_post.from_address.data, return_str)
            time.sleep(0.1)
        except Exception:
            pass
        finally:
            lf.lock_release(config.LOCKFILE_API)
            return_msg = "Post of size {} placed in send queue. The time it " \
                         "takes to send a message is related to the size of the " \
                         "post due to the proof of work required to send. " \
                         "Generally, the larger the post, the longer it takes to " \
                         "send. Posts ~10 KB take around a minute or less to send, " \
                         "whereas messages >= 100 KB can take several minutes to " \
                         "send. BM returned: {}".format(
                            human_readable_size(len(message_send)), return_str)
            return return_msg, errors
