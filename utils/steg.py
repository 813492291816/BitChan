import base64
import html
import logging
import os
from io import BytesIO

import gnupg
from utils.stegano.exifHeader import exifHeader

import config
from utils.encryption_decrypt import decrypt_safe_size
from utils.replacements import process_replacements

logger = logging.getLogger('bitchan.steg')


def steg_encrypt(orig_img, steg_img, sec_msg, gpg_pass):
    org_file_ext = orig_img.split(".")[-1].lower()

    try:
        if org_file_ext in ["jpg", "jpeg", "tiff"]:
            # PGP-encrypt steg message
            gpg = gnupg.GPG()
            enc_msg = gpg.encrypt(
                sec_msg.encode('utf-8'), symmetric="AES256", passphrase=gpg_pass, recipients=None)

            # base64-encode encrypted steg message
            msg_enc_b64enc = base64.b64encode(enc_msg.data).decode()

            exifHeader.hide(orig_img, steg_img, secret_message=msg_enc_b64enc)
            return "success"
            # elif org_file_ext == "png":
            #     secret = lsb.hide(orig_img, msg_enc_b64enc, auto_convert_rgb=True)
            #     secret.save(steg_img)
            #     return "success"
        else:
            return "Unsupported file type for Steg"
    except Exception as err:
        return err


def steg_decrypt(steg_img, gpg_pass, file_extension=None):
    if file_extension:
        steg_file_ext = file_extension
    else:
        steg_file_ext = steg_img.split(".")[-1]

    try:
        if steg_file_ext.lower() in ["jpg", "jpeg", "tiff"]:
            base64_message = exifHeader.reveal(steg_img).decode()
        # elif steg_file_ext.lower() == "png":
        #     base64_message = lsb.reveal(steg_img)
        else:
            logger.error("File type not accepted for steg decryption: {}".format(
                steg_file_ext.lower()))
            return
    except:
        return

    # base64-decode steg message
    decoded_steg_message = base64.b64decode(base64_message).decode()

    # PGP-decrypt steg message
    decrypted_msg = decrypt_safe_size(decoded_steg_message, gpg_pass, 400000)

    return decrypted_msg


def check_steg(message_id, file_extension, passphrase=config.PGP_PASSPHRASE_STEG, file_path=None, file_decoded=None):
    """Check image for steg message"""
    try:
        if file_path and os.path.exists(file_path):
            steg_message = steg_decrypt(file_path, passphrase)
        elif file_decoded:
            steg_message = steg_decrypt(
                BytesIO(file_decoded),
                passphrase,
                file_extension=file_extension)
        else:
            logger.error("Could not find file to extract steg from")
            return

        if not steg_message:
            logger.info("Could not decrypt steg PGP")
            return

        try:
            logger.info("{}: Found steg message in attached image".format(message_id[-config.ID_LENGTH:].upper()))
            message_steg = html.escape(steg_message)
            message_steg = process_replacements(
                message_steg, "{}steg".format(message_id), message_id, steg=True)
            return message_steg
        except Exception as err:
            logger.error("Error processing replacements: {}".format(err))
    except Exception as err:
        logger.error("Could not extract steg message: {}".format(err))
