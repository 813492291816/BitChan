import base64
import json
import logging
import os
import time
from io import BytesIO

import gnupg
from PIL import Image

import config
from utils.files import LF
from utils.files import human_readable_size

logger = logging.getLogger('bitchan.utils.messagees')


def post_message(form_post, form_steg):
    return_str = None
    status_msg = {"status_message": []}

    if not form_post.from_address.data:
        status_msg['status_message'].append("A From address is required.")

    if form_post.is_op.data == "yes":
        if len(form_post.subject.data.strip()) == 0:
            status_msg['status_message'].append("A subject is required.")
        if not form_post.body.data:
            status_msg['status_message'].append("A comment is required.")
    else:
        if not form_post.body.data and not form_post.file.data:
            status_msg['status_message'].append("A comment or attachment is required.")

    if len(form_post.body.data + form_post.subject.data.strip()) > 246250:
        status_msg['status_message'].append(
            "Limit of 246,250 characters exceeded for Subject + Comment: {}".format(
                len(form_post.body.data)))

    steg_submit = None
    if form_steg.steg_message.data:
        steg_submit = form_steg
        if form_post.file.data:
            try:
                file_filename = form_post.file.data.filename
                file_extension = os.path.splitext(file_filename)[1].split(".")[1].lower()
                if len(file_extension) > 6:
                    status_msg['status_message'].append("File extension length must be less than 7.")
                if file_extension not in config.FILE_EXTENSIONS_IMAGE:
                    status_msg['status_message'].append("Steg comments require an image attachment.")
            except:
                status_msg['status_message'].append("Error determining file extension. Is there one?")

    form_populate = {}
    if "status_message" not in status_msg or not status_msg["status_message"]:
        from bitchan_flask import nexus
        return_str, errors = nexus.submit_post(form_post, form_steg=steg_submit)
        if return_str == "Error":
            status_msg['status_title'] = "Error"
            status_msg['status_message'] = status_msg['status_message'] + errors
        else:
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(return_str)
    else:
        status_msg['status_title'] = "Error"
        form_populate = {
            "from_address": form_post.from_address.data,
            "subject": form_post.subject.data,
            "comment": form_post.body.data,
            "file": bool(form_post.file.data),
            "upload": form_post.upload.data,
            "strip_exif": form_post.strip_exif.data,
            "image_spoiler": form_post.image_spoiler.data,
            "steg_comment": form_steg.steg_message.data
        }

    return status_msg, return_str, form_populate
