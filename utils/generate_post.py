import json
import logging
import random
from flask import render_template

import config
from bitchan_client import DaemonCom
from database.models import Messages
from database.models import UploadSites
from utils.files import LF
from utils.gpg import find_gpg
from utils.gpg import gpg_decrypt
from utils.replacements import process_replacements

daemon_com = DaemonCom()
logger = logging.getLogger("bitchan.generate_post")


def generate_post_html(message_id, board_view=False):
    msg = Messages.query.filter(Messages.message_id == message_id).first()
    if not msg:
        return "Could not find post"

    if msg.regenerate_post_html or not msg.post_html_board_view or not msg.post_html:
        # Reduce the number of concurrent posts being generated
        rand_int = random.randint(0, 2)
        lf = LF()
        file_lock = f"/var/lock/gen_html_{rand_int}.lock"
        if lf.lock_acquire(file_lock, to=300):
            try:
                # Check once more to see if html has been generated
                msg = Messages.query.filter(Messages.message_id == message_id).first()
                if msg.regenerate_post_html or not msg.post_html_board_view or not msg.post_html:

                    if msg.regenerate_post_html:
                        text_replacements = process_replacements(
                            msg.original_message, message_id, message_id, address=msg.thread.chan.address)
                        message = text_replacements

                        # Find GPG strings in message and attempt to decrypt
                        if message:
                            try:
                                message, gpg_texts = find_gpg(message)
                                gpg_texts = json.dumps(gpg_decrypt(gpg_texts))
                                msg.gpg_texts = gpg_texts
                            except Exception as err:
                                logger.exception("{}: Error processing gpg: {}".format(
                                    message_id[-config.ID_LENGTH:].upper(), err))

                        msg.message = message
                        msg.text_replacements = text_replacements
                        msg.save()

                    if msg.regenerate_post_html or not msg.post_html_board_view:
                        board = {
                            "current_chan": msg.thread.chan,
                            "current_thread": msg.thread,
                            "messages": Messages,
                            "board_view": True
                        }

                        post_html_board_view = render_template("elements/board/post.html",
                                                               board=board,
                                                               msg=msg,
                                                               post_id=msg.post_id,
                                                               table_messages=Messages,
                                                               upload_sites=UploadSites)
                        msg.post_html_board_view = post_html_board_view
                        msg.save()

                    if msg.regenerate_post_html or not msg.post_html:
                        board = {
                            "current_chan": msg.thread.chan,
                            "current_thread": msg.thread,
                            "messages": Messages,
                            "board_view": False
                        }

                        post_html = render_template("elements/board/post.html",
                                                    board=board,
                                                    msg=msg,
                                                    post_id=msg.post_id,
                                                    table_messages=Messages,
                                                    upload_sites=UploadSites)
                        msg.post_html = post_html
                        msg.save()

                    if msg.regenerate_post_html:
                        msg.regenerate_post_html = False
                        msg.save()
            except Exception as err:
                logger.error("Error generating post html: {}".format(err))
            finally:
                lf.lock_release(file_lock)

    if board_view and msg.post_html_board_view:
        post_html = msg.post_html_board_view
    elif not board_view and msg.post_html:
        post_html = msg.post_html
    else:
        post_html = ""

    return post_html
