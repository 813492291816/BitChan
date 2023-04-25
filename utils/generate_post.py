import logging

from flask import render_template

import config
from bitchan_client import DaemonCom
from database.models import Messages
from database.models import UploadSites

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

daemon_com = DaemonCom()
logger = logging.getLogger("bitchan.generate_post")


def generate_post_html(message_id, board_view=False):
    msg = Messages.query.filter(Messages.message_id == message_id).first()
    if not msg:
        return "Could not find post"

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

    if board_view:
        post_html = msg.post_html_board_view
    else:
        post_html = msg.post_html

    return post_html
