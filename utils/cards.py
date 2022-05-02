import datetime
import logging
import re
import time

from flask import render_template
from sqlalchemy import and_
from sqlalchemy import func

import config
from config import DATABASE_BITCHAN
from database.models import Messages
from database.models import PostCards
from database.models import Threads
from database.utils import session_scope
from utils.generate_card import get_card_link_html
from utils.html_truncate import truncate
from utils.shared import post_has_image

DB_PATH = 'sqlite:///' + DATABASE_BITCHAN

logger = logging.getLogger('bitchan.cards')


def clean_html(raw_html):
    try:
        cleanr = re.compile('<.*?>')
        clean_text = re.sub(cleanr, '', raw_html)
        return clean_text
    except:
        return ""


def generate_card(thread_id, force_generate=False):
    with session_scope(DB_PATH) as new_session:
        card_test = new_session.query(PostCards).filter(
            PostCards.thread_id == thread_id).first()
        if card_test and not card_test.regenerate and not force_generate:
            return card_test.card_html

        ts_month = time.time() - (60 * 60 * 24 * 30)
        each_thread = new_session.query(Threads).filter(
            Threads.thread_hash == thread_id).first()
        thread_info = {
            "op_timestamp": None,
            "messages": [],
            "total_posts": new_session.query(Messages).filter(
                Messages.thread_id == each_thread.id).count(),
            "ppm": new_session.query(Messages).filter(and_(
                Messages.thread_id == each_thread.id,
                Messages.timestamp_sent > ts_month)).count(),
            "attachments": 0,
            "attach_post_ratio": 0
        }

        # Total file amounts
        total_attach = 0
        amount_files = new_session.query(Messages).with_entities(
            func.sum(Messages.file_amount).label("attSum")).filter(
            Messages.thread_id == each_thread.id).first()
        if amount_files.attSum:
            total_attach = amount_files.attSum
        thread_info["attachments"] = total_attach

        # Attachments:Post Ratio
        ratio = 0
        if amount_files.attSum:
            total_attach = amount_files.attSum
            ratio = total_attach / thread_info["total_posts"]
            ratio = "{:.1f}".format(ratio)
        thread_info["attach_post_ratio"] = ratio

        # OP
        op_message = new_session.query(Messages).filter(and_(
            Messages.thread_id == each_thread.id,
            Messages.is_op.is_(True))).first()
        thread_info["messages"].append(op_message)
        if op_message:
            op_ts = datetime.datetime.fromtimestamp(
                op_message.timestamp_sent).strftime('%Y-%m-%d %H:%M')
            thread_info["op_timestamp"] = op_ts

        # Replies
        messages = new_session.query(Messages).filter(
            and_(
                Messages.thread_id == each_thread.id,
                Messages.is_op.is_(False))).order_by(
            Messages.timestamp_sent.desc()).limit(3)
        if messages.count():
            messages_ordered = messages.from_self().order_by(
                Messages.timestamp_sent.asc()).all()
            for each_msg in messages_ordered:
                thread_info["messages"].append(each_msg)

        from bitchan_flask import app
        with app.app_context():
            rendered_html = render_template("pages/card.html",
                                            clean_html=clean_html,
                                            config=config,
                                            get_card_link_html=get_card_link_html,
                                            post_has_image=post_has_image,
                                            thread_info=thread_info,
                                            truncate=truncate)

        if card_test:
            card_test.card_html = rendered_html
            card_test.regenerate = False
            new_session.commit()
            return card_test.card_html
        else:
            card_new = PostCards()
            card_new.thread_id = thread_id
            card_new.card_html = rendered_html
            new_session.add(card_new)
            return card_new.card_html
