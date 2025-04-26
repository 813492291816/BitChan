import json
import logging
import time
import uuid
from collections import OrderedDict
from functools import wraps

from flask import session
from sqlalchemy import and_

from bitchan_client import DaemonCom
from database.models import GlobalSettings
from database.models import Messages
from database.models import SessionInfo
from utils.routes import has_permission
from utils.routes import is_logged_in

logger = logging.getLogger('bitchan.decorators')

daemon_com = DaemonCom()


def get_posts_from_thread(thread, settings, pow_filter_value, last, steg):
    """Return order, OP, and sorted replies for a particular thread"""
    try:
        thread_rules = json.loads(thread.rules)
    except:
        thread_rules = {}

    message_op = Messages.query.filter(and_(
        Messages.thread_id == thread.id,
        Messages.message_sha256_hash == thread.op_sha256_hash))

    message_replies = Messages.query.filter(and_(
        Messages.thread_id == thread.id,
        Messages.message_sha256_hash != thread.op_sha256_hash))

    if steg:
        message_op = message_op.filter(Messages.message_steg != "{}")
        message_replies = message_replies.filter(Messages.message_steg != "{}")

    message_op = message_op.first()

    message_reply_all_count = message_replies.count()

    # Sort
    if "sort_replies_by_pow" in thread_rules:
        post_order = Messages.pow_filter_value.desc()
        message_replies = message_replies.order_by(post_order)  # Needs to be sorted before filtering/limiting
    elif settings.post_timestamp == 'received':
        post_order = Messages.timestamp_received.asc()
    elif settings.post_timestamp == 'sent':
        post_order = Messages.timestamp_sent.asc()

    # Filter POW
    if pow_filter_value:
        message_replies = message_replies.filter(Messages.pow_filter_value >= pow_filter_value)

    # Limit
    if last and message_replies.count() > last:
        if "sort_replies_by_pow" in thread_rules:
            message_start = message_replies.limit(last).all()
            message_replies = message_replies.filter(
                Messages.pow_filter_value >= message_start[-1].pow_filter_value)
        elif settings.post_timestamp == 'received':
            message_replies_test = message_replies.order_by(Messages.timestamp_received.desc())
            message_start = message_replies_test.limit(last).all()
            message_replies = message_replies.filter(
                Messages.timestamp_received >= message_start[-1].timestamp_received)
        elif settings.post_timestamp == 'sent':
            message_replies_test = message_replies.order_by(Messages.timestamp_sent.desc())
            message_start = message_replies_test.limit(last).all()
            message_replies = message_replies.filter(
                Messages.timestamp_sent >= message_start[-1].timestamp_sent)

    # Needs to be sorted after filtering/limiting
    if settings.post_timestamp == 'received' or settings.post_timestamp == 'sent':
        message_replies = message_replies.order_by(post_order)

    return post_order, message_op, message_replies, message_reply_all_count


def count_views(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        dict_keys = OrderedDict({
            "boards": [],
            "lists": [],
            "threads": [],
            "general": [],
            "new_posts": [],
            "rss_thread": [],
            "rss_board": []
        })

        if f.__name__ == "new_posts" and kwargs.get("thread_hash_short"):
            dict_keys["new_posts"].append(kwargs["thread_hash_short"])
        elif f.__name__ == "list_chans" and kwargs.get("current_chan"):
            dict_keys["lists"].append((kwargs["current_chan"]))
        elif f.__name__ == "board" and kwargs.get("current_chan"):
            dict_keys["boards"].append((kwargs["current_chan"]))
        elif (f.__name__ in ["thread", "thread_steg"] and
                kwargs.get("current_chan") and kwargs.get("thread_id")):
            dict_keys["boards"].append((kwargs["current_chan"]))
            dict_keys["threads"].append(kwargs["thread_id"])
        elif f.__name__ == "rss" and kwargs.get("board_address") and kwargs.get("thread_id") != "0":
            dict_keys["rss_thread"].append((kwargs["thread_id"]))
        elif f.__name__ == "rss" and kwargs.get("board_address") and kwargs.get("thread_id") == "0":
            dict_keys["rss_board"].append((kwargs["board_address"]))
        else:
            dict_keys["general"].append(f.__name__)

        for each_key, data in dict_keys.items():
            for each_data in data:
                try:
                    daemon_com.set_view_counter(
                        each_key, each_data, increment=True)
                except:
                    pass

        return f(*args, **kwargs)
    return decorated_function


def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if is_logged_in() and has_permission("is_global_admin"):  # Bypass check if admin
            return f(*args, **kwargs)

        settings = GlobalSettings.query.first()
        if settings.enable_page_rate_limit:
            if "session_id" not in session:
                if settings.enable_verification:
                    session["verified"] = False
                    return "Invalid ID"
                else:
                    session["session_id"] = str(uuid.uuid4())

            session_info = SessionInfo.query.filter(
                SessionInfo.session_id == session["session_id"]).first()
            if not session_info:
                logger.info("new session created: {}".format(session["session_id"]))
                session_info = SessionInfo()
                session_info.session_id = session["session_id"]
                session_info.request_rate_ts = time.time()
                session_info.request_rate_amt = 1
                session_info.verified = True
                session_info.save()
            else:
                logger.info("Request info: {}, {}, {}".format(
                    session_info.request_rate_ts,
                    time.time() - session_info.request_rate_ts,
                    session_info.request_rate_amt))

                if time.time() - session_info.request_rate_ts > settings.rate_limit_period_seconds:
                    logger.info("Request more than 60 sec, resetting info")
                    session_info.request_rate_ts = time.time()
                    session_info.request_rate_amt = 1
                    session_info.save()
                elif session_info.request_rate_amt > settings.max_requests_per_period:
                    session_info.request_rate_ts = time.time()
                    session_info.request_rate_amt = 1
                    session_info.verified = False
                    session_info.save()
                    logger.info("Too many requests: unverifying")
                    session["verified"] = False
                    return "Too Many Requests"
                else:
                    logger.info("adding 1 to request total")
                    session_info.request_rate_amt += 1
                    session_info.save()

                # logger.info("Session: {}".format(session))

        return f(*args, **kwargs)
    return decorated_function


def watch_ban(f):
    """Monitor how many requests to the wait page, hand out bans for abusers"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "session_id" not in session:
            session["session_id"] = str(uuid.uuid4())
        if "banned" not in session:
            session["banned"] = 0
        if "verify_wait" not in session:
            session["verify_wait"] = []
        if "verify_test" not in session:
            session["verify_test"] = []

        # Remove counts older than 120 seconds
        for each_time in list(session["verify_wait"]):
            if each_time < time.time() - 120:
                session["verify_wait"].remove(each_time)
        for each_time in list(session["verify_test"]):
            if each_time < time.time() - 120:
                session["verify_test"].remove(each_time)

        if f.__name__ in ["verify_wait", "verify_test"]:
            session[f.__name__].append(time.time())

        if len(session["verify_wait"]) <= 7 and len(session["verify_test"]) <= 10:
            logger.info("{}: watch_ban count: wait: {}, test: {}".format(
                session["session_id"],
                len(session["verify_wait"]),
                len(session["verify_test"])))

        if len(session["verify_wait"]) >= 7 or len(session["verify_test"]) >= 10:
            # if >= 7 requests in past 120 seconds, ban 2
            if session["banned"] != 2:
                logger.info("{} Ban level 2".format(session["session_id"]))
                session["banned"] = 2
        elif len(session["verify_wait"]) >= 5 or len(session["verify_test"]) >= 8:
            # if >= 5 requests in past 120 seconds, ban 1
            if session["banned"] != 1:
                logger.info("{} Ban level 1".format(session["session_id"]))
                session["banned"] = 1
        else:
            # if < 5 requests in past 120 seconds, clear ban
            if session["banned"] != 0:
                logger.info("{} Ban level 0".format(session["session_id"]))
                session["banned"] = 0

        return f(*args, **kwargs)
    return decorated_function


def is_verified():
    if not GlobalSettings.query.first().enable_verification:
        # Verification checking not enabled
        return True

    if "session_id" not in session:
        # Unknown session, not verified
        # logger.info(f"Unknown session, not verified: {session}")
        return False

    session_info = SessionInfo.query.filter(
        SessionInfo.session_id == session["session_id"]).first()
    if (not session_info or not session_info.verified or
            ("verified" not in session or not session["verified"])):
        # not verified
        # logger.info(f"not verified: {session}, {session_info}")
        return False

    # verified
    return True
