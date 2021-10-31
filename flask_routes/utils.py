import logging
import time
import uuid
from functools import wraps

from flask import session

from database.models import GlobalSettings
from database.models import SessionInfo

logger = logging.getLogger('bitchan.decorators')


def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
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

                logger.info("Session: {}".format(session))

        return f(*args, **kwargs)
    return decorated_function


def is_verified():
    if not GlobalSettings.query.first().enable_verification:
        # Verification checking not enabled
        return True

    if "session_id" not in session:
        # Unknown session, not verified
        return False

    session_info = SessionInfo.query.filter(
        SessionInfo.session_id == session["session_id"]).first()
    if ("session_id" not in session or not session_info or not session_info.verified or
            ("verified" not in session or not session["verified"])):
        # not verified
        return False
    # verified
    return True
