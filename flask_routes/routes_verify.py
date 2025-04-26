import base64
import logging
import time
import uuid

from flask import abort
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

from bitchan_flask import captcha
from database.models import GlobalSettings
from database.models import SessionInfo
from flask_routes.utils import count_views
from flask_routes.utils import watch_ban
from utils.routes import allowed_access

logger = logging.getLogger('bitchan.routes_verify')

blueprint = Blueprint('routes_verify',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.route('/wait/<full_path_b64>')
@watch_ban
@count_views
def verify_wait(full_path_b64):
    if "banned" in session:
        if session["banned"] == 1:
            return "err"
        elif session["banned"] == 2:
            abort(404)

    allowed, allow_msg = allowed_access("can_verify")
    if not allowed:
        return allow_msg

    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())

    page_id = str(uuid.uuid4())
    session[page_id] = time.time()

    wait_sec = 5
    if "did_not_wait" in session:
        wait_sec += session["did_not_wait"] * 5

    return render_template("pages/verify_wait.html",
                           page_id=page_id,
                           full_path_b64=full_path_b64,
                           settings=GlobalSettings.query.first(),
                           wait_sec=wait_sec)


@blueprint.route('/verify/<page_id>/<full_path_b64>', methods=('GET', 'POST'))
@watch_ban
@count_views
def verify_test(page_id, full_path_b64):
    if "banned" in session:
        if session["banned"] == 1:
            return "err"
        elif session["banned"] == 2:
            abort(404)

    allowed, allow_msg = allowed_access("can_verify")
    if not allowed:
        return allow_msg

    if page_id not in session or "session_id" not in session:
        return '<div style="text-align:center;padding-top:2em">Invalid ID. <a href="/">Reverify</a></div>'

    ts = session[page_id]
    wait_sec = 5
    if "did_not_wait" in session:
        wait_sec += session["did_not_wait"] * 5
    if time.time() < ts + wait_sec:
        session.pop(page_id)
        if "did_not_wait" not in session:
            session["did_not_wait"] = 1
        else:
            session["did_not_wait"] += 1
        return '<div style="text-align:center;padding-top:2em">Invalid Wait. <a href="/">Reverify</a></div>'

    if request.method == 'POST':
        captcha_id = request.form.get('page_id', None)
        if captcha.validate(captcha_id):
            session_test = SessionInfo.query.filter(
                SessionInfo.session_id == session["session_id"]).first()
            if not session_test:
                session_info = SessionInfo()
                session_info.session_id = session["session_id"]
                session_info.request_rate_ts = time.time()
                session_info.request_rate_amt = 0
                session_info.verified = True
                session_info.save()
            else:
                session_test.session_id = session["session_id"]
                session_test.request_rate_ts = time.time()
                session_test.request_rate_amt = 0
                session_test.verified = True
                session_test.save()
            session["verified"] = True
            session.pop(page_id)
            logger.info("Post request session: {}".format(session))

            return redirect(url_for('routes_verify.verify_success',
                                    full_path_b64=full_path_b64))
        else:
            if "verify_captcha_count" not in session:
                session["verify_captcha_count"] = 1
            elif session["verify_captcha_count"] > 4:
                session["verify_captcha_count"] = 0
                session.pop(page_id)
                return redirect(url_for('routes_verify.verify_wait', full_path_b64=full_path_b64))
            else:
                session["verify_captcha_count"] += 1

    return render_template("pages/verify_test.html",
                           page_id=page_id,
                           settings=GlobalSettings.query.first(),
                           full_path=full_path_b64)


@blueprint.route('/success/<full_path_b64>', methods=('GET', 'POST'))
@watch_ban
@count_views
def verify_success(full_path_b64):
    if "banned" in session:
        if session["banned"] == 1:
            return "err"
        elif session["banned"] == 2:
            abort(404)

    if full_path_b64 == "0":
        return redirect(url_for('routes_main.index'))
    else:
        try:
            full_path_url = base64.b64decode(full_path_b64.encode()).decode()
            return redirect(full_path_url)
        except:
            return redirect(url_for('routes_main.index'))
