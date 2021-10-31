import logging
import time
import uuid

from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

from bitchan_flask import captcha
from database.models import SessionInfo
from utils.routes import allowed_access

logger = logging.getLogger('bitchan.routes_verify')

blueprint = Blueprint('routes_verify',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.route('/wait')
def verify_wait():
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())

    page_id = str(uuid.uuid4())
    session[page_id] = time.time()

    return render_template("pages/verify_wait.html",
                           page_id=page_id)


@blueprint.route('/verify/<page_id>', methods=('GET', 'POST'))
def verify_test(page_id):
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    if page_id not in session or "session_id" not in session:
        return '<div style="text-align:center;padding-top:2em">Invalid ID. <a href="/">Reverify</a></div>'

    ts = session[page_id]
    if time.time() < ts + 5:
        session.pop(page_id)
        return '<div style="text-align:center;padding-top:2em">Invalid Wait. <a href="/">Reverify</a></div>'

    if request.method == 'POST':
        page_id = request.form.get('page_id', None)
        if captcha.validate(page_id=page_id):
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
            return redirect(url_for('routes_main.index'))
        else:
            if "verify_captcha_count" not in session:
                session["verify_captcha_count"] = 1
            elif session["verify_captcha_count"] > 4:
                session["verify_captcha_count"] = 0
                session.pop(page_id)
                return redirect(url_for('routes_verify.verify_wait'))
            else:
                session["verify_captcha_count"] += 1

    return render_template("pages/verify_test.html",
                           page_id=page_id)
