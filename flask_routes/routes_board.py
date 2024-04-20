import base64
import html
import json
import logging
import os
import random
import time
import uuid
from io import BytesIO
from urllib.parse import unquote

from flask import current_app
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import send_file
from flask import session
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_
from sqlalchemy.sql import func

import config
from bitchan_client import DaemonCom
from bitchan_flask import captcha
from database.models import BanedHashes
from database.models import Chan
from database.models import Command
from database.models import Flags
from database.models import Games
from database.models import GlobalSettings
from database.models import Messages
from database.models import Threads
from database.models import UploadSites
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from flask_routes.utils import rate_limit
from forms import forms_board
from utils.files import LF
from utils.generate_popup import attachment_info
from utils.gpg import find_gpg
from utils.gpg import get_all_key_information
from utils.gpg import gpg_decrypt
from utils.identicon import generate_icon
from utils.message_post import generate_post_form_populate
from utils.message_post import post_message
from utils.posts import delete_post
from utils.replacements import format_body
from utils.replacements import process_replacements
from utils.routes import allowed_access
from utils.routes import get_chan_passphrase
from utils.routes import get_theme
from utils.routes import get_threads_from_page
from utils.routes import page_dict
from utils.shared import can_address_create_thread

logger = logging.getLogger('bitchan.routes_board')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_board',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.before_request
def before_view():
    if not is_verified():
        # If making a post, preserve the form data during reverification
        if request.method == "POST" and request.form:
            try:
                session['form_populate'] = generate_post_form_populate(forms_board.Post())
            except:
                pass

        full_path_b64 = "0"
        if request.method == "GET":
            if request.url:
                full_path_b64 = base64.urlsafe_b64encode(
                    request.url.encode()).decode()
            elif request.referrer:
                full_path_b64 = base64.urlsafe_b64encode(
                    request.referrer.encode()).decode()
        elif request.method == "POST":
            if request.referrer:
                full_path_b64 = base64.urlsafe_b64encode(
                    request.referrer.encode()).decode()
        return redirect(url_for('routes_verify.verify_wait',
                                full_path_b64=full_path_b64))


@blueprint.route('/boards')
@count_views
@rate_limit
def boards():
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    status_msg = {"status_message": []}

    return render_template("pages/boards.html",
                           status_msg=status_msg)


@blueprint.route('/board/<current_chan>/<current_page>', methods=('GET', 'POST'))
@count_views
@rate_limit
def board(current_chan, current_page):
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    chan = Chan.query.filter(Chan.address == current_chan).first()
    global_admin, _ = allowed_access("is_global_admin")

    if not chan or (not global_admin and chan.restricted):
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    form_post = forms_board.Post()
    form_set = forms_board.SetChan()
    post_order_desc = Threads.timestamp_sent.desc()
    settings = GlobalSettings.query.first()

    if settings.post_timestamp == 'received':
        post_order_desc = Threads.timestamp_received.desc()

    board = {
        "current_page": int(current_page),
        "current_chan": chan,
        "current_thread": None,
        "messages": Messages,
        "threads": Threads.query
            .filter(Threads.chan_id == chan.id)
            .order_by(post_order_desc)
    }

    form_populate = session.get('form_populate', {})
    status_msg = session.get('status_msg', {"status_message": []})

    (public_keys,
     private_keys,
     private_key_ids,
     public_key_ids,
     exported_public_keys) = get_all_key_information()

    list_gpg_from = []
    for each_key in private_keys:
        if len(each_key['uids'][0]) > 40:
            uid = f"{each_key['uids'][0][0:40]}..."
        else:
            uid = each_key['uids'][0]
        name = f"{uid} ({each_key['fingerprint'][0:6]}...{each_key['fingerprint'][-6:]})"
        list_gpg_from.append({"value": each_key["fingerprint"], "name": name})

    list_gpg_to = []
    for each_key in public_keys:
        if len(each_key['uids'][0]) > 40:
            uid = f"{each_key['uids'][0][0:40]}..."
        else:
            uid = each_key['uids'][0]
        name = f"{uid} ({each_key['fingerprint'][0:6]}...{each_key['fingerprint'][-6:]})"
        list_gpg_to.append({"value": each_key["fingerprint"], "name": name})

    if request.method == 'GET':
        if 'form_populate' in session:
            session.pop('form_populate')
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_set.set_pgp_passphrase_msg.data:
            global_admin, allow_msg = allowed_access("is_global_admin")
            if not global_admin:
                return allow_msg

            if not form_set.pgp_passphrase_msg.data:
                status_msg['status_message'].append("Message PGP passphrase required")
            elif len(form_set.pgp_passphrase_msg.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append("Message PGP passphrase longer than {}: {}".format(
                    config.PGP_PASSPHRASE_LENGTH, len(form_set.pgp_passphrase_msg.data)))
            else:
                chan.pgp_passphrase_msg = form_set.pgp_passphrase_msg.data
                chan.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Changed Message PGP Passphrase.")

        if form_set.set_pgp_passphrase_attach.data:
            global_admin, allow_msg = allowed_access("is_global_admin")
            if not global_admin:
                return allow_msg

            if not form_set.pgp_passphrase_attach.data:
                status_msg['status_message'].append("Attachment PGP passphrase required")
            elif len(form_set.pgp_passphrase_attach.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append("Attachment PGP passphrase longer than {}: {}".format(
                    config.PGP_PASSPHRASE_LENGTH, len(form_set.pgp_passphrase_attach.data)))
            else:
                chan.pgp_passphrase_attach = form_set.pgp_passphrase_attach.data
                chan.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Changed Attachment PGP Passphrase.")

        elif form_set.set_pgp_passphrase_steg.data:
            global_admin, allow_msg = allowed_access("is_global_admin")
            if not global_admin:
                return allow_msg

            if not form_set.pgp_passphrase_steg.data:
                status_msg['status_message'].append("Steg PGP passphrase required")
            elif len(form_set.pgp_passphrase_steg.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append("Steg PGP passphrase longer than {}: {}".format(
                    config.PGP_PASSPHRASE_LENGTH, len(form_set.pgp_passphrase_steg.data)))
            else:
                chan.pgp_passphrase_steg = form_set.pgp_passphrase_steg.data
                chan.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Changed Steg PGP Passphrase.")

        elif form_post.start_download.data:
            can_download, allow_msg = allowed_access("can_download")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not can_download and not board_list_admin:
                return allow_msg

            if settings.maintenance_mode:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append(
                    "Cannot initiate attachment download while Maintenance Mode is enabled.")
            else:
                daemon_com.set_start_download(form_post.message_id.data)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "File download initialized in the background. Give it time to download.")

        elif form_post.submit_post.data:
            invalid_post = False
            if not form_post.validate():
                for field, errors in form_post.errors.items():
                    if field == "csrf_token":
                        invalid_post = True
                    for error in errors:
                        logger.error("Error in the {} field - {}".format(
                            getattr(form_post, field).label.text, error))

            if invalid_post:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid Token")

            if not form_post.page_id.data:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid ID")
            elif settings.enable_captcha and not captcha.validate(form_post.page_id.data):
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid Captcha")

            # Check if allowed to post
            can_post, allow_msg = allowed_access("can_post")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not can_post and not board_list_admin:
                return allow_msg

            # Check if allowed to create new thread
            if form_post.is_op.data == "yes":
                if not can_address_create_thread(form_post.from_address.data, current_chan):
                    status_msg['status_title'] = "Error"
                    status_msg['status_message'].append(
                        f"Address {form_post.from_address.data} is not permitted to create new threads on this board")

            if form_post.default_from_address.data:
                chan.default_from_address = form_post.from_address.data
            else:
                chan.default_from_address = None
            chan.save()

            status_msg, result, form_populate = post_message(
                form_post, status_msg)
            status_msg["no_escape"] = True

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_board.board",
                                current_chan=current_chan,
                                current_page=current_page))

    try:
        from_list = daemon_com.get_from_list(current_chan)
    except:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    passphrase_base64, passphrase_base64_with_pgp = get_chan_passphrase(current_chan)

    return render_template("pages/board.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           from_list=from_list,
                           get_threads_from_page=get_threads_from_page,
                           list_gpg_from=list_gpg_from,
                           list_gpg_to=list_gpg_to,
                           page_id=str(uuid.uuid4()),
                           passphrase_base64=passphrase_base64,
                           passphrase_base64_with_pgp=passphrase_base64_with_pgp,
                           status_msg=status_msg,
                           upload_sites=UploadSites)


@blueprint.route('/csrf/<current_chan>')
@count_views
@rate_limit
def csrf(current_chan):
    can_post, allow_msg = allowed_access("can_post")
    board_list_admin, allow_msg = allowed_access(
        "is_board_list_admin", board_address=current_chan)
    if not can_post and not board_list_admin:
        return allow_msg

    form_post = forms_board.Post()
    return form_post.csrf_token._value()


@blueprint.route('/thread/<current_chan>/<thread_id>', methods=('GET', 'POST'))
@count_views
@rate_limit
def thread(current_chan, thread_id):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    anchor = None

    try:
        last = int(request.args.get('last'))
        if last < 0:
            last = None
    except:
        last = None

    try:
        ref = int(request.args.get('ref'))  # reply post is made via ajax, will not refresh page
    except:
        ref = None

    form_post = forms_board.Post()

    settings = GlobalSettings.query.first()
    chan = Chan.query.filter(Chan.address == current_chan).first()

    (public_keys,
     private_keys,
     private_key_ids,
     public_key_ids,
     exported_public_keys) = get_all_key_information()

    list_gpg_from = []
    for each_key in private_keys:
        list_gpg_from.append({"value": each_key["fingerprint"], "name": each_key["fingerprint"]})

    list_gpg_to = []
    for each_key in public_keys:
        list_gpg_to.append({"value": each_key["fingerprint"], "name": each_key["fingerprint"]})

    game_hash = ""
    game = Games.query.filter(and_(
        Games.game_over.is_(False),
        Games.thread_hash == thread_id)).first()
    if game:
        game_hash = game.game_hash

    if len(thread_id) == 12:
        thread = Threads.query.filter(Threads.thread_hash_short == thread_id).first()
    else:
        thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    if not chan:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    if not thread:
        return render_template("pages/404-thread.html",
                               board_address=current_chan,
                               thread_id=thread_id)

    board = {
        "current_chan": chan,
        "current_thread": thread,
        "messages": Messages
    }

    form_populate = session.get('form_populate', {})
    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'form_populate' in session:
            session.pop('form_populate')
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_post.start_download.data:
            can_download, allow_msg = allowed_access("can_download")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not can_download and not board_list_admin:
                return allow_msg

            if settings.maintenance_mode:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append(
                    "Cannot initiate attachment download while Maintenance Mode is enabled.")
            else:
                daemon_com.set_start_download(form_post.message_id.data)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "File download initialized in the background. Give it time to download.")

        if form_post.preview_post.data:
            anchor = "popup_reply"
            if 'status_title' not in status_msg:
                status_msg['status_title'] = "Preview"
                status_msg['status_message'].append("Post Preview generated.")
            form_populate = generate_post_form_populate(form_post)
            form_populate["preview"] = process_replacements(
                html.escape(form_populate["comment"].encode('utf-8').strip().decode()),
                str(random.randint(1, 10**10)),
                "0",
                preview=True)

            form_populate["preview"], gpg_texts = find_gpg(form_populate["preview"])
            gpg_texts = gpg_decrypt(gpg_texts)

            if thread:
                form_populate["preview"] = format_body(
                    "preview", form_populate["preview"], False, True, preview=True, this_thread_hash=thread.thread_hash, gpg_texts=gpg_texts)
            else:
                form_populate["preview"] = format_body(
                    "preview", form_populate["preview"], False, True, preview=True, gpg_texts=gpg_texts)

            if ref:  # send text response status to popup reply window
                status_msg["preview"] = form_populate["preview"]
                return status_msg

        elif form_post.submit_post.data or ref:
            invalid_post = False
            if not form_post.validate():
                for field, errors in form_post.errors.items():
                    if field == "csrf_token":
                        invalid_post = True
                    for error in errors:
                        logger.error("Error in the {} field - {}".format(
                            getattr(form_post, field).label.text, error))

            if invalid_post:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid")

            if not form_post.page_id.data:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid ID")
            elif settings.enable_captcha and not captcha.validate(form_post.page_id.data):
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid Captcha")

            can_post, allow_msg = allowed_access("can_post")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not can_post and not board_list_admin:
                return allow_msg

            if form_post.default_from_address.data:
                thread.default_from_address = form_post.from_address.data
            else:
                thread.default_from_address = None
            thread.save()

            status_msg, result, form_populate = post_message(
                form_post, status_msg)
            status_msg["no_escape"] = True

            if ref:  # send text response status to popup reply window
                return status_msg

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        if last:
            return redirect(url_for("routes_board.thread",
                                    current_chan=current_chan,
                                    last=last,
                                    thread_id=thread_id,
                                    _anchor=anchor))
        else:
            return redirect(url_for("routes_board.thread",
                                    current_chan=current_chan,
                                    thread_id=thread_id,
                                    _anchor=anchor))

    try:
        from_list = daemon_com.get_from_list(current_chan)
    except:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    return render_template("pages/thread.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           from_list=from_list,
                           game_hash=game_hash,
                           last=last,
                           list_gpg_from=list_gpg_from,
                           list_gpg_to=list_gpg_to,
                           logger=logger,
                           page_id=str(uuid.uuid4()),
                           status_msg=status_msg,
                           time=time,
                           upload_sites=UploadSites)


@blueprint.route('/thread_steg/<current_chan>/<thread_id>', methods=('GET', 'POST'))
@count_views
@rate_limit
def thread_steg(current_chan, thread_id):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    form_post = forms_board.Post()

    settings = GlobalSettings.query.first()
    chan = Chan.query.filter(Chan.address == current_chan).first()
    
    if len(thread_id) == 12:
        thread = Threads.query.filter(Threads.thread_hash_short == thread_id).first()
    else:
        thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    if not chan:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    if not thread:
        return render_template("pages/404-thread.html",
                               board_address=current_chan,
                               thread_id=thread_id)

    board = {
        "current_chan": chan,
        "current_thread": thread,
        "messages": Messages
    }
    form_populate = session.get('form_populate', {})
    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'form_populate' in session:
            session.pop('form_populate')
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_post.start_download.data:
            can_download, allow_msg = allowed_access("can_download")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not can_download and not board_list_admin:
                return allow_msg

            if settings.maintenance_mode:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append(
                    "Cannot initiate attachment download while Maintenance Mode is enabled.")
            else:
                daemon_com.set_start_download(form_post.message_id.data)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "File download initialized in the background. Give it time to download.")

        elif form_post.submit.data:
            invalid_post = False
            if not form_post.validate():
                for field, errors in form_post.errors.items():
                    if field == "csrf_token":
                        invalid_post = True
                    for error in errors:
                        logger.error("Error in the {} field - {}".format(
                            getattr(form_post, field).label.text, error))

            if invalid_post:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid")

            if not form_post.page_id.data:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid ID")
            elif settings.enable_captcha and not captcha.validate(form_post.page_id.data):
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Invalid Captcha")

            can_post, allow_msg = allowed_access("can_post")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not can_post and not board_list_admin:
                return allow_msg

            if form_post.default_from_address.data:
                thread.default_from_address = form_post.from_address.data
            else:
                thread.default_from_address = None
            thread.save()

            status_msg, result, form_populate = post_message(
                form_post, status_msg)
            status_msg["no_escape"] = True

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        return redirect(url_for("routes_board.thread_steg",
                                current_chan=current_chan,
                                thread_id=thread_id))

    try:
        from_list = daemon_com.get_from_list(current_chan)
    except:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    return render_template("pages/thread_steg.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           from_list=from_list,
                           page_id=str(uuid.uuid4()),
                           status_msg=status_msg,
                           upload_sites=UploadSites)


@blueprint.route('/random_post')
@count_views
@rate_limit
def random_post():
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    global_admin, _ = allowed_access("is_global_admin")

    timer = time.time()
    while time.time() - timer < 5:  # Search for a post for max 5 seconds
        try:
            if global_admin:
                message = Messages.query.join(Threads).filter(and_(
                    Threads.hide.is_(False),
                    Messages.hide.is_(False))).order_by(func.random()).first()
            else:
                message = Messages.query.join(Threads).join(Chan).filter(and_(
                    Chan.unlisted.is_(False),
                    Chan.restricted.is_(False),
                    Threads.hide.is_(False),
                    Messages.hide.is_(False))).order_by(func.random()).first()
            if message and message.thread and message.thread.chan:
                return redirect(f"/thread/{message.thread.chan.address}/{message.thread.thread_hash_short}#{message.post_id}")
        except:
            logger.exception("Finding random post")
    return "Error"


@blueprint.route('/icon/<address>')
def icon_image(address):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    path_icon = os.path.join(config.FILE_DIRECTORY, "{}_icon.png".format(address))
    if not os.path.exists(path_icon):
        generate_icon(address)
    if os.path.abspath(path_icon).startswith(config.FILE_DIRECTORY):
        return send_file(path_icon, mimetype='image/png', max_age=1440)


@blueprint.route('/custom_flag_by_flag_id/<flag_id>')
def custom_flag_by_flag_id(flag_id):
    """Returns a flag image based on the flag ID"""
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    flag = Flags.query.filter(Flags.id == int(flag_id)).first()

    if flag:
        return send_file(
            BytesIO(base64.b64decode(flag.flag_base64)),
            mimetype='image/{}'.format(flag.flag_extension),
            max_age=1440)


@blueprint.route('/custom_flag_by_post_id/<post_id>')
def custom_flag_by_post_id(post_id):
    """Returns a flag image based on the post ID"""
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    message = Messages.query.filter(Messages.message_id == post_id).first()

    if message:
        return send_file(
            BytesIO(base64.b64decode(message.nation_base64)),
            mimetype='image/jpg',
            max_age=1440)


@blueprint.route('/banner/<chan_address>')
def banner_image(chan_address):
    """Returns a banner image based on whether a custom banner is available"""
    file_path = None
    theme = get_theme()

    can_view, allow_msg = allowed_access("can_view")
    if not can_view or chan_address in ['light', 'dark']:
        if chan_address == 'light':
            file_path = f"{config.BITCHAN_DIR}/static/banner_light.png"
        elif chan_address == 'dark':
            file_path = f"{config.BITCHAN_DIR}/static/banner_dark.png"
        elif theme in config.THEMES_LIGHT:
            file_path = f"{config.BITCHAN_DIR}/static/banner_light.png"
        elif theme in config.THEMES_DARK:
            file_path = f"{config.BITCHAN_DIR}/static/banner_dark.png"
        if file_path:
            return send_file(file_path, mimetype='image/png', max_age=1440)
        else:
            return allow_msg

    if chan_address != "0":
        chan = Chan.query.filter(Chan.address == chan_address).first()
        if chan:
            admin_cmd = Command.query.filter(and_(
                Command.chan_address == chan.address,
                Command.action == "set",
                Command.action_type == "options")).first()
            if admin_cmd:
                try:
                    options = json.loads(admin_cmd.options)
                except:
                    options = {}
                if "banner_base64" in options and options["banner_base64"]:
                    return send_file(
                        BytesIO(base64.b64decode(options["banner_base64"])),
                        mimetype='image/png',
                        max_age=1440)

    if theme in config.THEMES_DARK:
        file_path = f"{config.BITCHAN_DIR}/static/banner_dark.png"
    elif theme in config.THEMES_LIGHT:
        file_path = f"{config.BITCHAN_DIR}/static/banner_light.png"

    if file_path:
        return send_file(file_path, mimetype='image/png', max_age=1440)

    return "Error determining the banner image to use"


def get_image_attach(message_id, file_path, file_filename, extension, mime_type="image/jpg"):
    post = Messages.query.filter(Messages.message_id == message_id).first()
    if extension in config.FILE_EXTENSIONS_IMAGE:
        mime_type = "image/jpg"
    elif extension in config.FILE_EXTENSIONS_VIDEO:
        mime_type = "video/mp4"

    if file_path and file_filename:
        file_path_full = os.path.join(file_path, file_filename)
        if os.path.exists(file_path_full):
            if (extension in config.FILE_EXTENSIONS_IMAGE and
                    os.path.abspath(file_path_full).startswith(file_path)):
                return send_file(file_path_full, mimetype=mime_type)
        elif "_thumb" not in file_path:
            logger.error(f"Attach File {file_path_full} doesn't exist")
            message = Messages.query.filter(Messages.message_id == message_id).first()
            message.file_download_successful = False
            message.file_sha256_hashes_match = False
            message.save()
        return "File not found"
    elif post.file_decoded:
        return send_file(BytesIO(post.file_decoded), mimetype=mime_type)


@blueprint.route('/files/<file_type>/<message_id>/<filename>')
def files(message_id, file_type, filename):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    filename = unquote(filename)

    post = Messages.query.filter(Messages.message_id == message_id).first()
    if not post:
        if file_type == "god_song":
            pass  # God songs can be in the long description
        elif filename == "banned_thumb.jpeg":
            pass  # banned image thumbnail
        else:
            return "Message ID not found"

    if post and post.hide:
        return "hidden"

    if file_type == "game":
        return post.game_image_file

    elif file_type == "thumb":
        # Return image thumbnail
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}_thumb".format(config.FILE_DIRECTORY, message_id)
        thumb_name = f'thumb_{media_info[filename]["file_number"]}.jpg'
        thumb_spoiler_name = f'thumb_{media_info[filename]["file_number"]}_spoiler.jpg'
        if media_info[filename]['spoiler'] and os.path.exists(os.path.join(path, thumb_spoiler_name)):
            return send_file(os.path.join(path, thumb_spoiler_name), mimetype="image/jpg")
        elif filename in media_info and os.path.exists(os.path.join(path, thumb_name)):
            return get_image_attach(
                message_id, path, thumb_name, media_info[filename]["extension"])
        else:
            return send_file(f"{config.CODE_DIR}/static/thread.png", mimetype="image/png")

    elif file_type == "thumb_video":
        # Return video thumbnail
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}_thumb".format(config.FILE_DIRECTORY, message_id)
        thumb_name = f'thumb_{media_info[filename]["file_number"]}.jpg'
        thumb_spoiler_name = f'thumb_{media_info[filename]["file_number"]}_spoiler.jpg'
        if filename in media_info:
            if media_info[filename]['spoiler'] and os.path.exists(os.path.join(path, thumb_spoiler_name)):
                return send_file(os.path.join(path, thumb_spoiler_name), mimetype="image/jpg")
            elif os.path.exists(os.path.join(path, thumb_name)):
                return send_file(os.path.join(path, thumb_name), mimetype="image/jpg")
            else:
                return send_file(f"{config.CODE_DIR}/static/video_missing_thumb.png", mimetype="image/png")

    elif file_type == "banned_thumb":
        # Return banned image thumbnail
        try:
            banned_id = int(message_id)
            img_ban = BanedHashes.query.filter(BanedHashes.id == banned_id).first()
            if img_ban:
                return send_file(BytesIO(base64.b64decode(img_ban.thumb_b64)), mimetype="image/jpeg")
        except:
            pass
        return ""

    elif file_type == "thumb_first":
        # Return image thumbnail
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}_thumb".format(config.FILE_DIRECTORY, message_id)
        for fn in media_info:
            if media_info[fn]["extension"] in config.FILE_EXTENSIONS_IMAGE:
                thumb_name = f'thumb_{media_info[fn]["file_number"]}.jpg'
                thumb_spoiler_name = f'thumb_{media_info[fn]["file_number"]}_spoiler.jpg'
                if media_info[fn]['spoiler'] and os.path.exists(os.path.join(path, thumb_spoiler_name)):
                    return send_file(os.path.join(path, thumb_spoiler_name), mimetype="image/png")
                elif os.path.exists(os.path.join(path, thumb_name)):
                    return get_image_attach(
                        message_id, path, thumb_name, media_info[fn]["extension"])

    elif file_type == "image":
        # Return image file
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}".format(config.FILE_DIRECTORY, message_id)
        if filename in media_info:
            return get_image_attach(
                message_id, path, filename, media_info[filename]["extension"])

    elif file_type == "god_song":
        file_path = "{}/{}_god_song.mp3".format(config.FILE_DIRECTORY, message_id)
        if os.path.exists(file_path):
            return send_file(file_path, mimetype="audio/mp3")
        else:
            return "Could not find God Song file at {}".format(file_path)

    elif file_type == "file":
        # Return potentially non-image file
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}".format(config.FILE_DIRECTORY, message_id)
        file_path = "{}/{}".format(path, filename)
        if os.path.exists(file_path):
            if (filename in media_info and
                    media_info[filename]["extension"] in config.FILE_EXTENSIONS_IMAGE):
                return get_image_attach(
                    message_id, path, filename, media_info[filename]["extension"])
            else:
                if os.path.abspath(file_path).startswith(path):
                    return send_file(file_path, download_name=filename)

    else:
        logger.error("File '{}' not found for message {}".format(filename, message_id))

    return "File not found"


@blueprint.route('/torrent/<torrent_file>')
def torrent(torrent_file):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    settings = GlobalSettings.query.first()
    if settings.kiosk_disable_torrent_file_download:
        return "User access to torrent is disabled"

    try:
        torrent_type = torrent_file.split(".")[1]
        post = Messages.query.filter(Messages.post_id == torrent_file.split(".")[0]).first()
        if not post:
            return "Post not found"
        elif torrent_type == "torrent" and post.file_torrent_decoded:
            return send_file(BytesIO(post.file_torrent_decoded), mimetype="applications/x-bittorrent")
        elif torrent_type == "magnet" and post.file_torrent_magnet:
            return post.file_torrent_magnet
        else:
            return "No torrent information found"
    except:
        return "Invalid Post"


@blueprint.route('/dl/<message_id>/<filename>')
def download(message_id, filename):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    post = Messages.query.filter(Messages.message_id == message_id).first()
    file_path_msg = os.path.join(config.FILE_DIRECTORY, message_id)
    file_path_full = os.path.join(file_path_msg, filename)
    if (post and
            os.path.exists(file_path_full) and
            os.path.abspath(file_path_full).startswith(file_path_msg)):
        return send_file(file_path_full,
                         download_name=filename,
                         as_attachment=True)


@blueprint.route('/block_address/<chan_address>/<block_address>/<block_type>', methods=('GET', 'POST'))
@count_views
def block_address(chan_address, block_address, block_type):
    """Block address locally, on single board or across all boards"""
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=chan_address)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_confirm = forms_board.Confirm()
    chan = Chan.query.filter(Chan.address == chan_address).first()

    board = {
        "current_chan": chan,
        "current_thread": None,
    }
    status_msg = {"status_message": []}

    if block_address in daemon_com.get_identities():
        status_msg['status_message'].append("You cannot block your own identity")
        status_msg['status_title'] = "Error"

    elif request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action="block_address",
                               block_type=block_type,
                               chan=chan,
                               chan_address=chan_address,
                               block_address=block_address)

    elif request.method == 'POST' and form_confirm.confirm.data:
        messages = Messages.query.filter(
            Messages.address_from == block_address).all()

        list_delete_message_ids = []

        for message in messages:
            if block_type == "single_board" and message.thread.chan.address == chan_address:
                list_delete_message_ids.append(message.message_id)
            elif block_type == "global":
                if not global_admin:
                    return allow_msg
                list_delete_message_ids.append(message.message_id)

        try:
            # First, delete messages from database
            if list_delete_message_ids:
                for each_id in list_delete_message_ids:
                    delete_post(each_id)
                daemon_com.signal_generate_post_numbers()

            # Allow messages to be deleted in bitmessage before allowing bitchan to rescan inbox
            time.sleep(1)
        except Exception as err:
            logger.error("Exception while deleting messages: {}".format(err))

        new_cmd = Command()
        new_cmd.do_not_send = True
        new_cmd.action = "block"
        new_cmd.action_type = "block_address"
        new_cmd.options = json.dumps({"block_address": block_address})
        if block_type == "single_board":
            new_cmd.chan_address = chan_address
        elif block_type == "global":
            new_cmd.chan_address = "all"  # global block (all boards)
        new_cmd.save()

        status_msg['status_title'] = "Success"
        status_msg['status_message'].append("Blocked address {}".format(block_address))

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)


@blueprint.route('/captcha/<img_id>/<page_id>/<b64_only>')
@count_views
def generate_captcha(page_id, img_id, b64_only):
    """Generate captcha"""
    can_post, allow_msg = allowed_access("can_post")
    can_view, allow_msg = allowed_access("can_view")
    if not can_post and not can_view:
        return allow_msg

    if page_id == "0":
        page_id = str(uuid.uuid4())
    else:
        page_id = None

    if b64_only == "0":
        b64 = None
        src = current_app.jinja_env.globals['captcha'](page_id=page_id, img_id=img_id)
    else:
        b64 = current_app.jinja_env.globals['captcha'](page_id=page_id, img_id=img_id, only_b64=True)
        src = None

    return jsonify({
        "src": src,
        "b64": b64,
        "page_id": page_id
    })
