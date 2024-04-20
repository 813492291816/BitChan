import base64
import hashlib
import html
import json
import logging
import time
import uuid
from threading import Thread

from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from config import RESTRICTED_WORDS
from database.models import Auth
from database.models import Chan
from database.models import GlobalSettings
from flask_routes import flask_session_login
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_admin
from forms import forms_board
from forms import forms_settings
from utils.chan import leave_chan
from utils.general import generate_passphrase
from utils.general import process_passphrase
from utils.general import set_clear_time_to_future
from utils.routes import allowed_access
from utils.routes import check_kiosk_user_changes
from utils.routes import get_logged_in_user_name
from utils.routes import page_dict
from utils.shared import add_mod_log_entry
from utils.shared import return_list_of_csv_bitmessage_addresses

logger = logging.getLogger('bitchan.routes_management')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_management',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.before_request
def before_view():
    if not is_verified():
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


def login_fail():
    settings = GlobalSettings.query.first()
    try:
        session['login_cnt_fail'] += 1
    except KeyError:
        session['login_cnt_fail'] = 1

    if session['login_cnt_fail'] > settings.kiosk_attempts_login - 1:
        session['login_time_ban'] = time.time()
        session['login_cnt_fail'] = 0
        return 'Failed login attempts exceeded max of {}. ' \
               'Banned from attempting login for {} seconds.'.format(
                   settings.kiosk_attempts_login, settings.kiosk_ban_login_sec)
    else:
        return 'Login failed ({}/{})'.format(
            session['login_cnt_fail'], settings.kiosk_attempts_login)


def is_login_banned():
    if not session.get('login_cnt_fail'):
        session['login_cnt_fail'] = 0
    if not session.get('login_time_ban'):
        session['login_time_ban'] = 0
    elif session['login_time_ban']:
        settings = GlobalSettings.query.first()
        session['ban_time_count'] = time.time() - session['login_time_ban']
        if session['ban_time_count'] < settings.kiosk_ban_login_sec:
            return 1
        else:
            session['login_time_ban'] = 0
    return 0


@blueprint.route('/login', methods=('GET', 'POST'))
@count_views
def login():
    form_login = forms_settings.Login()
    form_kiosk_change_pw = forms_admin.KioskChangePW()

    status_msg = {"status_message": []}

    if request.method == 'POST':
        if form_kiosk_change_pw.new_pw.data:  # Change password
            current_pw_correct = False
            new_pw_valid = False

            sha256 = hashlib.sha256()
            sha256.update(form_kiosk_change_pw.current_password.data.encode())
            current_pw_hash = sha256.hexdigest()

            sha256 = hashlib.sha256()
            sha256.update(form_kiosk_change_pw.new_password.data.encode())
            new_pw_hash = sha256.hexdigest()

            user = Auth.query.filter(Auth.password_hash == current_pw_hash).first()

            if user:
                current_pw_correct = True
                status_msg['status_message'] = check_kiosk_user_changes(
                    user.name,
                    form_kiosk_change_pw.new_password.data,
                    form_kiosk_change_pw.new_password_repeat.data,
                    status_msg['status_message'],
                    skip_name_check=True)
            else:
                status_msg['status_message'].append("Current password incorrect")

            if not status_msg['status_message']:
                new_pw_valid = True

            if current_pw_correct and new_pw_valid:
                user.password_hash = new_pw_hash
                user.require_change_pw = False
                user.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Password updated. You may now log in.")

            if 'status_title' not in status_msg and status_msg['status_message']:
                status_msg['status_title'] = "Error"

            return render_template("pages/login.html",
                                   status_msg=status_msg)

        elif form_login.login.data:
            if is_login_banned():
                settings = GlobalSettings.query.first()
                status_msg['status_message'].append("Banned from logging in for {:.0f} more seconds".format(
                    settings.kiosk_ban_login_sec - session['ban_time_count']))

            # Check if kiosk recovery user is enabled
            kisok_recovery_login_valid = False
            try:
                from config import KIOSK_RECOVERY_USER_PASSWORD
            except:
                KIOSK_RECOVERY_USER_PASSWORD = None

            if not form_login.password.data:
                status_msg['status_message'].append("Password required")
            elif form_login.password.data == "DEFAULT_PASSWORD_CHANGE_ME":
                status_msg['status_message'].append("Cannot use the default password")
            elif KIOSK_RECOVERY_USER_PASSWORD == "DEFAULT_PASSWORD_CHANGE_ME":
                status_msg['status_message'].append("Kiosk recovery password must be changed from the default before it can be used.")
            elif form_login.password.data == KIOSK_RECOVERY_USER_PASSWORD:
                kisok_recovery_login_valid = True
            else:
                # Check if password needs to be changed
                sha256 = hashlib.sha256()
                sha256.update(form_login.password.data.encode())
                password_hash = sha256.hexdigest()
                require_change_pw = Auth.query.filter(and_(
                    Auth.password_hash == password_hash,
                    Auth.require_change_pw.is_(True))).first()
                if require_change_pw:
                    status_msg['status_title'] = "Error"
                    status_msg['status_message'].append("Must set a new password to continue.")
                    return render_template("pages/new_pw.html",
                                           status_msg=status_msg)

            if not status_msg['status_message']:
                if kisok_recovery_login_valid:
                    # create logged in session for kiosk recovery user
                    if 'uuid' not in session:
                        session['uuid'] = uuid.uuid4()
                    flask_session_login[session['uuid']] = {
                        'logged_in': True,
                        'credentials': {
                            "id": 999999,
                            "name": "Kiosk_Recovery_User",
                            "password_hash": "",
                            "single_session": True,
                            "global_admin": True,
                            "can_post": True,
                            "janitor": False,
                            "board_list_admin": False,
                            "admin_boards": []
                        }
                    }
                    logger.info("LOG IN: {}, {}".format(
                        session['uuid'], "Kiosk_Recovery_User"))
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("Logged In")

                else:
                    # Check database for valid credentials
                    sha256 = hashlib.sha256()
                    sha256.update(form_login.password.data.encode())
                    password_hash = sha256.hexdigest()
                    pw_hashes_match = Auth.query.filter(Auth.password_hash == password_hash).first()

                    if pw_hashes_match:
                        # disable all logged-in sessions for this password
                        if pw_hashes_match.single_session and 'uuid' in session:
                            for session_id, cred in flask_session_login.items():
                                if ('credentials' in cred and
                                        'pw_hash' in cred['credentials'] and
                                        cred['credentials']['password_hash'] == password_hash and
                                        cred['logged_in']):
                                    flask_session_login[session_id]['logged_in'] = False
                                    logger.info("LOG OUT (forced): {}, {}".format(
                                        session['uuid'], pw_hashes_match.name))

                        # create logged in session
                        if 'uuid' not in session:
                            session['uuid'] = uuid.uuid4()
                        flask_session_login[session['uuid']] = {
                            'logged_in': True,
                            'credentials': {
                                "id": pw_hashes_match.id,
                                "name": pw_hashes_match.name,
                                "password_hash": pw_hashes_match.password_hash,
                                "single_session": pw_hashes_match.single_session,
                                "global_admin": pw_hashes_match.global_admin,
                                "can_post": pw_hashes_match.can_post,
                                "janitor": pw_hashes_match.janitor,
                                "board_list_admin": pw_hashes_match.board_list_admin,
                                "admin_boards": json.loads(pw_hashes_match.admin_boards)
                            }
                        }
                        logger.info("LOG IN: {}, {}".format(
                            session['uuid'], pw_hashes_match.name))
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append("Logged In")
                    else:
                        if 'uuid' not in session:
                            session['uuid'] = uuid.uuid4()
                        if session['uuid'] not in flask_session_login:
                            flask_session_login[session['uuid']] = {
                                'logged_in': False,
                                'credentials': {}
                            }
                        else:
                            flask_session_login[session['uuid']]['logged_in'] = False
                        status_msg['status_message'].append(login_fail())

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/login.html",
                           status_msg=status_msg)


@blueprint.route('/logout', methods=('GET', 'POST'))
@count_views
def logout():
    status_msg = {"status_message": []}
    board = {"current_chan": None}

    if ('uuid' in session and
            session['uuid'] in flask_session_login and
            'logged_in' in flask_session_login[session['uuid']]):
        flask_session_login[session['uuid']]['logged_in'] = False
        logger.info("LOG OUT: {}, {}".format(
            session['uuid'], flask_session_login[session['uuid']]['credentials']['name']))

    status_msg['status_title'] = "Success"
    status_msg['status_message'].append("Logged Out")

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)


@blueprint.route('/login_info', methods=('GET', 'POST'))
@count_views
def login_info():
    global_admin, allow_msg = allowed_access("is_global_admin")
    janitor, allow_msg = allowed_access("is_janitor")
    if not global_admin and not janitor:
        return allow_msg

    status_msg = {"status_message": []}
    board = {"current_chan": None}

    if ('uuid' in session and
            session['uuid'] in flask_session_login and
            'logged_in' in flask_session_login[session['uuid']] and
            flask_session_login[session['uuid']]['logged_in'] and
            'credentials' in flask_session_login[session['uuid']]):
        login_credentials = flask_session_login[session['uuid']]['credentials']
        login_credentials['uuid'] = session['uuid']
    else:
        login_credentials = None

    return render_template("pages/login_info.html",
                           board=board,
                           login_credentials=login_credentials,
                           status_msg=status_msg)


@blueprint.route('/kiosk_users', methods=('GET', 'POST'))
@count_views
def kiosk_users():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    form_kiosk_users = forms_admin.KioskUsers()
    status_msg = {"status_message": []}
    delete_id = None

    for each_input in request.form:
        if each_input.startswith("delete_"):
            delete_id = each_input.split("_")[1]
            break

    if "edit_id" in request.form:
        edit_id = request.form.get("edit_id")
    else:
        edit_id = None

    if request.method == 'POST':
        if delete_id:
            admin_user_count = Auth.query.filter(Auth.global_admin.is_(True)).count()
            user_delete = Auth.query.filter(Auth.id == delete_id).first()
            settings = GlobalSettings.query.first()

            if settings.enable_kiosk_mode and admin_user_count < 2 and user_delete.global_admin:
                status_msg['status_message'].append("Cannot delete user: At least one admin user must exist if kiosk mode is enabled.")

            if not status_msg['status_message']:
                user_delete.delete()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("User deleted")

        elif form_kiosk_users.add_user.data:
            new_user = Auth()
            new_user.name = form_kiosk_users.name.data
            new_user.global_admin = form_kiosk_users.is_admin.data
            new_user.janitor = form_kiosk_users.is_janitor.data
            new_user.board_list_admin = form_kiosk_users.is_board_list_admin.data
            try:
                if not form_kiosk_users.admin_boards.data:
                    pass
                else:
                    new_user.admin_boards = json.dumps(form_kiosk_users.admin_boards.data.replace(" ", "").split(","))
            except:
                status_msg['status_message'].append("Invalid list of addresses")
            new_user.can_post = form_kiosk_users.can_post.data
            new_user.single_session = form_kiosk_users.single_session.data
            new_user.require_change_pw = form_kiosk_users.require_change_pw.data

            status_msg['status_message'] = check_kiosk_user_changes(
                form_kiosk_users.name.data,
                form_kiosk_users.new_password.data,
                form_kiosk_users.retype_password.data,
                status_msg['status_message'])

            if not status_msg['status_message']:
                sha256 = hashlib.sha256()
                sha256.update(form_kiosk_users.new_password.data.encode())
                new_user.password_hash = sha256.hexdigest()
                new_user.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("New user created")

        elif form_kiosk_users.edit_user.data:
            user_edit = Auth.query.filter(Auth.id == form_kiosk_users.edit_id.data).first()
            if user_edit:
                user_edit.name = form_kiosk_users.name.data
                user_edit.global_admin = form_kiosk_users.is_admin.data
                user_edit.janitor = form_kiosk_users.is_janitor.data
                user_edit.board_list_admin = form_kiosk_users.is_board_list_admin.data
                try:
                    if not form_kiosk_users.admin_boards.data:
                        user_edit.admin_boards = "[]"
                    else:
                        user_edit.admin_boards = json.dumps(form_kiosk_users.admin_boards.data.replace(" ", "").split(","))
                except:
                    pass
                user_edit.can_post = form_kiosk_users.can_post.data
                user_edit.single_session = form_kiosk_users.single_session.data
                user_edit.require_change_pw = form_kiosk_users.require_change_pw.data

                skip_changing_password = False
                if not form_kiosk_users.new_password.data and not form_kiosk_users.retype_password.data:
                    skip_changing_password = True

                status_msg['status_message'] = check_kiosk_user_changes(
                    form_kiosk_users.name.data,
                    form_kiosk_users.new_password.data,
                    form_kiosk_users.retype_password.data,
                    status_msg['status_message'],
                    skip_pw_check=skip_changing_password,
                    skip_name_check=True,
                    new_name_check=False,
                    old_user_id=user_edit.id)

                if not status_msg['status_message']:
                    if not skip_changing_password:
                        sha256 = hashlib.sha256()
                        sha256.update(form_kiosk_users.new_password.data.encode())
                        user_edit.password_hash = sha256.hexdigest()
                    user_edit.save()
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("User edits saved")
        else:
            for each_input in request.form:
                if each_input.startswith("edit_"):
                    edit_id = each_input.split("_")[1]
                    break
                elif each_input.startswith("delete_"):
                    delete_id = each_input.split("_")[1]
                    break

    if edit_id:
        user = Auth.query.filter(Auth.id == edit_id).first()
    else:
        user = None

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/kiosk_users.html",
                           form_kiosk_users=form_kiosk_users,
                           edit_id=edit_id,
                           json=json,
                           kiosk_credentials=Auth.query.all(),
                           status_msg=status_msg,
                           user=user)


@blueprint.route('/join', methods=('GET', 'POST'))
@count_views
def join():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    form_join = forms_board.Join()

    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    if not form_join.stage.data:
        stage = "start"
    else:
        stage = form_join.stage.data

    if request.method == 'POST':
        if stage == "start":
            if form_join.join_type.data == "join":
                stage = "join"
            elif form_join.join_type.data == "public_board":
                stage = "public_board"
            elif form_join.join_type.data == "private_board":
                stage = "private_board"
            elif form_join.join_type.data == "public_list":
                stage = "public_list"
            elif form_join.join_type.data == "private_list":
                stage = "private_list"

        # Join board or list
        elif stage == "join" and form_join.join.data:
            if not form_join.passphrase.data:
                status_msg['status_message'].append("Passphrase required")

            passphrase = None
            try:
                passphrase_dict = json.loads(form_join.passphrase.data)
                passphrase = json.dumps(passphrase_dict)
            except:
                status_msg['status_message'].append("Passphrase does not represent valid JSON")

            # Check if already a member of board/list with passphrase
            chan = Chan.query.filter(Chan.passphrase == passphrase).first()
            if chan:
                status_msg['status_message'].append("You are already a member of this board or list.")

            if not form_join.pgp_passphrase_msg.data:
                status_msg['status_message'].append("Message PGP passphrase required")
            elif len(form_join.pgp_passphrase_msg.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append(
                    "Message PGP passphrase too long. Max: {}".format(config.PGP_PASSPHRASE_LENGTH))

            if not form_join.pgp_passphrase_attach.data:
                status_msg['status_message'].append(
                    "Attachment PGP passphrase required. "
                    "If it's a list you're joining, just leave the default option.")
            elif len(form_join.pgp_passphrase_attach.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append(
                    "Attachment PGP passphrase too long. Max: {}".format(config.PGP_PASSPHRASE_LENGTH))

            if not form_join.pgp_passphrase_steg.data:
                status_msg['status_message'].append(
                    "Steg PGP passphrase required"
                    "If it's a list you're joining, just leave the default option.")
            elif len(form_join.pgp_passphrase_attach.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append(
                    "Steg PGP passphrase too long. Max: {}".format(config.PGP_PASSPHRASE_LENGTH))

            errors, dict_chan_info = process_passphrase(passphrase)
            if not dict_chan_info:
                status_msg['status_message'].append("Error parsing passphrase")
                for error in errors:
                    status_msg['status_message'].append(error)

            if not status_msg['status_message']:
                for each_word in RESTRICTED_WORDS:
                    if each_word in dict_chan_info["label"].lower():
                        status_msg['status_message'].append(
                            "bitchan is a restricted word for labels")

            if "%" in passphrase:  # TODO: Remove check when Bitmessage fixes this issue
                status_msg['status_message'].append('Chan passphrase cannot contain: "%"')

            if not status_msg['status_message']:
                log_description = None

                result = daemon_com.join_chan(passphrase, clear_inventory=form_join.resync.data)

                if dict_chan_info["rules"]:
                    dict_chan_info["rules"] = set_clear_time_to_future(dict_chan_info["rules"])

                new_chan = Chan()
                new_chan.passphrase = passphrase
                new_chan.access = dict_chan_info["access"]
                new_chan.type = dict_chan_info["type"]
                new_chan.label = dict_chan_info["label"]
                new_chan.description = dict_chan_info["description"]
                new_chan.primary_addresses = json.dumps(dict_chan_info["primary_addresses"])
                new_chan.secondary_addresses = json.dumps(dict_chan_info["secondary_addresses"])
                new_chan.tertiary_addresses = json.dumps(dict_chan_info["tertiary_addresses"])
                new_chan.restricted_addresses = json.dumps(dict_chan_info["restricted_addresses"])
                new_chan.rules = json.dumps(dict_chan_info["rules"])
                new_chan.pgp_passphrase_msg = form_join.pgp_passphrase_msg.data
                new_chan.pgp_passphrase_attach = form_join.pgp_passphrase_attach.data
                new_chan.pgp_passphrase_steg = form_join.pgp_passphrase_steg.data

                if form_join.unlisted.data:
                    new_chan.unlisted = True

                if form_join.restricted.data:
                    new_chan.restricted = True

                if result.startswith("BM-"):
                    new_chan.address = result
                    new_chan.is_setup = True
                    if new_chan.type == "board":
                        status_msg['status_message'].append("Joined board")
                        url = "/board/{}/1".format(result)
                        url_text = "/{}/ - {}".format(new_chan.label, new_chan.description)
                        log_description = f"Joined board {result}: {url_text}"
                    elif new_chan.type == "list":
                        status_msg['status_message'].append("Joined list")
                        url = "/list/{}".format(result)
                        url_text = "{} - {}".format(new_chan.label, new_chan.description)
                        log_description = f"Joined list {result}: {url_text}"
                else:
                    status_msg['status_message'].append("Chan creation queued.")
                    new_chan.address = None
                    new_chan.is_setup = False

                if log_description:
                    add_mod_log_entry(log_description, board_address=result)

                if 'status_title' not in status_msg:
                    status_msg['status_title'] = "Success"
                    new_chan.save()
                    stage = "end"

        # Create public/private board/list
        elif (stage in ["public_board",
                        "private_board",
                        "public_list",
                        "private_list"] and
                form_join.join.data):

            if not form_join.pgp_passphrase_msg.data:
                status_msg['status_message'].append("Message PGP passphrase required")
            elif len(form_join.pgp_passphrase_msg.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append(
                    "Message PGP passphrase too long. Max: {}".format(config.PGP_PASSPHRASE_LENGTH))

            if stage in ["public_board", "private_board"]:
                if not form_join.pgp_passphrase_attach.data:
                    status_msg['status_message'].append("Attachment PGP passphrase required")
                elif len(form_join.pgp_passphrase_attach.data) > config.PGP_PASSPHRASE_LENGTH:
                    status_msg['status_message'].append(
                        "Attachment PGP passphrase too long. Max: {}".format(config.PGP_PASSPHRASE_LENGTH))

                if not form_join.pgp_passphrase_steg.data:
                    status_msg['status_message'].append("Steg PGP passphrase required")
                elif len(form_join.pgp_passphrase_steg.data) > config.PGP_PASSPHRASE_LENGTH:
                    status_msg['status_message'].append(
                        "Steg PGP passphrase too long. Max: {}".format(config.PGP_PASSPHRASE_LENGTH))

            label = form_join.label.data
            if not label:
                status_msg['status_message'].append("Label required")
            elif len(label) > config.LABEL_LENGTH:
                status_msg['status_message'].append(
                    "Label too long. Must be {} or fewer characters.".format(config.LABEL_LENGTH))
            for each_word in RESTRICTED_WORDS:
                if each_word in label.lower():
                    status_msg['status_message'].append("bitchan is a restricted word for labels")

            description = form_join.description.data
            if not description:
                status_msg['status_message'].append("Description required")
            elif len(description) > config.DESCRIPTION_LENGTH:
                status_msg['status_message'].append(
                    "Description too long. Must be {} or fewer characters.".format(config.DESCRIPTION_LENGTH))

            status_msg, add_list_prim_fail, add_list_prim_pass = return_list_of_csv_bitmessage_addresses(
                form_join.primary_additional.data, status_msg)
            if add_list_prim_fail:
                status_msg['status_message'].append(
                    "Error parsing primary additional identities. "
                    "Must only be comma-separated addresses without spaces.")
            if len(",".join(add_list_prim_pass)) > config.PASSPHRASE_ADDRESSES_LENGTH:
                status_msg['status_message'].append("Owner Address list is greater than {} characters: {}".format(
                    config.PASSPHRASE_ADDRESSES_LENGTH, len(",".join(add_list_prim_pass))))

            list_primary_identities = []
            for key in request.form.keys():
                if 'primary_identity_' in key and key[17:]:
                    list_primary_identities.append(key[17:])
            list_primary_address_book = []
            for key in request.form.keys():
                if 'primary_address_book_' in key and key[21:]:
                    list_primary_address_book.append(key[21:])
            list_primary_chans = []
            for key in request.form.keys():
                if 'primary_chans_' in key and key[14:]:
                    list_primary_chans.append(key[14:])
            list_primary_addresses = (
                list_primary_identities +
                list_primary_address_book +
                list_primary_chans +
                add_list_prim_pass)

            status_msg, add_list_sec_fail, add_list_sec_pass = return_list_of_csv_bitmessage_addresses(
                form_join.secondary_additional.data, status_msg)
            if add_list_sec_fail:
                status_msg['status_message'].append(
                    "Error parsing secondary additional identities. "
                    "Must only be comma-separated addresses without spaces.")
            if len(",".join(add_list_sec_pass)) > config.PASSPHRASE_ADDRESSES_LENGTH:
                status_msg['status_message'].append("Admin Address list is greater than {} characters: {}".format(
                    config.PASSPHRASE_ADDRESSES_LENGTH, len(",".join(add_list_sec_pass))))

            list_secondary_identities = []
            for key in request.form.keys():
                if 'secondary_identity_' in key and key[19:]:
                    list_secondary_identities.append(key[19:])
            list_secondary_address_book = []
            for key in request.form.keys():
                if 'secondary_address_book_' in key and key[23:]:
                    list_secondary_address_book.append(key[23:])
            list_secondary_chans = []
            for key in request.form.keys():
                if 'secondary_chans_' in key and key[16:]:
                    list_secondary_chans.append(key[16:])
            list_secondary_addresses = (
                list_secondary_identities +
                list_secondary_address_book +
                list_secondary_chans +
                add_list_sec_pass)

            status_msg, add_list_ter_fail, add_list_ter_pass = return_list_of_csv_bitmessage_addresses(
                form_join.tertiary_additional.data, status_msg)
            if add_list_ter_fail:
                status_msg['status_message'].append(
                    "Error parsing tertiary additional identities. "
                    "Must only be comma-separated addresses without spaces.")
            if len(",".join(add_list_ter_pass)) > config.PASSPHRASE_ADDRESSES_LENGTH:
                status_msg['status_message'].append("User Address list is greater than {} characters: {}".format(
                    config.PASSPHRASE_ADDRESSES_LENGTH, len(",".join(add_list_ter_pass))))

            list_tertiary_identities = []
            for key in request.form.keys():
                if 'tertiary_identity_' in key and key[18:]:
                    list_tertiary_identities.append(key[18:])
            list_tertiary_address_book = []
            for key in request.form.keys():
                if 'tertiary_address_book_' in key and key[22:]:
                    list_tertiary_address_book.append(key[22:])
            list_tertiary_chans = []
            for key in request.form.keys():
                if 'tertiary_chans_' in key and key[15:]:
                    list_tertiary_chans.append(key[15:])
            list_tertiary_addresses = (
                    list_tertiary_identities +
                    list_tertiary_address_book +
                    list_tertiary_chans +
                    add_list_ter_pass)

            status_msg, add_list_restricted_fail, add_list_restricted_pass = return_list_of_csv_bitmessage_addresses(
                form_join.restricted_additional.data, status_msg)
            if add_list_restricted_fail:
                status_msg['status_message'].append(
                    "Error parsing restricted additional identities. "
                    "Must only be comma-separated addresses without spaces.")

            list_restricted_address_book = []
            for key in request.form.keys():
                if 'restricted_address_book_' in key and key[24:]:
                    list_restricted_address_book.append(key[24:])
            list_restricted_chans = []
            for key in request.form.keys():
                if 'restricted_chans_' in key and key[17:]:
                    list_restricted_chans.append(key[17:])
            list_restricted_addresses = (
                    list_restricted_address_book +
                    list_restricted_chans +
                    add_list_restricted_pass)

            if (stage in ["private_board", "private_list"] and
                    not list_primary_addresses):
                status_msg['status_message'].append(
                    "Must provide at least one primary address as the owner")

            rules = {}

            if form_join.require_identity_to_post.data:
                rules["require_identity_to_post"] = form_join.require_identity_to_post.data

            if form_join.restrict_thread_creation.data:
                status_msg, add_list_restricted_fail, add_list_restricted_pass = return_list_of_csv_bitmessage_addresses(
                    form_join.thread_creation_users.data, status_msg)
                if add_list_restricted_fail:
                    status_msg['status_message'].append(
                        "Parsing Thread Creation User Addresses. "
                        "Must be properly-formatted addresses separated by commas. "
                        f"Failed addresses: {add_list_restricted_fail}")
                rules["restrict_thread_creation"] = {"enabled": True, "addresses": add_list_restricted_pass}

            if form_join.automatic_wipe.data:
                if form_join.wipe_epoch.data > config.WIPE_START_MAX:
                    status_msg['status_message'].append(
                        "Automatic Wipe Epoch Start Time is greater than year 3020.")
                if form_join.interval_seconds.data > config.WIPE_INTERVAL_MAX:
                    status_msg['status_message'].append(
                        "Automatic Wipe Interval is greater than 500 years.")
                try:
                    rules["automatic_wipe"] = {
                        "wipe_epoch": form_join.wipe_epoch.data,
                        "interval_seconds": form_join.interval_seconds.data
                    }
                except:
                    status_msg['status_message'].append(
                        "Could not process Rule options to Automatic Wipe")

            if form_join.allow_list_pgp_metadata.data:
                rules["allow_list_pgp_metadata"] = form_join.allow_list_pgp_metadata.data

            extra_string = form_join.extra_string.data
            if len(extra_string) > config.PASSPHRASE_ADDRESSES_LENGTH:
                status_msg['status_message'].append("Extra String is greater than {} characters: {}".format(
                    config.PASSPHRASE_EXTRA_STRING_LENGTH, len(extra_string)))

            if not status_msg['status_message']:
                access = stage.split("_")[0]
                chan_type = stage.split("_")[1]

                passphrase = generate_passphrase(
                    access,
                    chan_type,
                    label,
                    description,
                    list_restricted_addresses,
                    list_primary_addresses,
                    list_secondary_addresses,
                    list_tertiary_addresses,
                    rules,
                    extra_string)

                # Check generated passphrase
                errors, dict_chan_info = process_passphrase(passphrase)
                if not dict_chan_info:
                    status_msg['status_message'].append("Parsing passphrase")
                    for error in errors:
                        status_msg['status_message'].append(error)

                if "%" in passphrase:  # TODO: Remove check when Bitmessage fixes this issue
                    status_msg['status_message'].append('Chan passphrase cannot contain: "%"')

                if Chan.query.filter(Chan.passphrase == passphrase).count():
                    status_msg['status_message'].append("Chan passphrase already in database")

            if not status_msg['status_message']:
                log_description = None

                result = daemon_com.join_chan(passphrase, clear_inventory=form_join.resync.data)

                if rules:
                    rules = set_clear_time_to_future(rules)

                new_chan = Chan()
                new_chan.access = access
                new_chan.type = chan_type
                new_chan.label = label
                new_chan.description = description
                new_chan.passphrase = passphrase
                new_chan.restricted_addresses = json.dumps(list_restricted_addresses)
                new_chan.primary_addresses = json.dumps(list_primary_addresses)
                new_chan.secondary_addresses = json.dumps(list_secondary_addresses)
                new_chan.tertiary_addresses = json.dumps(list_tertiary_addresses)
                new_chan.rules = json.dumps(rules)
                new_chan.pgp_passphrase_msg = form_join.pgp_passphrase_msg.data
                new_chan.pgp_passphrase_attach = form_join.pgp_passphrase_attach.data
                new_chan.pgp_passphrase_steg = form_join.pgp_passphrase_steg.data

                if form_join.unlisted.data:
                    new_chan.unlisted = True

                if form_join.restricted.data:
                    new_chan.restricted = True

                if result.startswith("BM-"):
                    if stage == "public_board":
                        status_msg['status_message'].append("Created public board")
                    elif stage == "private_board":
                        status_msg['status_message'].append("Created private board")
                    elif stage == "public_list":
                        status_msg['status_message'].append("Created public list")
                    elif stage == "private_list":
                        status_msg['status_message'].append("Created private list")
                    new_chan.address = result
                    new_chan.is_setup = True
                    if stage in ["public_board", "private_board"]:
                        url = "/board/{}/1".format(result)
                        url_text = "/{}/ - {}".format(label, description)
                        log_description = f"Created board {result}: {url_text}"
                    elif stage in ["public_list", "private_list"]:
                        url = "/list/{}".format(result)
                        url_text = "{} - {}".format(label, description)
                        log_description = f"Created list {result}: {url_text}"
                else:
                    status_msg['status_message'].append("Creation queued")
                    new_chan.address = None
                    new_chan.is_setup = False

                if log_description:
                    user_name = get_logged_in_user_name()
                    admin_name = user_name if user_name else "LOCAL ADMIN"
                    add_mod_log_entry(log_description, board_address=new_chan.address, user_from=admin_name)

                if 'status_title' not in status_msg:
                    status_msg['status_title'] = "Success"
                    new_chan.save()
                    stage = "end"

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/join.html",
                           stage=stage,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/join_base64/<passphrase_base64>', methods=('GET', 'POST'))
@count_views
def join_base64(passphrase_base64):
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
    pgp_passphrase_attach = config.PGP_PASSPHRASE_ATTACH
    pgp_passphrase_steg = config.PGP_PASSPHRASE_STEG
    passphrase_json = None
    dict_chan_info = None
    status_msg = {"status_message": []}
    url = ""
    url_text = ""
    chan_exists = None
    stage = "join_passphrase"

    form_join = forms_board.Join()

    try:
        passphrase_json = base64.b64decode(html.unescape(passphrase_base64)).decode()

        try:
            dict_test = json.loads(passphrase_json)
        except:
            dict_test = {}

        if dict_test:
            if "passphrase" in dict_test:
                passphrase_json = dict_test["passphrase"]
            if "pgp_msg" in dict_test:
                pgp_passphrase_msg = dict_test["pgp_msg"]
            if "pgp_attach" in dict_test:
                pgp_passphrase_attach = dict_test["pgp_attach"]
            if "pgp_steg" in dict_test:
                pgp_passphrase_steg = dict_test["pgp_steg"]

        chan_exists = Chan.query.filter(Chan.passphrase == passphrase_json).first()

        errors, dict_chan_info = process_passphrase(passphrase_json)
        if not dict_chan_info:
            status_msg['status_message'].append("Parsing passphrase")
            for error in errors:
                status_msg['status_message'].append(error)
    except Exception as err:
        logger.exception("parsing base64 string")
        status_msg['status_message'].append(
            f'Issue parsing base64 string: {html.unescape(passphrase_base64)}: {err}')

    if request.method == 'POST':
        if form_join.join.data:

            if not status_msg['status_message']:
                for each_word in RESTRICTED_WORDS:
                    if each_word in dict_chan_info["label"].lower():
                        status_msg['status_message'].append(
                            "bitchan is a restricted word for labels")

                if "%" in passphrase_json:  # TODO: Remove check when Bitmessage fixes this issue
                    status_msg['status_message'].append('Chan passphrase cannot contain: "%"')

            if not status_msg['status_message']:
                log_description = None

                result = daemon_com.join_chan(passphrase_json, clear_inventory=form_join.resync.data)

                if dict_chan_info["rules"]:
                    dict_chan_info["rules"] = set_clear_time_to_future(dict_chan_info["rules"])

                if form_join.pgp_passphrase_msg.data:
                    pgp_passphrase_msg = form_join.pgp_passphrase_msg.data
                if form_join.pgp_passphrase_attach.data:
                    pgp_passphrase_attach = form_join.pgp_passphrase_attach.data
                if form_join.pgp_passphrase_steg.data:
                    pgp_passphrase_steg = form_join.pgp_passphrase_steg.data

                new_chan = Chan()
                new_chan.passphrase = passphrase_json
                new_chan.access = dict_chan_info["access"]
                new_chan.type = dict_chan_info["type"]
                new_chan.label = dict_chan_info["label"]
                new_chan.description = dict_chan_info["description"]
                new_chan.pgp_passphrase_msg = pgp_passphrase_msg
                if dict_chan_info["type"] == "board":
                    new_chan.pgp_passphrase_attach = pgp_passphrase_attach
                    new_chan.pgp_passphrase_steg = pgp_passphrase_steg
                new_chan.primary_addresses = json.dumps(dict_chan_info["primary_addresses"])
                new_chan.secondary_addresses = json.dumps(dict_chan_info["secondary_addresses"])
                new_chan.tertiary_addresses = json.dumps(dict_chan_info["tertiary_addresses"])
                new_chan.restricted_addresses = json.dumps(dict_chan_info["restricted_addresses"])
                new_chan.rules = json.dumps(dict_chan_info["rules"])

                if form_join.unlisted.data:
                    new_chan.unlisted = True

                if form_join.restricted.data:
                    new_chan.restricted = True

                if result.startswith("BM-"):
                    new_chan.address = result
                    new_chan.is_setup = True
                    if new_chan.type == "board":
                        status_msg['status_message'].append("Joined board")
                        url = "/board/{}/1".format(result)
                        url_text = "/{}/ - {}".format(new_chan.label, new_chan.description)
                        log_description = "Joined board {} ({})".format(url_text, result)
                    elif new_chan.type == "list":
                        status_msg['status_message'].append("Joined list")
                        url = "/list/{}".format(result)
                        url_text = "{} - {}".format(new_chan.label, new_chan.description)
                        log_description = "Joined list {} ({})".format(url_text, result)
                else:
                    status_msg['status_message'].append("Creation queued")
                    new_chan.address = None
                    new_chan.is_setup = False

                if log_description:
                    add_mod_log_entry(log_description, board_address=result)

                if 'status_title' not in status_msg:
                    status_msg['status_title'] = "Success"
                    new_chan.save()
                    stage = "end"

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/join.html",
                           chan_exists=chan_exists,
                           dict_chan_info=dict_chan_info,
                           form_join=form_join,
                           passphrase=passphrase_json,
                           pgp_passphrase_msg=pgp_passphrase_msg,
                           pgp_passphrase_attach=pgp_passphrase_attach,
                           pgp_passphrase_steg=pgp_passphrase_steg,
                           stage=stage,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/leave/<address>', methods=('GET', 'POST'))
@count_views
def leave(address):
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    form_confirm = forms_board.Confirm()
    form_leave = forms_board.Leave()

    chan = Chan.query.filter(Chan.address == address).first()

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action="leave",
                               address=address,
                               chan=chan)

    status_msg = {"status_message": []}

    leave_and_delete = Thread(
        target=leave_chan, args=(address, form_leave.clear_mod_log.data,))
    leave_and_delete.start()

    status_msg['status_title'] = "Success"
    status_msg['status_message'].append(f"Deletion of /{chan.label}/ - {chan.description} ({address}) initiated. See the logs for details and any errors")

    board = {"current_chan": None}
    url = ""
    url_text = ""

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)
