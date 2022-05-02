import base64
import json
import logging
import time
import uuid

from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

import config
from bitchan_client import DaemonCom
from config import RESTRICTED_WORDS
from credentials import credentials
from database.models import Chan
from database.models import Command
from database.models import DeletedMessages
from database.models import GlobalSettings
from database.models import ModLog
from flask_routes import flask_session_login
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_board
from forms import forms_settings
from utils.files import LF
from utils.general import generate_passphrase
from utils.general import process_passphrase
from utils.general import set_clear_time_to_future
from utils.posts import delete_chan
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.routes import allowed_access
from utils.routes import page_dict
from utils.shared import add_mod_log_entry

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

    status_msg = {"status_message": []}

    if request.method == 'POST':
        if form_login.login.data:
            if is_login_banned():
                settings = GlobalSettings.query.first()
                status_msg['status_message'].append("Banned from logging in for {:.0f} more seconds".format(
                    settings.kiosk_ban_login_sec - session['ban_time_count']))

            if not form_login.password.data:
                status_msg['status_message'].append("Password required")

            if form_login.password.data == "DEFAULT_PASSWORD_CHANGE_ME":
                status_msg['status_message'].append("Cannot use the default password")

            if not status_msg['status_message']:
                login_credentials = credentials.get_user_by_password(form_login.password.data)
                if login_credentials:
                    # disable all logged-in sessions for this password
                    if login_credentials["single_session"] and 'uuid' in session:
                        for session_id, cred in flask_session_login.items():
                            if ('credentials' in cred and
                                    'password' in cred['credentials'] and
                                    cred['credentials']['password'] == form_login.password.data and
                                    cred['logged_in']):
                                flask_session_login[session_id]['logged_in'] = False
                                logger.info("LOG OUT (forced): {}, {}".format(
                                    session['uuid'], login_credentials['id']))

                    # create logged in session
                    if 'uuid' not in session:
                        session['uuid'] = uuid.uuid4()
                    flask_session_login[session['uuid']] = {
                        'logged_in': True,
                        'credentials': login_credentials
                    }
                    logger.info("LOG IN: {}, {}".format(
                        session['uuid'], login_credentials['id']))
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
            session['uuid'], flask_session_login[session['uuid']]['credentials']['id']))

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
                    status_msg['status_message'].append("Chan creation queued.")
                    new_chan.address = None
                    new_chan.is_setup = False

                if log_description:
                    add_mod_log_entry(
                        log_description,
                        message_id=None,
                        user_from=None,
                        board_address=result,
                        thread_hash=None)

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

            def process_additional_addresses(form_list, status_msg):
                add_list_failed = []
                add_list_passed = []
                try:
                    if form_list:
                        list_additional = form_list.split(",")
                        for each_ident in list_additional:
                            ident_strip = each_ident.replace(" ", "")
                            if (ident_strip and (
                                    not ident_strip.startswith("BM-") or
                                    len(ident_strip) > 38 or
                                    len(ident_strip) < 34)):
                                add_list_failed.append(ident_strip)
                            elif ident_strip.startswith("BM-"):
                                add_list_passed.append(ident_strip)
                except:
                    logger.exception(1)
                    status_msg['status_message'].append(
                        "Error parsing additional addresses. "
                        "Must only be comma-separated addresses without spaces.")
                return status_msg, add_list_failed, add_list_passed

            status_msg, add_list_prim_fail, add_list_prim_pass = process_additional_addresses(
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

            status_msg, add_list_sec_fail, add_list_sec_pass = process_additional_addresses(
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

            status_msg, add_list_ter_fail, add_list_ter_pass = process_additional_addresses(
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

            status_msg, add_list_restricted_fail, add_list_restricted_pass = process_additional_addresses(
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
                    status_msg['status_message'].append("Error parsing passphrase")
                    for error in errors:
                        status_msg['status_message'].append(error)

                if "%" in passphrase:  # TODO: Remove check when Bitmessage fixes this issue
                    status_msg['status_message'].append('Chan passphrase cannot contain: "%"')

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
                        log_description = "Created board {} ({})".format(url_text, result)
                    elif stage in ["public_list", "private_list"]:
                        url = "/list/{}".format(result)
                        url_text = "{} - {}".format(label, description)
                        log_description = "Created list {} ({})".format(url_text, result)
                else:
                    status_msg['status_message'].append("Creation queued")
                    new_chan.address = None
                    new_chan.is_setup = False

                if log_description:
                    add_mod_log_entry(
                        log_description,
                        message_id=None,
                        user_from=None,
                        board_address=result,
                        thread_hash=None)

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
    dict_chan_info = None
    status_msg = {"status_message": []}
    url = ""
    url_text = ""
    chan_exists = None
    stage = "join_passphrase"

    form_join = forms_board.Join()

    try:
        passphrase_dict_json = base64.b64decode(
            passphrase_base64.replace("&", "/")).decode()
        passphrase_dict = json.loads(passphrase_dict_json)
        passphrase_json = passphrase_dict["passphrase"]
        if "pgp_msg" in passphrase_dict:
            pgp_passphrase_msg = passphrase_dict["pgp_msg"]
        if "pgp_attach" in passphrase_dict:
            pgp_passphrase_attach = passphrase_dict["pgp_attach"]
        if "pgp_steg" in passphrase_dict:
            pgp_passphrase_steg = passphrase_dict["pgp_steg"]
        chan_exists = Chan.query.filter(Chan.passphrase == passphrase_json).first()

        errors, dict_chan_info = process_passphrase(passphrase_json)
        if not dict_chan_info:
            status_msg['status_message'].append("Error parsing passphrase")
            for error in errors:
                status_msg['status_message'].append(error)
    except Exception as err:
        status_msg['status_message'].append("Issue parsing base64 string: {}".format(err))

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
                    add_mod_log_entry(
                        log_description,
                        message_id=None,
                        user_from=None,
                        board_address=result,
                        thread_hash=None)

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

    chan = Chan.query.filter(Chan.address == address).first()

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action="leave",
                               address=address,
                               chan=chan)

    status_msg = {"status_message": []}

    admin_cmds = Command.query.filter(
        Command.chan_address == address).all()
    for each_adm_cmd in admin_cmds:
        each_adm_cmd.delete()

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            for each_thread in chan.threads:
                for each_message in each_thread.messages:
                    delete_post(each_message.message_id)  # Delete thread posts
                delete_thread(each_thread.thread_hash)  # Delete thread

            deleted_msgs = DeletedMessages.query.filter(
                DeletedMessages.address_to == address).all()
            for each_msg in deleted_msgs:
                logger.info("DeletedMessages: Deleting entry: {}".format(each_msg.message_id))
                each_msg.delete()

            try:
                daemon_com.leave_chan(address)  # Leave chan in Bitmessage
                delete_chan(address)  # Delete chan

                # Delete mod log entries for address
                mod_logs = ModLog.query.filter(
                    ModLog.board_address == address).all()
                for each_entry in mod_logs:
                    each_entry.delete()
            except:
                logger.exception("Could not delete chan via daemon or delete_chan()")

            daemon_com.delete_and_vacuum()

            status_msg['status_title'] = "Success"
            status_msg['status_message'].append("Deleted {}".format(address))
        finally:
            time.sleep(1)
            lf.lock_release(config.LOCKFILE_MSG_PROC)

    board = {"current_chan": None}
    url = ""
    url_text = ""

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)
