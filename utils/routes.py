import base64
import datetime
import html
import json
import logging
import math
import os
import time
from collections import OrderedDict
from operator import getitem
from urllib.parse import quote
from urllib.parse import urlparse

from flask import request
from flask import session
from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from database.models import AddressBook
from database.models import Chan
from database.models import Command
from database.models import Flags
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import Threads
from flask_routes import flask_session_login
from forms.nations import nations
from utils import themes
from utils.files import human_readable_size
from utils.general import display_time
from utils.general import process_passphrase
from utils.general import timestamp_to_date
from utils.generate_card import get_card_link_html
from utils.generate_popup import attachment_info
from utils.generate_popup import generate_popup_post_body_message
from utils.generate_popup import generate_reply_link_and_popup_html
from utils.generate_popup import get_user_name
from utils.generate_popup import message_has_images
from utils.generate_post import generate_post_html
from utils.html_truncate import truncate
from utils.replacements import format_body
from utils.replacements import replace_lt_gt
from utils.shared import get_access
from utils.shared import get_post_id
from utils.shared import post_has_image
from utils.tor import path_torrc
from utils.tor import str_bm_enabled
from utils.tor import str_custom_enabled
from utils.tor import str_random_enabled

logger = logging.getLogger('bitchan.routes')
daemon_com = DaemonCom()


def get_user_name_info(address_from, full_address=False):
    identities = daemon_com.get_identities()
    address_book = daemon_com.get_address_book()
    chans = daemon_com.get_all_chans()
    user_type = None

    if full_address:
        address = address_from
    else:
        address = address_from[-config.ID_LENGTH:]

    if address_from in identities:
        user_type = "identity"
        if identities[address_from]["label_short"]:
            username = "{id} (You, {lbl})".format(
                id=address,
                lbl=identities[address_from]["label_short"])
        else:
            username = "{} (You)".format(
                address)
    elif address_from in address_book:
        user_type = "address_book"
        if address_book[address_from]["label_short"]:
            username = "{id} ({lbl})".format(
                id=address,
                lbl=address_book[address_from]["label_short"])
        else:
            username = "{} (ⒶⓃⓄⓃ)".format(address)
    elif address_from in chans:
        user_type = "chan"
        if chans[address_from]["label_short"]:
            username = "{id} ({lbl})".format(
                id=address,
                lbl=chans[address_from]["label_short"])
        else:
            username = "{} (ⒶⓃⓄⓃ)".format(address)
    else:
        username = address
    return username, user_type


def get_chan_passphrase(address):
    chan = Chan.query.filter(Chan.address == address).first()
    dict_join = {
        "passphrase": chan.passphrase
    }
    passphrase_base64 = base64.b64encode(
        json.dumps(dict_join).encode()).decode().replace("/", "&")
    if chan.pgp_passphrase_msg != config.PGP_PASSPHRASE_MSG:
        dict_join["pgp_msg"] = chan.pgp_passphrase_msg
    if chan.pgp_passphrase_attach != config.PGP_PASSPHRASE_ATTACH:
        dict_join["pgp_attach"] = chan.pgp_passphrase_attach
    if chan.pgp_passphrase_steg != config.PGP_PASSPHRASE_STEG:
        dict_join["pgp_steg"] = chan.pgp_passphrase_steg
    passphrase_base64_with_pgp = base64.b64encode(
        json.dumps(dict_join).encode()).decode().replace("/", "&")
    return passphrase_base64, passphrase_base64_with_pgp


def get_onion_info():
    tor_enabled_bm = False
    tor_address_bm = None
    try:
        with open(path_torrc) as f:
            s = f.read()
            if str_bm_enabled in s:
                tor_enabled_bm = True
            if os.path.exists("/usr/local/tor/bm/hostname"):
                text_file = open("/usr/local/tor/bm/hostname", "r")
                tor_address_bm = text_file.read()
                text_file.close()
    except:
        logger.exception("checking torrc")

    tor_enabled_rand = False
    tor_address_rand = None
    try:
        with open(path_torrc) as f:
            s = f.read()
            if str_random_enabled in s:
                tor_enabled_rand = True
            if os.path.exists("/usr/local/tor/rand/hostname"):
                text_file = open("/usr/local/tor/rand/hostname", "r")
                tor_address_rand = text_file.read()
                text_file.close()
    except:
        logger.exception("checking torrc")

    tor_enabled_cus = False
    tor_address_cus = None
    try:
        with open(path_torrc) as f:
            s = f.read()
            if str_custom_enabled in s:
                tor_enabled_cus = True
            if os.path.exists("/usr/local/tor/cus/hostname"):
                text_file = open("/usr/local/tor/cus/hostname", "r")
                tor_address_cus = text_file.read()
                text_file.close()
    except:
        logger.exception("checking torrc")

    return tor_enabled_bm, tor_address_bm, tor_enabled_rand, tor_address_rand, tor_enabled_cus, tor_address_cus


def get_post_replies_dict(message_id):
    message = Messages.query.filter(
        Messages.message_id == message_id).first()
    if not message:
        return {}

    dict_replies = OrderedDict()

    try:
        reply_ids = json.loads(message.post_ids_replying_to_msg)
    except:
        reply_ids = []

    for each_reply_id in reply_ids:
        reply = Messages.query.filter(
            Messages.message_id.endswith(each_reply_id.lower())).first()

        if (reply and
                reply.thread and
                reply.thread.chan and
                message.thread and
                message.thread.chan and
                not reply.hide):

            name_str = ""
            self_post = False
            identity = Identity.query.filter(
                Identity.address == reply.address_from).first()
            if not name_str and identity and identity.label:
                self_post = True
                name_str = " ({})".format(identity.label)
            address_book = AddressBook.query.filter(
                AddressBook.address == reply.address_from).first()
            if not name_str and address_book and address_book.label:
                name_str = " ({})".format(address_book.label)

            if reply.thread.id == message.thread.id:
                dict_replies[each_reply_id] = {
                    "msg_location": "local_same_thread",
                    "name_str": name_str,
                    "self_post": self_post,
                    "message": reply
                }
            elif reply.thread.chan.address == message.thread.chan.address:
                dict_replies[each_reply_id] = {
                    "msg_location": "remote_same_board",
                    "name_str": name_str,
                    "self_post": self_post,
                    "message": reply
                }
            else:
                dict_replies[each_reply_id] = {
                    "msg_location": "remote_different_board",
                    "name_str": name_str,
                    "self_post": self_post,
                    "message": reply
                }

    return dict_replies


def format_message_steg(message_id):
    message = Messages.query.filter(Messages.message_id == message_id).first()
    if message:
        try:
            message_steg = json.loads(message.message_steg)
        except:
            message_steg = {}
        msg_text = ""
        if message_steg:
            for i, (filename, each_msg) in enumerate(message_steg.items()):
                if i < len(message_steg) - 1:
                    msg_text += '<div style="padding-bottom: 1em"><span class="replace-funcs">File: {file}</span>' \
                                '<br/>{steg}</div>'.format(file=filename, steg=each_msg)
                else:
                    msg_text += '<div><span class="replace-funcs">File: {file}</span>' \
                                '<br/>{steg}</div>'.format(file=filename, steg=each_msg)
            return msg_text


def is_logged_in():
    if ('uuid' in session and session['uuid'] in flask_session_login and
            flask_session_login[session['uuid']]['logged_in']):
        return True
    return False


def get_chan_mod_info(address):
    try:
        chan = Chan.query.filter(Chan.address == address).first()
        if chan:
            return chan.label, chan.description, chan.type
    except:
        pass
    return None, None, None


def get_thread_subject(thread_hash):
    thread = Threads.query.filter(Threads.thread_hash == thread_hash).first()
    if thread:
        return thread.subject


def get_thread_options(thread_hash):
    thread_options = {
        "lock": False,
        "lock_local": False,
        "lock_remote": False,
        "sticky": False,
        "sticky_local": False,
        "sticky_remote": False,
        "anchor": False,
        "anchor_local": False,
        "anchor_remote": False
    }

    thread = Threads.query.filter(
        Threads.thread_hash == thread_hash).first()
    admin_cmd = Command.query.filter(
        Command.thread_id == thread_hash).first()
    if admin_cmd:
        if admin_cmd.thread_lock:
            thread_options["lock"] = True
            thread_options["lock_remote"] = True
        if admin_cmd.thread_sticky:
            thread_options["sticky"] = True
            thread_options["sticky_remote"] = True
        if admin_cmd.thread_anchor:
            thread_options["anchor"] = True
            thread_options["anchor_remote"] = True

    if thread:
        if thread.locked_local:
            thread_options["lock"] = True
            thread_options["lock_local"] = True
        if thread.stickied_local:
            thread_options["sticky"] = True
            thread_options["sticky_local"] = True
        if thread.anchored_local:
            thread_options["anchor"] = True
            thread_options["anchor_local"] = True

    return thread_options


def has_permission(permission):
    if ('uuid' in session and session['uuid'] in flask_session_login and
            flask_session_login[session['uuid']]['logged_in']):
        if permission == "is_global_admin":
            if flask_session_login[session['uuid']]["credentials"]["global_admin"]:
                return True
        elif permission == "is_board_admin":
            return flask_session_login[session['uuid']]["credentials"]["admin_boards"]
        elif permission == "is_janitor":
            return flask_session_login[session['uuid']]["credentials"]["janitor"]
        elif permission == "can_post":
            if flask_session_login[session['uuid']]["credentials"]["can_post"]:
                return True
    return False


def get_logged_in_user_name():
    if ('uuid' in session and session['uuid'] in flask_session_login and
            flask_session_login[session['uuid']]['logged_in']):
        return flask_session_login[session['uuid']]["credentials"]["id"]


def allowed_access(check, board_address=None):
    try:
        settings = GlobalSettings.query.first()

        if (not settings.enable_kiosk_mode and
                (check in ["is_global_admin",
                           "is_board_list_admin",
                           "can_verify",
                           "can_view",
                           "can_post",
                           "can_download"])):
            return True, ""

        elif check == "can_verify":
            if settings.enable_verification:
                return True, ""

        elif check == "can_view":
            if ((settings.enable_kiosk_mode and not settings.kiosk_login_to_view) or
                    (settings.enable_kiosk_mode and settings.kiosk_login_to_view and is_logged_in()) or
                    not settings.enable_kiosk_mode):
                return True, ""

        elif check == "can_download":
            if ((is_logged_in() and settings.kiosk_allow_download) or
                    (is_logged_in() and has_permission("is_global_admin"))):
                return True, ""

        elif check == "can_post":
            if ((not is_logged_in() and settings.kiosk_allow_posting) or
                    (is_logged_in() and has_permission("is_global_admin")) or
                    (is_logged_in() and has_permission("can_post"))):
                return True, ""

        elif check == "is_janitor":
            if is_logged_in() and has_permission("is_janitor"):
                return True, ""

        elif check == "is_global_admin":
            if is_logged_in() and has_permission("is_global_admin"):
                return True, ""

        elif check == "is_board_list_admin":
            admin_boards = has_permission("is_board_admin")
            if ((is_logged_in() and has_permission("is_global_admin")) or
                    is_logged_in() and
                    admin_boards and
                    type(admin_boards) == list and
                    board_address and
                    board_address in admin_boards):
                return True, ""

        if settings.kiosk_login_to_view and not is_logged_in():
            msg = 'Insufficient permissions to perform this action. ' \
                  '<a href="/login">Log in</a> with the proper credentials.'
            return False, msg

    except Exception as err:
        msg = "Login error: {}".format(err)
        return False, msg
    msg = 'Insufficient permissions to perform this action. ' \
          '<a href="/login">Log in</a> with the proper credentials.'
    return False, msg


def debug_info_post(message_id):
    msg = Messages.query.filter(
        Messages.message_id == message_id).first()
    if msg:
        debug_post_columns = [column.name for column in Messages.__mapper__.columns]
        debug_post_data = [getattr(msg, column.name) for column in Messages.__mapper__.columns]
        return debug_post_columns, debug_post_data
    return [], []


def debug_info_thread(thread_hash):
    thread = Threads.query.filter(
        Threads.thread_hash == thread_hash).first()
    if thread:
        debug_thread_columns = [column.name for column in Threads.__mapper__.columns]
        debug_thread_data = [getattr(thread, column.name) for column in Threads.__mapper__.columns]
        return debug_thread_columns, debug_thread_data
    return [], []


def debug_info_board(address):
    board = Chan.query.filter(
        Chan.address == address).first()
    if board:
        debug_board_columns = [column.name for column in Chan.__mapper__.columns]
        debug_board_data = [getattr(board, column.name) for column in Chan.__mapper__.columns]
        return debug_board_columns, debug_board_data
    return [], []


def wipe_time_left(epoch, show_seconds=True):
    now = time.time()
    distance = epoch - now
    if distance < 0:
        return "Expired"

    days = math.floor(distance / (60 * 60 * 24))
    hours = math.floor((distance % (60 * 60 * 24)) / (60 * 60))
    minutes = math.floor((distance % (60 * 60)) / 60)
    seconds = math.floor(distance % 60)

    str_return = ""
    if days:
        str_return += str(days)
        if days > 1:
            str_return += " Days, "
        else:
            str_return += " Day, "
    if hours or days:
        str_return += str(hours)
        if hours > 1:
            str_return += " Hours, "
        else:
            str_return += " Hour, "
    if minutes or hours or days:
        str_return += "{} Min".format(minutes)
    if show_seconds and (seconds or minutes or hours or days):
        str_return += ", {} Sec".format(seconds)
    return str_return


def get_theme():
    cookie_theme = request.cookies.get('theme')
    if not cookie_theme:
        cookie_theme = GlobalSettings.query.first().theme
    return cookie_theme


def page_dict():
    command_options = {}
    command_thread_options = {}
    unread_mail = 0

    # Get user options
    user_options = {
        "options_css": request.cookies.get('options_css', default=""),
        "options_js": request.cookies.get('options_js', default=""),
        "options_post_horizontal": request.cookies.get('options_post_horizontal'),
        "options_hide_authors": request.cookies.get('options_hide_authors')
    }

    admin_cmd = Command.query.filter(and_(
        Command.action == "set",
        Command.action_type == "options")).all()
    for each_cmd in admin_cmd:
        if each_cmd.chan_address and each_cmd.options:
            command_options[each_cmd.chan_address] = json.loads(each_cmd.options)

    admin_cmd = Command.query.filter(and_(
        Command.action == "set",
        Command.action_type == "thread_options")).all()
    for each_cmd in admin_cmd:
        if each_cmd.thread_id and each_cmd.options:
            command_thread_options[each_cmd.thread_id] = each_cmd

    for ident in Identity.query.all():
        if ident.unread_messages:
            unread_mail += ident.unread_messages

    all_chans = daemon_com.get_all_chans()
    identities = daemon_com.get_identities()
    address_labels = daemon_com.get_address_labels()
    address_book = OrderedDict(
        sorted(daemon_com.get_address_book().items(), key=lambda x: getitem(x[1], 'label')))

    chans_board_info = daemon_com.get_chans_board_info()
    for each_address in chans_board_info:
        chans_board_info[each_address]["db"] = Chan.query.filter(and_(
            Chan.address == each_address,
            Chan.type == "board")).first()

    chans_list_info = daemon_com.get_chans_list_info()
    for each_address in chans_list_info:
        chans_list_info[each_address]["db"] = Chan.query.filter(and_(
            Chan.address == each_address,
            Chan.type == "list")).first()

    return dict(and_=and_,
                address_book=address_book,
                address_labels=address_labels,
                all_chans=all_chans,
                allowed_access=allowed_access,
                attachment_info=attachment_info,
                bitmessage=daemon_com,
                chans_board_info=chans_board_info,
                chans_list_info=chans_list_info,
                command_options=command_options,
                command_thread_options=command_thread_options,
                config=config,
                custom_flags=Flags.query.all(),
                datetime=datetime,
                debug_info_board=debug_info_board,
                debug_info_post=debug_info_post,
                debug_info_thread=debug_info_thread,
                display_time=display_time,
                format_body=format_body,
                format_message_steg=format_message_steg,
                get_access=get_access,
                get_card_link_html=get_card_link_html,
                get_chan_mod_info=get_chan_mod_info,
                get_chan_passphrase=get_chan_passphrase,
                generate_post_html=generate_post_html,
                get_post_id=get_post_id,
                get_post_replies_dict=get_post_replies_dict,
                generate_reply_link_and_popup_html=generate_reply_link_and_popup_html,
                get_thread_options=get_thread_options,
                get_thread_subject=get_thread_subject,
                get_user_name=get_user_name,
                get_user_name_info=get_user_name_info,
                has_permission=has_permission,
                html=html,
                human_readable_size=human_readable_size,
                identities=identities,
                json=json,
                logged_in=is_logged_in(),
                message_has_images=message_has_images,
                nations=dict(nations),
                generate_popup_post_body_message=generate_popup_post_body_message,
                post_has_image=post_has_image,
                process_passphrase=process_passphrase,
                quote=quote,
                replace_lt_gt=replace_lt_gt,
                session=session,
                settings=GlobalSettings.query.first(),
                table_boards=Chan,
                table_messages=Messages,
                table_thread=Threads,
                get_theme=get_theme,
                themes=themes.themes,
                time=time,
                timestamp_to_date=timestamp_to_date,
                truncate=truncate,
                unread_mail=unread_mail,
                urlparse=urlparse,
                user_options=user_options,
                wipe_time_left=wipe_time_left)
