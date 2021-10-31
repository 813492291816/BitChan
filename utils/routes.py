import html
import json
import logging
import time
from collections import OrderedDict
from operator import getitem
from urllib.parse import quote
from urllib.parse import urlparse

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
from database.models import PostReplies
from database.models import Threads
from flask_routes import flask_session_login
from forms.nations import nations
from utils import themes
from utils.files import human_readable_size
from utils.general import display_time
from utils.general import process_passphrase
from utils.html_truncate import truncate
from utils.message_summary import attachment_info
from utils.message_summary import get_card_link_html
from utils.message_summary import get_post_id
from utils.message_summary import get_reply_link_html
from utils.message_summary import get_user_name
from utils.message_summary import message_has_images
from utils.message_summary import popup_message_content
from utils.message_summary import timestamp_to_date
from utils.replacements import format_body
from utils.replacements import replace_lt_gt
from utils.shared import get_access
from utils.shared import post_has_image

logger = logging.getLogger('bitchan.routes')
daemon_com = DaemonCom()


def get_post_replies_dict(message_id):
    dict_replies = OrderedDict()
    message = Messages.query.filter(
        Messages.message_id == message_id).first()
    if not message:
        return {}

    post_reply = PostReplies.query.filter(
        PostReplies.post_id == message.post_id).first()
    if post_reply:
        reply_ids = json.loads(post_reply.reply_ids)
    else:
        reply_ids = []

    for each_reply_id in reply_ids:
        reply = Messages.query.filter(
            Messages.message_id.endswith(each_reply_id.lower())).first()

        if (reply and reply.thread and reply.thread.chan and
                message.thread and message.thread.chan):

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
        elif permission == "can_post":
            if flask_session_login[session['uuid']]["credentials"]["can_post"]:
                return True
    return False


def allowed_access(
        check_is_global_admin=False,
        check_is_board_list_admin=False,
        check_admin_board=None,
        check_can_view=False,
        check_can_post=False,
        check_can_download=False):
    try:
        settings = GlobalSettings.query.first()

        if not settings.enable_kiosk_mode:
            return True, ""

        if check_can_view:
            if not settings.kiosk_login_to_view:
                return True, ""

        if check_can_download:
            if ((is_logged_in() and settings.kiosk_allow_download) or
                    (is_logged_in() and has_permission("is_global_admin"))):
                return True, ""

        if check_can_post:
            if ((not is_logged_in() and settings.kiosk_allow_posting) or
                    (is_logged_in() and has_permission("is_global_admin")) or
                    (is_logged_in() and has_permission("can_post"))):
                return True, ""

        if check_is_global_admin:
            if is_logged_in() and has_permission("is_global_admin"):
                return True, ""

        if check_is_board_list_admin:
            admin_boards = has_permission("is_board_admin")
            if ((is_logged_in() and has_permission("is_global_admin")) or
                    is_logged_in() and
                    admin_boards and
                    type(admin_boards) == list and
                    check_admin_board and
                    check_admin_board in admin_boards):
                return True, ""

        if settings.kiosk_login_to_view and not is_logged_in():
            msg = 'Insufficient permissions to perform this action. ' \
                  '<a href="/login">Log in</a> with the proper credentials.'
            return False, msg

        if ((is_logged_in() and has_permission("is_global_admin")) or
                (settings.kiosk_login_to_view and is_logged_in())):
            return True, ""
    except Exception as err:
        msg = "Login error: {}".format(err)
        return False, msg
    msg = 'Insufficient permissions to perform this action. ' \
          '<a href="/login">Log in</a> with the proper credentials.'
    return False, msg


def page_dict():
    command_options = {}
    command_thread_options = {}
    unread_mail = 0

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
                display_time=display_time,
                format_body=format_body,
                format_message_steg=format_message_steg,
                get_access=get_access,
                get_card_link_html=get_card_link_html,
                get_chan_mod_info=get_chan_mod_info,
                get_post_id=get_post_id,
                get_post_replies_dict=get_post_replies_dict,
                get_reply_link_html=get_reply_link_html,
                get_thread_options=get_thread_options,
                get_thread_subject=get_thread_subject,
                get_user_name=get_user_name,
                has_permission=has_permission,
                html=html,
                human_readable_size=human_readable_size,
                identities=identities,
                json=json,
                logged_in=is_logged_in(),
                message_has_images=message_has_images,
                nations=dict(nations),
                popup_message_content=popup_message_content,
                post_has_image=post_has_image,
                process_passphrase=process_passphrase,
                quote=quote,
                replace_lt_gt=replace_lt_gt,
                settings=GlobalSettings.query.first(),
                table_messages=Messages,
                themes=themes.themes,
                time=time,
                timestamp_to_date=timestamp_to_date,
                truncate=truncate,
                unread_mail=unread_mail,
                urlparse=urlparse)
