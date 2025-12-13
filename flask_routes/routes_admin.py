import base64
import html
import json
import logging
import os
import time
from io import BytesIO
from urllib.parse import unquote

import gnupg
from PIL import Image
from flask import redirect
from flask import render_template
from flask import request
from flask import send_file
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_
from sqlalchemy import or_

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Command
from database.models import Messages
from database.models import Threads
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_board
from forms import forms_settings
from utils.download import process_attachments
from utils.files import LF
from utils.files import generate_thumbnail_image
from utils.files import human_readable_size
from utils.gateway import api
from utils.gateway import delete_and_replace_comment
from utils.general import check_bm_address_csv_to_list
from utils.generate_popup import attachment_info
from utils.message_post import send_post_delete_request
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.posts import restore_post
from utils.posts import restore_thread
from utils.routes import allowed_access
from utils.routes import ban_and_delete
from utils.routes import get_logged_in_user_name
from utils.routes import page_dict
from utils.shared import add_mod_log_entry
from utils.shared import get_access
from utils.shared import regenerate_card_popup_post_html

logger = logging.getLogger('bitchan.routes_admin')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_admin',
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


@blueprint.route('/mod_thread/<address>/<thread_id>/<mod_type>', methods=('GET', 'POST'))
@count_views
def mod_thread(address, thread_id, mod_type):
    """
    Locally/remotely modify a thread or post
    """
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_confirm = forms_board.Confirm()

    message_id = None
    chan = Chan.query.filter(Chan.address == address).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    from_list = daemon_com.get_from_list(address, only_owner_admin=True)

    if not thread:
        return "Thread doesn't exist"

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action=mod_type,
                               chan=chan,
                               current_chan=address,
                               from_list=from_list,
                               thread=thread,
                               thread_id=thread_id,
                               mod_type=mod_type)

    board = {
        "current_chan": chan,
        "current_thread": thread_id
    }
    status_msg = {"status_message": []}
    url = "/thread/{}/{}".format(address, thread.thread_hash_short)
    url_text = "Thread: {}".format(thread.subject)

    try:
        #
        # Send message to remotely sticky/unsticky thread
        #
        if mod_type in ["thread_sticky_remote",
                        "thread_unsticky_remote",
                        "thread_lock_remote",
                        "thread_unlock_remote",
                        "thread_anchor_remote",
                        "thread_unanchor_remote"]:
            dict_message = {
                "version": config.VERSION_MSG,
                "timestamp_utc": daemon_com.get_utc(),
                "message_type": "admin",
                "chan_type": "board",
                "action": "set",
                "action_type": "thread_options",
                "thread_id": thread_id,
                "options": {}
            }

            if not form_confirm.address.data:
                status_msg['status_message'].append("From address required")
                status_msg['status_title'] = "Error"

            if not status_msg['status_message']:
                # Set options to send
                if mod_type in ["thread_sticky_remote", "thread_unsticky_remote"]:
                    dict_message["options"]["sticky"] = bool(mod_type == "thread_sticky_remote")
                    if mod_type == "thread_sticky_remote":
                        status_msg['status_message'].append("Remotely stickied thread: '{}'".format(thread.subject))
                        status_msg['status_title'] = "Remotely stickied thread"
                    else:
                        status_msg['status_message'].append("Remotely unstickied thread: '{}'".format(thread.subject))
                        status_msg['status_title'] = "Remotely unstickied thread"

                elif mod_type in ["thread_lock_remote", "thread_unlock_remote"]:
                    dict_message["options"]["lock"] = bool(mod_type == "thread_lock_remote")
                    dict_message["options"]["lock_ts"] = time.time()
                    if mod_type == "thread_lock_remote":
                        status_msg['status_message'].append("Remotely locked thread: '{}'".format(thread.subject))
                        status_msg['status_title'] = "Remotely locked thread"
                    else:
                        status_msg['status_message'].append("Remotely unlocked thread: '{}'".format(thread.subject))
                        status_msg['status_title'] = "Remotely unlocked thread"

                elif mod_type in ["thread_anchor_remote", "thread_unanchor_remote"]:
                    dict_message["options"]["anchor"] = bool(mod_type == "thread_anchor_remote")
                    dict_message["options"]["anchor_ts"] = time.time()
                    if mod_type == "thread_anchor_remote":
                        status_msg['status_message'].append("Remotely anchored thread: '{}'".format(thread.subject))
                        status_msg['status_title'] = "Remotely anchored thread"
                    else:
                        status_msg['status_message'].append("Remotely unanchored thread: '{}'".format(thread.subject))
                        status_msg['status_title'] = "Remotely unanchored thread"

                pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                chan = Chan.query.filter(Chan.address == address).first()
                if chan and chan.pgp_passphrase_msg:
                    pgp_passphrase_msg = chan.pgp_passphrase_msg

                str_message = json.dumps(dict_message)
                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    str_message, symmetric="AES256", passphrase=pgp_passphrase_msg, recipients=None)
                message_send = base64.b64encode(message_encrypted.data).decode()

                # Don't allow a message to send while Bitmessage is restarting
                allow_send = False
                timer = time.time()
                while not allow_send:
                    if daemon_com.bitmessage_restarting() is False:
                        allow_send = True
                    if time.time() - timer > config.BM_WAIT_DELAY:
                        logger.error(
                            "{}: Unable to send message: "
                            "Could not detect Bitmessage running.".format(thread_id[0:6]))
                        return
                    time.sleep(1)

                if allow_send:
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                        try:
                            return_str = api.sendMessage(
                                address,
                                form_confirm.address.data,
                                "",
                                message_send,
                                2,
                                config.BM_TTL)
                            if return_str:
                                logger.info("{}: Message to globally {} sent from {} to {}".format(
                                    thread_id[0:6], mod_type, form_confirm.address.data, address))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)

    except Exception as err:
        logger.error("Exception while deleting message(s): {}".format(err))

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/bulk_delete_thread/<address>', methods=('GET', 'POST'))
@count_views
def bulk_delete_thread(address):
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    if not global_admin and not board_list_admin:
        return allow_msg

    if address != "0":
        board = Chan.query.filter(Chan.address == address).first()
        threads = board.threads
    else:
        board = "0"
        threads = Threads.query.limit(100).all()

    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    if request.method == 'POST':
        try:
            delete_bulk_thread_hashes = []
            for each_input in request.form:
                if each_input.startswith("deletethreadbulk_"):
                    delete_bulk_thread_hashes.append(each_input.split("_")[1])

            try:
                for each_thread_hash in delete_bulk_thread_hashes:
                    thread = Threads.query.filter(
                        Threads.thread_hash == each_thread_hash).first()
                    if thread:
                        list_delete_message_ids = []
                        for message in thread.messages:
                            list_delete_message_ids.append(message.message_id)

                        # First, delete messages from database
                        for each_id in list_delete_message_ids:
                            delete_post(each_id)

                        # Next, delete thread from DB
                        delete_thread(each_thread_hash)
                        status_msg['status_message'].append("Thread deleted: {}".format(thread.subject))
            except Exception as err:
                logger.error("Exception while deleting message(s): {}".format(err))

            status_msg['status_title'] = "Success"
            status_msg['status_title'] = "Deleted Thread"
        except:
            logger.exception("/bulk_delete_thread")

    return render_template("pages/bulk_delete_threads.html",
                           board=board,
                           status_msg=status_msg,
                           threads=threads,
                           url=url,
                           url_text=url_text)


@blueprint.route('/b64_to_img/<str_b64>')
@count_views
def b64_to_img(str_b64):
    can_post, allow_msg = allowed_access("can_post")
    can_view, allow_msg = allowed_access("can_view")
    if not can_post and not can_view:
        return allow_msg

    return send_file(BytesIO(base64.b64decode(str_b64.replace("-", "/"))), mimetype="image/jpeg")


@blueprint.route('/delete_post_with_password/<address>/<message_id>/<thread_id>', methods=('GET', 'POST'))
@count_views
def delete_post_with_password(address, message_id, thread_id):
    """Delete a post with a password"""
    can_post, allow_msg = allowed_access("can_post")
    can_view, allow_msg = allowed_access("can_view")
    if not can_post and not can_view:
        return allow_msg

    form_confirm = forms_board.Confirm()

    chan = Chan.query.filter(Chan.address == address).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()
    message = Messages.query.filter(Messages.message_id == message_id).first()

    from_list = daemon_com.get_from_list(address, all_addresses=True)

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action="delete_post_with_password",
                               chan=chan,
                               current_chan=address,
                               from_list=from_list,
                               message=message,
                               message_id=message_id,
                               thread=thread,
                               thread_id=thread_id)

    board = {
        "current_chan": chan,
        "current_thread": thread_id
    }
    status_msg = {"status_message": []}

    if message_id == "0":
        message_id = None

    url = "/thread/{}/{}".format(address, thread_id)
    url_text = "{}".format(thread.subject)

    try:
        if not form_confirm.address.data:
            status_msg['status_message'].append("From address required")

        if not form_confirm.text.data:
            status_msg['status_message'].append("Password required")

        message = Messages.query.filter(Messages.message_id == message_id).first()
        if not message:
            status_msg['status_message'].append("Message not found")

        if message and not message.thread:
            status_msg['status_message'].append("Thread not found")

        if not status_msg['status_message']:
            send_post_delete_request(
                form_confirm.address.data,
                address,
                message_id,
                message.thread.thread_hash,
                form_confirm.text.data)
            status_msg['status_message'].append(
                "Remotely send request to delete post with password in thread '{}'".format(thread.subject))
            status_msg['status_title'] = "Success"

    except Exception as err:
        logger.error("Exception while deleting message(s): {}".format(err))

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/delete_thread_post/<address>/<message_id>/<thread_id>/<delete_type>', methods=('GET', 'POST'))
@count_views
def delete(address, message_id, thread_id, delete_type):
    """
    Owners and Admins can delete messages and threads

    delete_type can be:
    post: delete post from local instance
    posts_all: delete post for all users (must be owner or admin)
    thread: delete thread from local instance
    thread_all: delete thread for all users (must be owner or admin)
    """
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    janitor, allow_msg = allowed_access("is_janitor")
    if not global_admin and not board_list_admin and not janitor:
        return allow_msg

    form_confirm = forms_board.Confirm()

    chan = Chan.query.filter(Chan.address == address).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()
    message = Messages.query.filter(Messages.message_id == message_id).first()

    from_list = daemon_com.get_from_list(address, only_owner_admin=True)

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action=delete_type,
                               chan=chan,
                               current_chan=address,
                               from_list=from_list,
                               message=message,
                               message_id=message_id,
                               thread=thread,
                               thread_id=thread_id)

    board = {
        "current_chan": chan,
        "current_thread": thread_id
    }
    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    if message_id == "0":
        message_id = None

    if delete_type in ["delete_post", "delete_post_all"]:
        url = "/thread/{}/{}".format(address, thread_id)
        url_text = "{}".format(thread.subject)

    try:
        thread_arch = Threads.query.filter(
            and_(Threads.thread_hash == thread_id, Threads.archived.is_(True))).first()
        message_arch = Messages.query.join(Threads).filter(
            and_(Messages.message_id == message_id, Threads.archived.is_(True))).first()

        if thread_arch or message_arch:
            status_msg['status_message'].append("Cannot delete Archived thread or post. Unarchive before deleting.")

        elif delete_type in ["delete_post", "delete_thread"]:
            only_hide = False
            if janitor:
                only_hide = True

            list_delete_message_ids = []
            if delete_type == "delete_thread" and thread:
                board["current_thread"] = None
                for message in thread.messages:
                    list_delete_message_ids.append(message.message_id)
            elif delete_type == "delete_post":
                list_delete_message_ids.append(message_id)

            log_description = ""
            if delete_type == "delete_post":
                if janitor:
                    log_description = 'Janitor: Locally delete (locally hide) post from thread "{}"'.format(thread.subject)
                else:
                    log_description = 'Locally delete post from thread "{}"'.format(thread.subject)
            elif delete_type == "delete_thread":
                if janitor:
                    log_description = 'Janitor: Locally delete (locally hide) thread "{}"'.format(thread.subject)
                else:
                    log_description = 'Locally delete thread "{}"'.format(thread.subject)

            status_msg['status_message'].append(log_description)
            status_msg['status_title'] = "Success"

            # If local, first delete messages
            if list_delete_message_ids:
                for each_id in list_delete_message_ids:
                    delete_post(each_id, only_hide=only_hide)

            # If local, next delete thread
            if delete_type == "delete_thread" and thread:
                delete_thread(thread_id, only_hide=only_hide)

            # Find if any admin commands exist for deleting this post or thread
            # If so, add override to indicate local action has been taken to restore or delete
            admin_cmd = Command.query.filter(and_(
                Command.chan_address == address,
                Command.action == "delete",
                or_(Command.action_type == "delete_post",
                    Command.action_type == "delete_thread"))).all()
            for each_cmd in admin_cmd:
                try:
                    options = json.loads(each_cmd.options)
                except:
                    options = {}
                if (
                        ("delete_thread" in options and
                         "thread_id" in options["delete_thread"] and
                         options["delete_thread"]["thread_id"] == thread_id)
                        or
                        ("delete_post" in options and
                         "message_id" in options["delete_post"] and
                         options["delete_thread"]["message_id"] == message_id)
                        ):
                    admin_cmd.locally_deleted = True
                    admin_cmd.save()
                    break

            user_from_tmp = get_logged_in_user_name()
            user_from = user_from_tmp if user_from_tmp else None

            add_mod_log_entry(
                log_description,
                message_id=message_id,
                user_from=user_from,
                board_address=address,
                thread_hash=thread_id)

            # Allow messages to be deleted in bitmessage before allowing bitchan to rescan inbox
            time.sleep(1)

        # Send message to remotely delete post/thread
        elif delete_type in ["delete_post_all", "delete_thread_all"]:
            if not global_admin and not board_list_admin:
                return allow_msg

            if not form_confirm.address.data and delete_type in ["delete_thread_all", "delete_post_all"]:
                status_msg['status_message'].append("From address required")

            if not status_msg['status_message']:
                if delete_type == "delete_post_all":
                    status_msg['status_message'].append("Remotely deleted post from thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Success"
                elif delete_type == "delete_thread_all":
                    status_msg['status_message'].append("Remotely deleted thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Success"

                dict_message = {
                    "version": config.VERSION_MSG,
                    "timestamp_utc": daemon_com.get_utc(),
                    "message_type": "admin",
                    "chan_type": "board",
                    "action": "delete",
                    "options": {}
                }
                if delete_type == "delete_post_all":
                    dict_message["action_type"] = "delete_post"
                    dict_message["options"]["delete_post"] = {
                        "thread_id": thread_id,
                        "message_id": message_id
                    }
                elif delete_type == "delete_thread_all":
                    dict_message["action_type"] = "delete_thread"
                    dict_message["options"]["delete_thread"] = {
                        "thread_id": thread_id,
                        "message_id": None
                    }

                pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                chan = Chan.query.filter(Chan.address == address).first()
                if chan and chan.pgp_passphrase_msg:
                    pgp_passphrase_msg = chan.pgp_passphrase_msg

                str_message = json.dumps(dict_message)
                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    str_message, symmetric="AES256", passphrase=pgp_passphrase_msg, recipients=None)
                message_send = base64.b64encode(message_encrypted.data).decode()

                # Don't allow a message to send while Bitmessage is restarting
                allow_send = False
                timer = time.time()
                while not allow_send:
                    if daemon_com.bitmessage_restarting() is False:
                        allow_send = True
                    if time.time() - timer > config.BM_WAIT_DELAY:
                        logger.error(
                            "{}: Unable to send message: "
                            "Could not detect Bitmessage running.".format(thread_id[0:6]))
                        return
                    time.sleep(1)

                if allow_send:
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                        try:
                            return_str = api.sendMessage(
                                address,
                                form_confirm.address.data,
                                "",
                                message_send,
                                2,
                                config.BM_TTL)
                            if return_str:
                                logger.info("{}: Message to globally delete {} sent from {} to {}".format(
                                    thread_id[0:6], delete_type, form_confirm.address.data, address))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)

        else:
            status_msg['status_message'].append(f"Unrecognized option: {delete_type}")

    except Exception as err:
        logger.error("Exception while deleting message(s): {}".format(err))
        status_msg['status_message'].append(f"Exception: {err}")

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/thread_attributes/<address>/<thread_id>', methods=('GET', 'POST'))
@count_views
def thread_attributes(address, thread_id):
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    if not global_admin and not board_list_admin:
        return allow_msg

    chan = Chan.query.filter(Chan.address == address).first()

    if len(thread_id) == 12:
        thread = Threads.query.filter(Threads.thread_hash_short == thread_id).first()
    else:
        thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    user_from_tmp = get_logged_in_user_name()
    user_from = user_from_tmp if user_from_tmp else None

    # Ensure message, thread, board is valid
    if not chan or not thread:
        return "thread or board doesn't exist"

    # Ensure message is from specified board address
    if thread.chan.address != address:
        return "Board addresses do not match thread"

    status_msg = {"status_message": []}

    form_thread_attributes = forms_board.ThreadAttributes()

    if request.method == 'POST':
        if form_thread_attributes.save_attributes.data:
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(f"Set thread attributes.")

            if thread.locked_local != bool(form_thread_attributes.thread_lock.data):
                if thread.archived and bool(form_thread_attributes.thread_archive.data) and not bool(form_thread_attributes.thread_lock.data):
                    status_msg['status_message'].append(f"Cannot unlock thread if it's archived.")
                else:
                    thread.locked_local = form_thread_attributes.thread_lock.data
                    thread.save()

                    regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

                    if thread.locked_local:
                        log_description = "Locally locked thread"
                        status_msg['status_message'].append(" Locally locked thread.")
                    else:
                        log_description = "Locally unlocked thread"
                        status_msg['status_message'].append(" Locally unlocked thread.")

                    add_mod_log_entry(
                        log_description,
                        message_id=None,
                        user_from=user_from,
                        board_address=address,
                        thread_hash=thread_id)

            if thread.anchored_local != bool(form_thread_attributes.thread_anchor.data):
                thread.anchored_local = form_thread_attributes.thread_anchor.data
                thread.save()

                regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

                if thread.anchored_local:
                    log_description = "Locally anchored thread"
                    status_msg['status_message'].append(" Locally anchored thread.")
                else:
                    log_description = "Locally unanchored thread"
                    status_msg['status_message'].append(" Locally unanchored thread.")

                add_mod_log_entry(
                    log_description,
                    message_id=None,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=thread_id)

            if thread.stickied_local != bool(form_thread_attributes.thread_sticky.data):
                thread.stickied_local = form_thread_attributes.thread_sticky.data
                thread.save()

                regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

                if thread.stickied_local:
                    log_description = "Locally stickied thread"
                    status_msg['status_message'].append(" Locally stickied thread.")
                else:
                    log_description = "Locally unstickied thread"
                    status_msg['status_message'].append(" Locally unstickied thread.")

                add_mod_log_entry(
                    log_description,
                    message_id=None,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=thread_id)

            if thread.archived != bool(form_thread_attributes.thread_archive.data):
                thread.archived = form_thread_attributes.thread_archive.data
                thread.archive_epoch = time.time()
                thread.locked_local = True
                thread.save()

                regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

                if thread.archived:
                    log_description = "Locally locked and archived thread"
                    status_msg['status_message'].append(" Locally locked and archived thread.")
                else:
                    log_description = "Locally unarchived thread"
                    status_msg['status_message'].append(" Locally unarchived thread.")

                add_mod_log_entry(
                    log_description,
                    message_id=None,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=thread_id)

            if thread.hide != bool(form_thread_attributes.thread_hide.data):
                thread.hide = form_thread_attributes.thread_hide.data
                thread.save()

                regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

                if thread.hide:
                    log_description = "Locally hid thread"
                    status_msg['status_message'].append(" Locally hid thread.")
                else:
                    # Find if any admin commands exist for deleting this post or thread
                    # If so, add override to indicate local action has been taken to restore or delete
                    admin_cmd = Command.query.filter(and_(
                        Command.chan_address == address,
                        Command.action == "delete",
                        Command.action_type == "delete_thread")).all()
                    for each_cmd in admin_cmd:
                        try:
                            options = json.loads(each_cmd.options)
                        except:
                            options = {}
                        if (
                                ("delete_thread" in options and
                                 "thread_id" in options["delete_thread"] and
                                 options["delete_thread"]["thread_id"] == thread_id)
                        ):
                            admin_cmd.locally_restored = True
                            admin_cmd.save()
                            break

                    log_description = "Locally unhid thread"
                    status_msg['status_message'].append(" Locally unhid thread.")

                add_mod_log_entry(
                    log_description,
                    message_id=None,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=thread_id)

            if thread.favorite != bool(form_thread_attributes.thread_favorite.data):
                thread.favorite = form_thread_attributes.thread_favorite.data
                thread.save()

                regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

                if thread.favorite:
                    log_description = "Locally favorited thread"
                    status_msg['status_message'].append(" Locally favorited thread.")
                else:
                    log_description = "Locally unfavorited thread"
                    status_msg['status_message'].append(" Locally unfavorited thread.")

                add_mod_log_entry(
                    log_description,
                    message_id=None,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=thread_id)

            if thread.post_max_height_local != bool(form_thread_attributes.thread_max_height.data):
                thread.post_max_height_local = form_thread_attributes.thread_max_height.data
                thread.save()

                regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

                if thread.post_max_height_local:
                    log_description = "Locally set max height for thread posts"
                    status_msg['status_message'].append(" Locally set max height for thread posts.")
                else:
                    log_description = "Locally unset max height for thread posts"
                    status_msg['status_message'].append(" Locally unset max height for thread posts.")

                add_mod_log_entry(
                    log_description,
                    message_id=None,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=thread_id)

        if 'status_title' not in status_msg:
            status_msg['status_title'] = "Error"

    return render_template("pages/attributes_local_thread.html",
                           board_address=address,
                           form_thread_attributes=form_thread_attributes,
                           status_msg=status_msg,
                           thread=thread)


@blueprint.route('/post_attributes/<address>/<message_id>', methods=('GET', 'POST'))
@count_views
def post_attributes(address, message_id):
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    if not global_admin and not board_list_admin:
        return allow_msg

    chan = Chan.query.filter(Chan.address == address).first()

    message = Messages.query.filter(Messages.message_id == message_id).first()

    user_from_tmp = get_logged_in_user_name()
    user_from = user_from_tmp if user_from_tmp else None

    # Ensure message, thread, board is valid
    if not chan or not message:
        return "post or board doesn't exist"

    # Ensure message is from specified board address
    if message.thread.chan.address != address:
        return "Board addresses do not match thread"

    status_msg = {"status_message": []}

    form_attributes = forms_board.PostAttributes()

    if request.method == 'POST':
        if form_attributes.save_attributes.data:
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(f"Set post attributes.")

            if message.hide != bool(form_attributes.post_hide.data):
                message.hide = form_attributes.post_hide.data
                message.save()

                regenerate_card_popup_post_html(message_id=message_id)

                if message.hide:
                    log_description = "Locally hid post"
                    status_msg['status_message'].append(" Locally hid post.")
                else:
                    # Find if any admin commands exist for deleting this post or thread
                    # If so, add override to indicate local action has been taken to restore or delete
                    admin_cmd = Command.query.filter(and_(
                        Command.chan_address == address,
                        Command.action == "delete",
                        Command.action_type == "delete_post")).all()
                    for each_cmd in admin_cmd:
                        try:
                            options = json.loads(each_cmd.options)
                        except:
                            options = {}
                        if (
                                ("delete_post" in options and
                                 "message_id" in options["delete_post"] and
                                 options["delete_thread"]["message_id"] == message_id)
                        ):
                            admin_cmd.locally_restored = True
                            admin_cmd.save()
                            break

                    log_description = "Locally unhid post"
                    status_msg['status_message'].append(" Locally unhid post.")

                add_mod_log_entry(
                    log_description,
                    message_id=message.id,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=message.thread.thread_hash)

            if message.favorite != bool(form_attributes.post_favorite.data):
                message.favorite = form_attributes.post_favorite.data
                message.save()

                regenerate_card_popup_post_html(message_id=message_id)

                if message.favorite:
                    log_description = "Locally favorited post"
                    status_msg['status_message'].append(" Locally favorited post.")
                else:
                    log_description = "Locally unfavorited post"
                    status_msg['status_message'].append(" Locally unfavorited post.")

                add_mod_log_entry(
                    log_description,
                    message_id=message.id,
                    user_from=user_from,
                    board_address=address,
                    thread_hash=message.thread.thread_hash)

        if 'status_title' not in status_msg:
            status_msg['status_title'] = "Error"

    return render_template("pages/attributes_local_post.html",
                           board_address=address,
                           form_attributes=form_attributes,
                           message=message,
                           status_msg=status_msg)


@blueprint.route('/attachment_options/<address>/<message_id>/<single_file>/<file_name>', methods=('GET', 'POST'))
@count_views
def attachment_options(address, message_id, single_file, file_name):
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    if not global_admin and not board_list_admin:
        return allow_msg

    message = Messages.query.filter(Messages.message_id == message_id).first()

    # Ensure message, thread, board is valid
    if not message or not message.thread or not message.thread.chan:
        return "Message, thread, or board doesn't exist"

    # Ensure message is from specified board address
    if message.thread.chan.address != address:
        return "Board addresses do not match"

    dict_files = {}
    list_filenames = []

    only_board_address = None
    if global_admin:
        pass
    elif board_list_admin:
        only_board_address = address

    user_name = get_logged_in_user_name()
    admin_name = user_name if user_name else "LOCAL ADMIN"

    form_diag = forms_settings.Diag()

    file_order, attach, number_files = attachment_info(message_id)

    # Determine if a single or multiple files are being considered
    if single_file == "1":
        file_name = unquote(file_name)
        if file_name in attach:
            list_filenames.append(file_name)
            dict_files[file_name] = attach[file_name]
            dict_files[file_name]["number"] = attach[file_name]["file_number"]
    else:
        for i, each_file in enumerate(file_order):
            if each_file is None:
                continue
            list_filenames.append(each_file)
            dict_files[each_file] = attach[each_file]
            dict_files[each_file]["number"] = i + 1

    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    if request.method == 'POST':
        if form_diag.save_attachment_options.data:
            dict_options = {}
            file_num = []

            # Get number of files
            for each_name in request.form:
                if each_name.startswith("hashname_"):
                    file_num.append(each_name.split("_")[1])
                    dict_options[each_name.split("_")[1]] = {}

            list_keys = [
                "hashname",
                "boardaddress",
                "ban",
                "deleteposts",
                "deletethreads",
                "thumbb64",
                "thumbb64blur",
                "storethumb",
                "blurthumb",
                "sha256_hash",
                "imagehash_hash",
                "spoiler"
            ]

            # Get options for each file
            for each_num in file_num:
                for each_key in list_keys:
                    if f"{each_key}_{each_num}" in request.form:
                        dict_options[each_num][each_key] = request.form.get(f"{each_key}_{each_num}")
                    else:
                        dict_options[each_num][each_key] = None

            # Check if each file should be banned
            spoiler_changed = False
            for each_num in dict_options:
                try:
                    if dict_options[each_num]['ban']:
                        if not dict_options[each_num]['sha256_hash'] and not dict_options[each_num]['imagehash']:
                            status_msg['status_message'].append("A hash is required.")
                        else:
                            if dict_options[each_num]['blurthumb']:
                                thumb_b64 = unquote(dict_options[each_num]['thumbb64blur'].replace("-", "/"))
                            else:
                                thumb_b64 = unquote(dict_options[each_num]['thumbb64'].replace("-", "/"))

                            board_address = None
                            if only_board_address:
                                board_address = only_board_address
                            elif dict_options[each_num]['boardaddress']:
                                board_address = dict_options[each_num]['boardaddress']

                            ban_and_delete(
                                sha256_hash=dict_options[each_num]['sha256_hash'],
                                imagehash_hash=dict_options[each_num]['imagehash_hash'],
                                name=dict_options[each_num]['hashname'],
                                delete_posts=dict_options[each_num]['deleteposts'],
                                delete_threads=dict_options[each_num]['deletethreads'],
                                store_thumbnail_b64=thumb_b64,
                                user_name=admin_name,
                                only_board_address=board_address)

                            status_msg['status_message'].append(
                                f"Banned file with hash: "
                                f"{dict_options[each_num]['hashname']}, "
                                f"{dict_options[each_num]['imagehash_hash']}, "
                                f"{dict_options[each_num]['sha256_hash']}.")

                    # Check if message has been deleted
                    if not Messages.query.filter(Messages.message_id == message_id).first():
                        continue

                    this_spoiler_changed = False
                    if each_num == "1" and bool(message.image1_spoiler) != bool(dict_options[each_num]['spoiler']):
                        message.image1_spoiler = bool(dict_options[each_num]['spoiler'])
                        this_spoiler_changed = True
                    elif each_num == "2" and bool(message.image2_spoiler) != bool(dict_options[each_num]['spoiler']):
                        message.image2_spoiler = bool(dict_options[each_num]['spoiler'])
                        this_spoiler_changed = True
                    elif each_num == "3" and bool(message.image3_spoiler) != bool(dict_options[each_num]['spoiler']):
                        message.image3_spoiler = bool(dict_options[each_num]['spoiler'])
                        this_spoiler_changed = True
                    elif each_num == "4" and bool(message.image4_spoiler) != bool(dict_options[each_num]['spoiler']):
                        message.image4_spoiler = bool(dict_options[each_num]['spoiler'])
                        this_spoiler_changed = True
                    if this_spoiler_changed:
                        spoiler_changed = True
                        status_msg['status_message'].append(
                            f"Image {each_num} spoiler changed to: {bool(dict_options[each_num]['spoiler'])}.")

                except Exception as err:
                    status_msg['status_message'].append(f"Couldn't apply attachment options: {err}")
                    logger.exception(f"Couldn't apply attachment options")

            # If spoiler changed and message still exists
            if spoiler_changed and Messages.query.filter(Messages.message_id == message_id).first():
                message.save()
                extract_path = "{}/{}".format(config.FILE_DIRECTORY, message.message_id)
                errors_files, media_info, message_steg = process_attachments(
                    message.message_id, extract_path, progress=False, overwrite_thumbs=True)
                for each_err in errors_files:
                    status_msg['status_message'].append(f"Error: {each_err}.")
                regenerate_card_popup_post_html(message_id=message.message_id)

            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(
                f"All chosen attachment options applied.")

        if 'status_title' not in status_msg:
            status_msg['status_title'] = "Error"

        return render_template("pages/alert.html",
                               board=None,
                               status_msg=status_msg,
                               url=url,
                               url_text=url_text)

    # Generate base64 thumbnails for each image attachment
    for each_file in list_filenames:
        file_path_full = os.path.join(f"{config.FILE_DIRECTORY}/{message_id}", each_file)
        dict_files[each_file]['thumb_b64'] = generate_thumbnail_image(
            message_id, file_path_full, None, dict_files[each_file]["extension"],
            size_x=30, size_y=30, blur=False, return_b64=True)
        if dict_files[each_file]['thumb_b64']:
            dict_files[each_file]['thumb_b64'] = dict_files[each_file]['thumb_b64'].decode().replace("/", "-")
        dict_files[each_file]['thumb_b64_blur'] = generate_thumbnail_image(
            message_id, file_path_full, None, dict_files[each_file]["extension"],
            size_x=30, size_y=30, blur=True, return_b64=True)
        if dict_files[each_file]['thumb_b64_blur']:
            dict_files[each_file]['thumb_b64_blur'] = dict_files[each_file]['thumb_b64_blur'].decode().replace("/", "-")

    return render_template("pages/attachment_options.html",
                           board_address=address,
                           message_id=message_id,
                           only_board_address=only_board_address,
                           status_msg=status_msg,
                           dict_files=dict_files,
                           url=url,
                           url_text=url_text)


@blueprint.route('/delete_with_comment_local/<address>/<message_id>/<thread_id>', methods=('GET', 'POST'))
@count_views
def delete_with_comment_local(address, message_id, thread_id):
    """Locally delete post with comment"""
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    janitor, allow_msg = allowed_access("is_janitor")
    if not global_admin and not board_list_admin and not janitor:
        return allow_msg

    form_del_com = forms_board.DeleteComment()
    chan = Chan.query.filter(Chan.address == address).first()

    from_list = daemon_com.get_from_list(address, all_addresses=True)

    board = {
        "current_chan": chan,
        "current_message_id": message_id,
        "current_thread": thread_id
    }
    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    if request.method == 'POST':
        if not form_del_com.delete_comment.data:
            status_msg['status_message'].append("A comment is required.")

        elif form_del_com.send.data:
            # Find if thread/post exist and delete
            if not chan:
                logger.error("{}: Can't locally delete post with comment: Unknown board".format(
                    message_id[-config.ID_LENGTH:].upper()))
            else:
                user_from = None
                if janitor:
                    only_hide = True
                    user_from = get_logged_in_user_name()
                else:
                    only_hide = False
                    if not form_del_com.address.data:
                        status_msg['status_message'].append("A from address is required.")
                    else:
                        user_from = form_del_com.address.data

                if not status_msg['status_message']:
                    # Find if any admin commands exist for deleting this post or thread
                    # If so, add override to indicate local action has been taken to restore or delete
                    admin_cmd = Command.query.filter(and_(
                        Command.chan_address == address,
                        Command.action == "delete_comment",
                        Command.action_type == "post")).all()
                    for each_cmd in admin_cmd:
                        try:
                            options = json.loads(each_cmd.options)
                        except:
                            options = {}
                        if ("delete_comment" in options and
                                "message_id" in options["delete_comment"] and
                                "comment" in options["delete_comment"] and
                                options["delete_comment"]["message_id"] == message_id):
                            admin_cmd.locally_deleted = True
                            admin_cmd.save()
                            break

                    delete_and_replace_comment(
                        message_id,
                        form_del_com.delete_comment.data,
                        local_delete=True,
                        from_address=user_from,
                        only_hide=only_hide)

                    status_msg['status_message'].append(
                        "Message locally deleted from post and replaced with comment: '{}'".format(
                            form_del_com.delete_comment.data))
                    status_msg['status_title'] = "Deleted Message with Comment"

                    url = "/thread/{}/{}".format(address, thread_id)
                    url_text = "Return to Thread"

                    return render_template("pages/alert.html",
                                           board=board,
                                           status_msg=status_msg,
                                           url=url,
                                           url_text=url_text)

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/delete_comment.html",
                           board=board,
                           from_list=from_list,
                           local_delete=True,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/delete_with_comment/<address>/<message_id>/<thread_id>', methods=('GET', 'POST'))
@count_views
def delete_with_comment(address, message_id, thread_id):
    """Globally delete post with comment"""
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=address)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_del_com = forms_board.DeleteComment()
    chan = Chan.query.filter(Chan.address == address).first()

    from_list = daemon_com.get_from_list(address, only_owner_admin=True)

    board = {
        "current_chan": chan,
        "current_thread": thread_id,
    }
    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    if request.method == 'POST':
        if not form_del_com.delete_comment.data:
            status_msg['status_message'].append("A comment is required.")

        if not form_del_com.address.data:
            status_msg['status_message'].append("A from address is required.")

        if form_del_com.send.data and not status_msg['status_message']:
            try:
                # Send message to remotely delete post with comment
                dict_message = {
                    "version": config.VERSION_MSG,
                    "timestamp_utc": daemon_com.get_utc(),
                    "message_type": "admin",
                    "chan_type": "board",
                    "action": "delete_comment",
                    "action_type": "post",
                    "options": {
                        "delete_comment": {
                            "comment": form_del_com.delete_comment.data,
                            "message_id": message_id
                        }
                    }
                }

                pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                chan = Chan.query.filter(Chan.address == address).first()
                if chan and chan.pgp_passphrase_msg:
                    pgp_passphrase_msg = chan.pgp_passphrase_msg

                str_message = json.dumps(dict_message)
                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    str_message, symmetric="AES256", passphrase=pgp_passphrase_msg, recipients=None)
                message_send = base64.b64encode(message_encrypted.data).decode()

                # Don't allow a message to send while Bitmessage is restarting
                allow_send = False
                timer = time.time()
                while not allow_send:
                    if daemon_com.bitmessage_restarting() is False:
                        allow_send = True
                    if time.time() - timer > config.BM_WAIT_DELAY:
                        logger.error(
                            "{}: Unable to send message: "
                            "Could not detect Bitmessage running.".format(thread_id[0:6]))
                        return
                    time.sleep(1)

                if allow_send:
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                        try:
                            return_str = api.sendMessage(
                                address,
                                form_del_com.address.data,
                                "",
                                message_send,
                                2,
                                config.BM_TTL)
                            if return_str:
                                logger.info("{}: Message to globally delete with comment sent from {} to {}. "
                                            "The message will need to propagate through the network before "
                                            "the changes are reflected on the board.".format(
                                                thread_id[0:6], form_del_com.address.data, address))

                            status_msg['status_message'].append(
                                "Message deleted from post and replaced with comment: '{}'".format(
                                    form_del_com.delete_comment.data))
                            status_msg['status_title'] = "Deleted Message with Comment"

                            url = "/thread/{}/{}".format(address, thread_id)
                            url_text = "Return to Thread"

                            return render_template("pages/alert.html",
                                                   board=board,
                                                   status_msg=status_msg,
                                                   url=url,
                                                   url_text=url_text)
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)
                else:
                    logger.error("Could not authenticate access to globally delete post with comment")
            except Exception as err:
                logger.error("Exception while deleting message with comment: {}".format(err))

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/delete_comment.html",
                           board=board,
                           from_list=from_list,
                           local_delete=False,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/admin_board_ban_address/<chan_address>/<ban_address>/<ban_type>', methods=('GET', 'POST'))
@count_views
def admin_board_ban_address(chan_address, ban_address, ban_type):
    """Owners and Admins can ban addresses"""
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=chan_address)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_confirm = forms_board.Confirm()
    chan = Chan.query.filter(Chan.address == chan_address).first()

    status_msg = {"status_message": []}
    board = {
        "current_chan": chan,
        "current_thread": None,
    }

    from_list = daemon_com.get_from_list(chan_address, only_owner_admin=True)

    if ban_address in daemon_com.get_identities():
        status_msg['status_message'].append("You cannot ban your own identity")
        status_msg['status_title'] = "Error"

    elif request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action=ban_type,
                               chan=chan,
                               chan_address=chan_address,
                               from_list=from_list,
                               ban_address=ban_address)

    elif request.method == 'POST' and form_confirm.confirm.data and not form_confirm.address.data:
        status_msg['status_message'].append("From address required")
        status_msg['status_title'] = "Error"

    elif request.method == 'POST' and form_confirm.confirm.data:
        try:
            # Send message to remotely ban user and delete all user messages
            dict_message = {
                "version": config.VERSION_MSG,
                "timestamp_utc": daemon_com.get_utc(),
                "message_type": "admin",
                "chan_type": "board",
                "action": ban_type,
                "action_type": "ban_address",
                "chan_address": chan_address,
                "options": {"ban_address": ban_address}
            }

            if ban_type == "board_ban_public" and form_confirm.text.data:
                dict_message["options"]["reason"] = form_confirm.text.data

            pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
            if chan and chan.pgp_passphrase_msg:
                pgp_passphrase_msg = chan.pgp_passphrase_msg

            str_message = json.dumps(dict_message)
            gpg = gnupg.GPG()
            message_encrypted = gpg.encrypt(
                str_message, symmetric="AES256", passphrase=pgp_passphrase_msg, recipients=None)
            message_send = base64.b64encode(message_encrypted.data).decode()

            # Don't allow a message to send while Bitmessage is restarting
            allow_send = False
            timer = time.time()
            while not allow_send:
                if daemon_com.bitmessage_restarting() is False:
                    allow_send = True
                if time.time() - timer > config.BM_WAIT_DELAY:
                    logger.error(
                        "Unable to send message: "
                        "Could not detect Bitmessage running.")
                    return
                time.sleep(1)

            if allow_send:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                    try:
                        return_str = api.sendMessage(
                            chan_address,
                            form_confirm.address.data,
                            "",
                            message_send,
                            2,
                            config.BM_TTL)
                        if return_str:
                            ban_type = ""
                            if ban_type == "board_ban_public":
                                ban_type = " publicly"
                            elif ban_type == "board_ban_silent":
                                ban_type = " silently"
                            reason = ""
                            if form_confirm.text.data:
                                reason = " Reason: {}".format(form_confirm.text.data)
                            status_msg['status_message'].append(
                                "Global message sent to{} ban {} from board {}.{}".format(
                                    ban_type, ban_address, chan_address, reason))
                            status_msg['status_title'] = "Ban Address"
                    finally:
                        time.sleep(config.API_PAUSE)
                        lf.lock_release(config.LOCKFILE_API)

                # If a public ban, add to mod log
                if ban_type == "board_ban_public":
                    log_description = "Ban {}".format(ban_address)
                    if form_confirm.text.data:
                        log_description += ": Reason: {}".format(form_confirm.text.data)
                    add_mod_log_entry(
                        log_description,
                        user_from=form_confirm.address.data,
                        board_address=chan_address)
            else:
                logger.error("Could not authenticate access to globally ban")
        except Exception as err:
            logger.error("Exception while banning address: {}".format(err))

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)


@blueprint.route('/set_owner_options/<chan_address>', methods=('GET', 'POST'))
@count_views
def set_owner_options(chan_address):
    """Set options only Owner can change"""
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    chan = Chan.query.filter(Chan.address == chan_address).first()

    form_options = forms_board.SetOptions()

    board = {
        "current_chan": chan,
        "current_thread": None,
    }
    status_msg = {"status_message": []}

    if request.method == 'POST':
        if form_options.set_options.data:
            modify_admin_addresses = None
            modify_user_addresses = None
            modify_restricted_addresses = None
            image_base64 = None
            long_description = None
            css = None
            word_replace = {}

            admin_cmd = Command.query.filter(and_(
                Command.chan_address == chan_address,
                Command.action == "set",
                Command.action_type == "options")).first()

            if form_options.modify_admin_addresses.data is not None:
                send_modify_admin_addresses = False
                status_msg, list_add = check_bm_address_csv_to_list(
                    status_msg, form_options.modify_admin_addresses.data)
                if admin_cmd and admin_cmd.options:
                    # Only update if different from current modify_admin_addresses
                    try:
                        options = json.loads(admin_cmd.options)
                    except:
                        options = {}
                    if "modify_admin_addresses" in options:
                        if options["modify_admin_addresses"] != list_add:
                            send_modify_admin_addresses = True
                    else:
                        send_modify_admin_addresses = True
                else:
                    send_modify_admin_addresses = True

                if send_modify_admin_addresses:
                    modify_admin_addresses = list_add
                    logger.info("Setting modify_admin_addresses: {}".format(list_add))

            if form_options.modify_user_addresses.data is not None:
                send_modify_user_addresses = False
                status_msg, list_add = check_bm_address_csv_to_list(
                    status_msg, form_options.modify_user_addresses.data)
                if admin_cmd and admin_cmd.options:
                    # Only update if different from current modify_user_addresses
                    try:
                        options = json.loads(admin_cmd.options)
                    except:
                        options = {}
                    if "modify_user_addresses" in options:
                        if options["modify_user_addresses"] != list_add:
                            send_modify_user_addresses = True
                    else:
                        send_modify_user_addresses = True
                else:
                    send_modify_user_addresses = True

                if send_modify_user_addresses:
                    modify_user_addresses = list_add
                    logger.info("Setting modify_user_addresses: {}".format(list_add))

            if form_options.modify_restricted_addresses.data is not None:
                send_modify_restricted_addresses = False
                status_msg, list_add = check_bm_address_csv_to_list(
                    status_msg, form_options.modify_restricted_addresses.data)
                if admin_cmd and admin_cmd.options:
                    # Only update if different from current modify_restricted_addresses
                    try:
                        options = json.loads(admin_cmd.options)
                    except:
                        options = {}
                    if "modify_restricted_addresses" in options:
                        if options["modify_restricted_addresses"] != list_add:
                            send_modify_restricted_addresses = True
                    else:
                        send_modify_restricted_addresses = True
                else:
                    send_modify_restricted_addresses = True

                if send_modify_restricted_addresses:
                    modify_restricted_addresses = list_add
                    logger.info("Setting modify_restricted_addresses: {}".format(list_add))

            if form_options.file_banner.data:
                # determine image dimensions
                image_base64 = base64.b64encode(form_options.file_banner.data.read())
                try:
                    im = Image.open(BytesIO(base64.b64decode(image_base64)))
                    media_width, media_height = im.size
                    if media_width > config.BANNER_MAX_WIDTH or media_height > config.BANNER_MAX_HEIGHT:
                        status_msg['status_message'].append(
                            "Banner image dimensions too large. Requirements: width <= {}, height <= {}.".format(
                                config.BANNER_MAX_WIDTH, config.BANNER_MAX_HEIGHT))
                    else:
                        logger.info("Setting banner image")
                except Exception as err:
                    status_msg['status_message'].append(
                        "Error while determining image size: {}".format(err))

            if form_options.long_description.data:
                send_long_description = False
                if admin_cmd and admin_cmd.options:
                    # Only update if different from current long description
                    try:
                        options = json.loads(admin_cmd.options)
                    except:
                        options = {}
                    if "long_description" in options:
                        if options["long_description"] != html.escape(form_options.long_description.data):
                            send_long_description = True
                    else:
                        send_long_description = True
                else:
                    send_long_description = True

                if send_long_description:
                    logger.info("Setting Long Description")
                    long_description = html.escape(form_options.long_description.data)

            if form_options.css.data:
                send_css = False
                if admin_cmd and admin_cmd.options:
                    # Only update if different from current css
                    try:
                        options = json.loads(admin_cmd.options)
                    except:
                        options = {}
                    if "css" in options:
                        if options["css"] != html.escape(form_options.css.data):
                            send_css = True
                    else:
                        send_css = True
                else:
                    send_css = True

                if send_css:
                    logger.info("Setting CSS")
                    css = html.escape(form_options.css.data)

            if form_options.word_replace.data:
                def word_replace_str_to_dict(word_str):
                    try:
                        word_replace = {}
                        for each_replace_set in word_str.split(";"):
                            key = html.escape(each_replace_set.split(",")[0].strip())
                            value = html.escape(each_replace_set.split(",")[1].strip())
                            word_replace[key] = value
                        return word_replace
                    except:
                        return {}

                send_word_replace = False
                if admin_cmd and admin_cmd.options:
                    # Only update if different from current word replace
                    try:
                        options = json.loads(admin_cmd.options)
                    except:
                        options = {}
                    if "word_replace" in options:
                        if options["word_replace"] != word_replace_str_to_dict(form_options.word_replace.data):
                            send_word_replace = True
                    else:
                        send_word_replace = True
                else:
                    send_word_replace = True

                if send_word_replace:
                    logger.info("Setting word_replace")
                    word_replace = word_replace_str_to_dict(form_options.word_replace.data)

            # Ensure at least one option is set
            if (not image_base64 and
                    not long_description and
                    not css and
                    not word_replace and
                    modify_admin_addresses is None and
                    modify_user_addresses is None and
                    modify_restricted_addresses is None):
                status_msg['status_message'].append(
                    "Must set at least one option (and be different from currently-set options)")

            def admin_has_access(address):
                access = get_access(address)
                for id_type in [daemon_com.get_identities(), daemon_com.get_all_chans()]:
                    for address in id_type:
                        if id_type[address]['enabled'] and address in access["primary_addresses"]:
                            return address

            from_address = admin_has_access(chan_address)

            if not from_address:
                status_msg['status_message'].append(
                    "Could not authenticate access to globally set board options")
            elif not status_msg['status_message']:
                # Send message to remotely set options
                dict_message = {
                    "version": config.VERSION_MSG,
                    "timestamp_utc": daemon_com.get_utc(),
                    "message_type": "admin",
                    "action": "set",
                    "action_type": "options",
                    "options": {}
                }

                if image_base64:
                    dict_message["options"]["banner_base64"] = image_base64.decode()
                if long_description:
                    dict_message["options"]["long_description"] = long_description
                if css:
                    dict_message["options"]["css"] = css
                if word_replace:
                    dict_message["options"]["word_replace"] = word_replace

                if modify_admin_addresses is not None:
                    dict_message["options"]["modify_admin_addresses"] = modify_admin_addresses
                if modify_user_addresses is not None:
                    dict_message["options"]["modify_user_addresses"] = modify_user_addresses
                if modify_restricted_addresses is not None:
                    dict_message["options"]["modify_restricted_addresses"] = modify_restricted_addresses

                pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                chan = Chan.query.filter(Chan.address == chan.address).first()
                if chan and chan.pgp_passphrase_msg:
                    pgp_passphrase_msg = chan.pgp_passphrase_msg

                str_message = json.dumps(dict_message)
                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    str_message, symmetric="AES256", passphrase=pgp_passphrase_msg, recipients=None)
                message_send = base64.b64encode(message_encrypted.data).decode()

                if len(message_send) > config.BM_PAYLOAD_MAX_SIZE:
                    status_msg['status_message'].append(
                        "Message payload too large: {}. Must be less than {}".format(
                            human_readable_size(len(message_send)),
                            human_readable_size(config.BM_PAYLOAD_MAX_SIZE)))
                else:
                    logger.info("Message size: {}".format(len(message_send)))

                if not status_msg['status_message']:
                    # Don't allow a message to send while Bitmessage is restarting
                    allow_send = False
                    timer = time.time()
                    while not allow_send:
                        if daemon_com.bitmessage_restarting() is False:
                            allow_send = True
                        if time.time() - timer > config.BM_WAIT_DELAY:
                            logger.error(
                                "Unable to send message: "
                                "Could not detect Bitmessage running.")
                            return
                        time.sleep(1)

                    if allow_send:
                        lf = LF()
                        if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                            try:
                                return_str = api.sendMessage(
                                    chan.address,
                                    from_address,
                                    "",
                                    message_send,
                                    2,
                                    config.BM_TTL)
                                if return_str:
                                    msg = "Message to globally set options sent. " \
                                          "The message must be received before the settings take effect. " \
                                          "Return: {}".format(from_address, chan.address, return_str)
                                    logger.info(msg)
                                    status_msg['status_title'] = "Success"
                                    status_msg['status_message'].append(msg)
                            finally:
                                time.sleep(config.API_PAUSE)
                                lf.lock_release(config.LOCKFILE_API)

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)


@blueprint.route('/set_info_options/<chan_address>', methods=('GET', 'POST'))
@count_views
def set_info_options(chan_address):
    """Set options users can change"""
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=chan_address)
    if not global_admin and not board_list_admin:
        return allow_msg

    chan = Chan.query.filter(Chan.address == chan_address).first()

    form_options = forms_board.SetOptions()

    board = {
        "current_chan": chan,
        "current_thread": None,
    }
    status_msg = {"status_message": []}

    if request.method == 'POST':
        if form_options.allow_css.data or form_options.disallow_css.data:
            chan = Chan.query.filter(Chan.address == chan.address).first()
            if form_options.allow_css.data:
                chan.allow_css = form_options.allow_css.data
                status_msg['status_message'].append("Custom CSS changed to allowed")
            elif form_options.disallow_css.data:
                chan.allow_css = False
                status_msg['status_message'].append("Custom CSS changed to disallowed")
            chan.save()
            status_msg['status_title'] = "Success"

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)
