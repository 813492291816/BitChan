import base64
import html
import json
import logging
import time
from io import BytesIO

import gnupg
from PIL import Image
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Command
from database.models import GlobalSettings
from database.models import Messages
from database.models import Threads
from forms import forms_board
from utils.files import LF
from utils.files import human_readable_size
from utils.gateway import api
from utils.gateway import delete_and_replace_comment
from utils.general import check_bm_address_csv_to_list
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.routes import allowed_access
from utils.routes import page_dict
from utils.shared import add_mod_log_entry
from utils.shared import get_access
from utils.shared import regenerate_thread_card_and_popup

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
    if (GlobalSettings.query.first().enable_verification and
            ("verified" not in session or not session["verified"])):
        session["verified_msg"] = "You are not verified"
        return redirect(url_for('routes_verify.verify_wait'))
    session["verified_msg"] = "You are verified"


@blueprint.route('/mod_thread/<current_chan>/<thread_id>/<mod_type>', methods=('GET', 'POST'))
def mod_thread(current_chan, thread_id, mod_type):
    """
    Locally/remotely modify a thread or post
    """
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    board_list_admin, allow_msg = allowed_access(
        check_is_board_list_admin=True, check_admin_board=current_chan)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_confirm = forms_board.Confirm()

    message_id = None
    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    from_list = daemon_com.get_from_list(current_chan, only_owner_admin=True)

    if not thread:
        return "Thread doesn't exist"

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action=mod_type,
                               chan=chan,
                               current_chan=current_chan,
                               from_list=from_list,
                               thread=thread,
                               thread_id=thread_id,
                               mod_type=mod_type)

    board = {
        "current_chan": chan,
        "current_thread": thread_id
    }
    status_msg = {"status_message": []}
    url = "/thread/{}/{}".format(current_chan, thread.thread_hash_short)
    url_text = "Thread: {}".format(thread.subject)

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            from_user = None
            log_description = ""

            message = Messages.query.filter(and_(
                Messages.thread_id == thread.id,
                Messages.is_op.is_(True))).first()
            if message:
                message_id = message.message_id

            #
            # Locally sticky/unsticky
            #
            if mod_type in ["thread_sticky_local", "thread_unsticky_local"]:
                thread.stickied_local = bool(mod_type == "thread_sticky_local")
                thread.save()

                regenerate_thread_card_and_popup(thread.thread_hash)

                if mod_type == "thread_sticky_local":
                    log_description = "Locally stickied thread"
                    status_msg['status_message'].append("Locally stickied thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Locally stickied thread"
                else:
                    log_description = "Locally unstickied thread"
                    status_msg['status_message'].append("Locally unstickied thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Locally unstickied thread"

            #
            # Locally lock/unlock
            #
            elif mod_type in ["thread_lock_local", "thread_unlock_local"]:
                thread.locked_local = bool(mod_type == "thread_lock_local")
                thread.locked_local_ts = time.time()
                thread.save()

                regenerate_thread_card_and_popup(thread.thread_hash)

                if mod_type == "thread_lock_local":
                    log_description = "Locally locked thread"
                    status_msg['status_message'].append("Locally locked thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Locally locked thread"
                else:
                    log_description = "Locally unlocked thread"
                    status_msg['status_message'].append("Locally unlocked thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Locally unlocked thread"

            #
            # Locally anchor/unanchor
            #
            elif mod_type in ["thread_anchor_local", "thread_unanchor_local"]:
                thread.anchored_local = bool(mod_type == "thread_anchor_local")
                thread.anchored_local_ts = time.time()
                thread.save()

                regenerate_thread_card_and_popup(thread.thread_hash)

                if mod_type == "thread_anchor_local":
                    log_description = "Locally anchored thread"
                    status_msg['status_message'].append("Locally anchored thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Locally anchored thread"
                else:
                    log_description = "Locally unanchored thread"
                    status_msg['status_message'].append("Locally unanchored thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Locally unanchored thread"

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
                    chan = Chan.query.filter(Chan.address == current_chan).first()
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
                                    current_chan,
                                    form_confirm.address.data,
                                    "",
                                    message_send,
                                    2,
                                    config.BM_TTL)
                                if return_str:
                                    logger.info("{}: Message to globally {} sent from {} to {}".format(
                                        thread_id[0:6], mod_type, form_confirm.address.data, current_chan))
                            finally:
                                time.sleep(config.API_PAUSE)
                                lf.lock_release(config.LOCKFILE_API)

            if mod_type in ["thread_sticky_local",
                            "thread_unsticky_local",
                            "thread_lock_local",
                            "thread_unlock_local",
                            "thread_anchor_local",
                            "thread_unanchor_local"]:
                # Only log local events.
                # Global events will be logged when the admin command message is processed
                add_mod_log_entry(
                    log_description,
                    message_id=message_id,
                    user_from=from_user,
                    board_address=current_chan,
                    thread_hash=thread_id)

        except Exception as err:
            logger.error("Exception while deleting message(s): {}".format(err))
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/bulk_delete_thread/<current_chan>', methods=('GET', 'POST'))
def bulk_delete_thread(current_chan):
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    board_list_admin, allow_msg = allowed_access(
        check_is_board_list_admin=True, check_admin_board=current_chan)
    if not global_admin and not board_list_admin:
        return allow_msg

    if current_chan != "0":
        board = Chan.query.filter(Chan.address == current_chan).first()
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

            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
                try:
                    for each_thread_hash in delete_bulk_thread_hashes:
                        thread = Threads.query.filter(
                            Threads.thread_hash == each_thread_hash).first()
                        if thread:
                            list_delete_message_ids = []
                            for message in thread.messages:
                                list_delete_message_ids.append(message.message_id)

                            # First, delete messages from database
                            if list_delete_message_ids:
                                for each_id in list_delete_message_ids:
                                    delete_post(each_id)

                            # Next, delete thread from DB
                            delete_thread(each_thread_hash)
                            status_msg['status_message'].append("Thread deleted: {}".format(thread.subject))
                except Exception as err:
                    logger.error("Exception while deleting message(s): {}".format(err))
                finally:
                    daemon_com.signal_generate_post_numbers()
                    lf.lock_release(config.LOCKFILE_MSG_PROC)

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


@blueprint.route('/delete_thread_post/<current_chan>/<message_id>/<thread_id>/<delete_type>', methods=('GET', 'POST'))
def delete(current_chan, message_id, thread_id, delete_type):
    """
    Owners and Admins can delete messages and threads

    delete_type can be:
    post: delete post from local instance
    posts_all: delete post for all users (must be owner or admin)
    thread: delete thread from local instance
    thread_all: delete thread for all users (must be owner or admin)
    """
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    board_list_admin, allow_msg = allowed_access(
        check_is_board_list_admin=True, check_admin_board=current_chan)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_confirm = forms_board.Confirm()

    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    from_list = daemon_com.get_from_list(current_chan, only_owner_admin=True)

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action=delete_type,
                               chan=chan,
                               current_chan=current_chan,
                               from_list=from_list,
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
        url = "/thread/{}/{}".format(current_chan, thread_id)
        url_text = "{}".format(thread.subject)

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            if delete_type in ["delete_post", "delete_thread"]:
                list_delete_message_ids = []
                if delete_type == "delete_thread" and thread:
                    board["current_thread"] = None
                    for message in thread.messages:
                        list_delete_message_ids.append(message.message_id)
                elif delete_type == "delete_post":
                    list_delete_message_ids.append(message_id)

                log_description = ""
                if delete_type == "delete_post":
                    status_msg['status_message'].append("Locally deleted post from thread: '{}'".format(thread.subject))
                    status_msg['status_title'] = "Success"
                    log_description = "Locally deleted post"
                elif delete_type == "delete_thread":
                    status_msg['status_message'].append("Locally deleted thread: {}".format(thread.subject))
                    status_msg['status_title'] = "Success"
                    log_description = 'Locally deleted thread "{}"'.format(thread.subject)

                # If local, first delete messages
                if list_delete_message_ids:
                    for each_id in list_delete_message_ids:
                        delete_post(each_id)
                    daemon_com.signal_generate_post_numbers()

                # If local, next delete thread
                if delete_type in ["delete_thread"]:
                    if thread:
                        delete_thread(thread_id)

                add_mod_log_entry(
                    log_description,
                    message_id=message_id,
                    user_from=form_confirm.address.data,
                    board_address=current_chan,
                    thread_hash=thread_id)

                # Allow messages to be deleted in bitmessage before allowing bitchan to rescan inbox
                time.sleep(1)

            # Send message to remotely delete post/thread
            elif delete_type in ["delete_post_all", "delete_thread_all"]:
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
                    chan = Chan.query.filter(Chan.address == current_chan).first()
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
                                    current_chan,
                                    form_confirm.address.data,
                                    "",
                                    message_send,
                                    2,
                                    config.BM_TTL)
                                if return_str:
                                    logger.info("{}: Message to globally delete {} sent from {} to {}".format(
                                        thread_id[0:6], delete_type, form_confirm.address.data, current_chan))
                            finally:
                                time.sleep(config.API_PAUSE)
                                lf.lock_release(config.LOCKFILE_API)

        except Exception as err:
            logger.error("Exception while deleting message(s): {}".format(err))
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/delete_with_comment_local/<current_chan>/<message_id>/<thread_id>', methods=('GET', 'POST'))
def delete_with_comment_local(current_chan, message_id, thread_id):
    """Locally delete post with comment"""
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    board_list_admin, allow_msg = allowed_access(
        check_is_board_list_admin=True, check_admin_board=current_chan)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_del_com = forms_board.DeleteComment()
    chan = Chan.query.filter(Chan.address == current_chan).first()

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
                delete_and_replace_comment(
                    message_id, form_del_com.delete_comment.data, local_delete=True)

                status_msg['status_message'].append(
                    "Message locally deleted from post and replaced with comment: '{}'".format(
                        form_del_com.delete_comment.data))
                status_msg['status_title'] = "Deleted Message with Comment"

                url = "/thread/{}/{}".format(current_chan, thread_id)
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
                           local_delete=True,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/delete_with_comment/<current_chan>/<message_id>/<thread_id>', methods=('GET', 'POST'))
def delete_with_comment(current_chan, message_id, thread_id):
    """Globally delete post with comment"""
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    board_list_admin, allow_msg = allowed_access(
        check_is_board_list_admin=True, check_admin_board=current_chan)
    if not global_admin and not board_list_admin:
        return allow_msg

    form_del_com = forms_board.DeleteComment()
    chan = Chan.query.filter(Chan.address == current_chan).first()

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
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
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
                    chan = Chan.query.filter(Chan.address == current_chan).first()
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
                                    current_chan,
                                    form_del_com.address.data,
                                    "",
                                    message_send,
                                    2,
                                    config.BM_TTL)
                                if return_str:
                                    logger.info("{}: Message to globally delete with comment sent from {} to {}. "
                                                "The message will need to propagate through the network before "
                                                "the changes are reflected on the board.".format(
                                                    thread_id[0:6], form_del_com.address.data, current_chan))

                                status_msg['status_message'].append(
                                    "Message deleted from post and replaced with comment: '{}'".format(
                                        form_del_com.delete_comment.data))
                                status_msg['status_title'] = "Deleted Message with Comment"

                                url = "/thread/{}/{}".format(current_chan, thread_id)
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
                finally:
                    lf.lock_release(config.LOCKFILE_MSG_PROC)

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    from_list = daemon_com.get_from_list(current_chan, only_owner_admin=True)

    return render_template("pages/delete_comment.html",
                           board=board,
                           from_list=from_list,
                           local_delete=False,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/admin_board_ban_address/<chan_address>/<ban_address>/<ban_type>', methods=('GET', 'POST'))
def admin_board_ban_address(chan_address, ban_address, ban_type):
    """Owners and Admins can ban addresses"""
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    board_list_admin, allow_msg = allowed_access(
        check_is_board_list_admin=True, check_admin_board=chan_address)
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
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
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
                            message_id=None,
                            user_from=form_confirm.address.data,
                            board_address=chan_address,
                            thread_hash=None)
                else:
                    logger.error("Could not authenticate access to globally ban")
            except Exception as err:
                logger.error("Exception while banning address: {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_MSG_PROC)

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)


@blueprint.route('/set_owner_options/<chan_address>', methods=('GET', 'POST'))
def set_owner_options(chan_address):
    """Set options only Owner can change"""
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
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
            spoiler_base64 = None
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

            if form_options.file_spoiler.data:
                # determine image dimensions
                spoiler_base64 = base64.b64encode(form_options.file_spoiler.data.read())
                try:
                    im = Image.open(BytesIO(base64.b64decode(spoiler_base64)))
                    media_width, media_height = im.size
                    if media_width > config.SPOILER_MAX_WIDTH or media_height > config.SPOILER_MAX_HEIGHT:
                        status_msg['status_message'].append(
                            "Spoiler image dimensions too large. Requirements: width <= {}, height <= {}.".format(
                                config.SPOILER_MAX_WIDTH, config.SPOILER_MAX_HEIGHT))
                    else:
                        logger.info("Setting spoiler image")
                except Exception as err:
                    status_msg['status_message'].append(
                        "Error while determining spoiler size: {}".format(err))

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
                    not spoiler_base64 and
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
                if spoiler_base64:
                    dict_message["options"]["spoiler_base64"] = spoiler_base64.decode()
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
def set_info_options(chan_address):
    """Set options users can change"""
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    board_list_admin, allow_msg = allowed_access(
        check_is_board_list_admin=True, check_admin_board=chan_address)
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
