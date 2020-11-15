import base64
import html
import json
import logging
import time
from io import BytesIO

import gnupg
from PIL import Image
from flask import render_template
from flask import request
from flask.blueprints import Blueprint
from sqlalchemy import and_

import config
from bitchan_flask import nexus
from database.models import Chan
from database.models import Command
from database.models import Messages
from database.models import Threads
from forms import forms_board
from utils.files import LF
from utils.files import delete_message_files
from utils.files import human_readable_size
from utils.general import check_bm_address_csv_to_list
from utils.routes import get_access
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_admin')

blueprint = Blueprint('routes_admin',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.route('/delete/<current_chan>/<message_id>/<thread_id>/<delete_type>', methods=('GET', 'POST'))
def delete(current_chan, message_id, thread_id, delete_type):
    """Owners and Admins can delete messages and threads"""
    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    board = {
        "current_chan": chan,
        "current_thread": thread_id,
    }
    status_msg = {"status_message": []}
    url = ""
    url_text = ""
    delete_thread = False
    list_delete_message_ids = []

    if ((delete_type in ["post", "post_all"] and len(thread.messages) == 1) or
            delete_type in ["thread", "thread_all"]):
        delete_thread = True

    if delete_thread:
        for message in thread.messages:
            list_delete_message_ids.append(message.message_id)
    elif thread:
        list_delete_message_ids.append(message_id)
        url = "/thread/{}/{}".format(current_chan, thread_id)
        url_text = "{}".format(thread.subject)

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            # First, delete messages from database
            if list_delete_message_ids:
                for each_id in list_delete_message_ids:
                    this_message = Messages.query.filter(Messages.message_id == each_id).first()
                    if this_message:
                        # Delete all files associated with message
                        delete_message_files(this_message.message_id)
                        this_message.delete()

            # Next, delete message objects from bitchan objects and thread from DB
            if not delete_thread:
                nexus.delete_message(current_chan, thread_id, message_id)
                status_msg['status_message'].append("Message deleted from thread: '{}'".format(thread.subject))
                status_msg['status_title'] = "Deleted Message"
            else:
                status_msg['status_message'].append("Thread deleted: '{}'".format(thread.subject))
                if thread:
                    thread.delete()
                nexus.delete_thread(current_chan, thread_id)
                status_msg['status_title'] = "Deleted Thread"

            # Allow messages to be deleted in bitmessage before allowing bitchan to rescan inbox
            time.sleep(2)

            # Send message to remotely delete post/thread
            if delete_type in ["post_all", "thread_all"]:
                dict_message = {
                    "version": config.VERSION_BITCHAN,
                    "timestamp_utc": nexus.get_utc(),
                    "message_type": "admin",
                    "chan_type": "board",
                    "action": "delete",
                    "options": {}
                }
                if delete_type == "post_all":
                    dict_message["action_type"] = "delete_post"
                    dict_message["options"]["delete_post"] = {
                        "thread_id": thread_id,
                        "message_id": message_id
                    }
                elif delete_type == "thread_all":
                    dict_message["action_type"] = "delete_thread"
                    dict_message["options"]["delete_thread"] = {
                        "thread_id": thread_id,
                        "message_id": message_id
                    }

                def admin_has_access(address):
                    access = get_access(address)
                    for id_type in [nexus.get_identities(), nexus.get_all_chans()]:
                        for address in id_type:
                            if id_type[address]['enabled'] and address in access["primary_addresses"]:
                                return address
                            if id_type[address]['enabled'] and address in access["secondary_addresses"]:
                                return address

                from_address = admin_has_access(current_chan)

                if from_address:
                    str_message = json.dumps(dict_message)
                    gpg = gnupg.GPG()
                    message_encrypted = gpg.encrypt(
                        str_message, symmetric=True, passphrase=config.PASSPHRASE_MSG, recipients=None)
                    message_send = base64.b64encode(message_encrypted.data).decode()

                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=60):
                        try:
                            return_str = nexus._api.sendMessage(
                                current_chan,
                                from_address,
                                "",
                                message_send,
                                2,
                                config.BM_TTL)
                            if return_str:
                                logger.info("{}: Message to globally delete {} sent from {} to {}".format(
                                    thread_id[0:6], delete_type, from_address, current_chan))
                            time.sleep(0.1)
                        finally:
                            lf.lock_release(config.LOCKFILE_API)
                else:
                    logger.error("Could not authenticate access to globally delete post/thread")
        except Exception as err:
            logger.error("Exception while deleting message(s): {}".format(err))
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/delete_with_comment/<current_chan>/<message_id>/<thread_id>', methods=('GET', 'POST'))
def delete_with_comment(current_chan, message_id, thread_id):
    """Owners and Admins can delete messages and threads"""
    form_del_com = forms_board.DeleteComment()
    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

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

        elif form_del_com.send.data:
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
                try:
                    # Send message to remotely delete post with comment
                    dict_message = {
                        "version": config.VERSION_BITCHAN,
                        "timestamp_utc": nexus.get_utc(),
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

                    def admin_has_access(address):
                        access = get_access(address)
                        for id_type in [nexus.get_identities(), nexus.get_all_chans()]:
                            for address in id_type:
                                if id_type[address]['enabled'] and address in access["primary_addresses"]:
                                    return address
                                if id_type[address]['enabled'] and address in access["secondary_addresses"]:
                                    return address

                    from_address = admin_has_access(current_chan)

                    if from_address:
                        str_message = json.dumps(dict_message)
                        gpg = gnupg.GPG()
                        message_encrypted = gpg.encrypt(
                            str_message, symmetric=True, passphrase=config.PASSPHRASE_MSG, recipients=None)
                        message_send = base64.b64encode(message_encrypted.data).decode()

                        lf = LF()
                        if lf.lock_acquire(config.LOCKFILE_API, to=60):
                            try:
                                return_str = nexus._api.sendMessage(
                                    current_chan,
                                    from_address,
                                    "",
                                    message_send,
                                    2,
                                    config.BM_TTL)
                                if return_str:
                                    logger.info("{}: Message to globally delete with comment sent from {} to {}. "
                                                "The message will need to propagate through the network before "
                                                "the changes are reflected on the board.".format(
                                                    thread_id[0:6], from_address, current_chan))
                                time.sleep(0.1)

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
                                lf.lock_release(config.LOCKFILE_API)
                    else:
                        logger.error("Could not authenticate access to globally delete post with comment")
                except Exception as err:
                    logger.error("Exception while deleting message with comment: {}".format(err))
                finally:
                    lf.lock_release(config.LOCKFILE_MSG_PROC)

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/delete_comment.html",
                           board=board,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/admin_board_ban_address/<chan_address>/<ban_address>', methods=('GET', 'POST'))
def admin_board_ban_address(chan_address, ban_address):
    """Owners and Admins can ban addresses"""
    chan = Chan.query.filter(Chan.address == chan_address).first()
    messages = Messages.query.filter(Messages.address_from == ban_address).all()

    board = {
        "current_chan": chan,
        "current_thread": None,
    }
    status_msg = {"status_message": []}
    list_delete_message_ids = []

    for message in messages:
        if message.thread.chan.address == chan_address:
            list_delete_message_ids.append(message.message_id)

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            # First, delete messages from database
            if list_delete_message_ids:
                for each_id in list_delete_message_ids:
                    this_message = Messages.query.filter(Messages.message_id == each_id).first()
                    if this_message:
                        # Delete all files associated with message
                        delete_message_files(this_message.message_id)
                        this_message.delete()

            # Allow messages to be deleted in bitmessage before allowing bitchan to rescan inbox
            time.sleep(1)

            # Send message to remotely ban user and delete all user messages
            dict_message = {
                "version": config.VERSION_BITCHAN,
                "timestamp_utc": nexus.get_utc(),
                "message_type": "admin",
                "chan_type": "board",
                "action": "ban",
                "action_type": "ban_address",
                "chan_address": chan_address,
                "options": {"ban_address": ban_address}
            }

            def admin_has_access(address):
                access = get_access(address)
                for id_type in [nexus.get_identities(), nexus.get_all_chans()]:
                    for address in id_type:
                        if id_type[address]['enabled'] and address in access["primary_addresses"]:
                            return address
                        if id_type[address]['enabled'] and address in access["secondary_addresses"]:
                            return address

            from_address = admin_has_access(chan_address)

            if from_address:
                str_message = json.dumps(dict_message)
                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    str_message, symmetric=True, passphrase=config.PASSPHRASE_MSG, recipients=None)
                message_send = base64.b64encode(message_encrypted.data).decode()

                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        return_str = nexus._api.sendMessage(
                            chan_address,
                            from_address,
                            "",
                            message_send,
                            2,
                            config.BM_TTL)
                        if return_str:
                            status_msg['status_message'].append(
                                "Message sent to globally ban {} from board {}".format(
                                ban_address, chan_address))
                            status_msg['status_title'] = "Ban Address"
                        time.sleep(0.1)
                    finally:
                        lf.lock_release(config.LOCKFILE_API)
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
    chan = Chan.query.filter(Chan.address == chan_address).first()

    form_options = forms_board.SetOptions()

    board = {
        "current_chan": chan,
        "current_thread": None,
    }
    status_msg = {"status_message": []}

    if request.method == 'POST':
        if form_options.set_options.data:
            from bitchan_flask import nexus

            modify_admin_addresses = None
            modify_user_addresses = None
            modify_restricted_addresses = None
            image_base64 = None
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
                            "Image dimensions too large. Requirements: width <= {}, height <= {}.".format(
                                config.BANNER_MAX_WIDTH, config.BANNER_MAX_HEIGHT))
                    else:
                        logger.info("Setting banner image")
                except Exception as err:
                    status_msg['status_message'].append(
                        "Error while determining image size: {}".format(err))

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
                    not css and
                    not word_replace and
                    modify_admin_addresses is None and
                    modify_user_addresses is None and
                    modify_restricted_addresses is None):
                status_msg['status_message'].append(
                    "Must set at least one option (and be different from currently-set options)")

            def admin_has_access(address):
                access = get_access(address)
                for id_type in [nexus.get_identities(), nexus.get_all_chans()]:
                    for address in id_type:
                        if id_type[address]['enabled'] and address in access["primary_addresses"]:
                            return address

            from_address = admin_has_access(chan_address)

            if not from_address:
                status_msg['status_message'].append(
                    "Could not authenticate access to globally set board options")
            elif not status_msg['status_message']:
                # Send message to remotely set banner
                dict_message = {
                    "version": config.VERSION_BITCHAN,
                    "timestamp_utc": nexus.get_utc(),
                    "message_type": "admin",
                    "action": "set",
                    "action_type": "options",
                    "options": {}
                }

                if image_base64:
                    dict_message["options"]["banner_base64"] = image_base64.decode()
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

                str_message = json.dumps(dict_message)
                gpg = gnupg.GPG()
                message_encrypted = gpg.encrypt(
                    str_message, symmetric=True, passphrase=config.PASSPHRASE_MSG, recipients=None)
                message_send = base64.b64encode(message_encrypted.data).decode()

                if len(message_send) > config.BM_PAYLOAD_MAX_SIZE:
                    status_msg['status_message'].append(
                        "Message payload too large: {}. Must be less than {}".format(
                            human_readable_size(len(message_send)),
                            human_readable_size(config.BM_PAYLOAD_MAX_SIZE)))
                else:
                    logger.info("Message size: {}".format(len(message_send)))

                if not status_msg['status_message']:
                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=60):
                        try:
                            return_str = nexus._api.sendMessage(
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
                            time.sleep(0.1)
                        finally:
                            lf.lock_release(config.LOCKFILE_API)

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)