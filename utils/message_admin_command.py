import base64
import html
import json
import logging
import time
from io import BytesIO

import gnupg
from PIL import Image
from sqlalchemy import and_

import config
from database.models import Chan
from database.models import Command
from database.models import Messages
from database.models import Threads
from database.utils import session_scope
from utils.files import LF
from utils.gateway import delete_and_replace_comment
from utils.gateway import delete_db_message
from utils.gateway import get_access
from utils.general import get_random_alphanumeric_string
from utils.general import is_bitmessage_address
from utils.replacements import process_replacements
from utils.shared import is_access_same_as_db

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.admin_command')


def send_commands():
    """Send admin commands prior to them expiring to ensure options are available to all users"""
    from bitchan_flask import nexus

    try:
        run_id = get_random_alphanumeric_string(
            6, with_punctuation=False, with_spaces=False)
        with session_scope(DB_PATH) as new_session:
            admin_cmds = new_session.query(Command).filter(
                Command.do_not_send == False).all()
            for each_cmd in admin_cmds:
                if not each_cmd.options:
                    continue

                logger.info("{}: Checking commands to send to {}".format(
                    run_id, each_cmd.chan_address))

                # Determine if we have an authorized address to send from
                chan = new_session.query(Chan).filter(
                    Chan.address == each_cmd.chan_address).first()
                if not chan:
                    logger.info("{}: Chan not found in DB".format(run_id))
                    continue

                def admin_has_access(address):
                    access = get_access(address)
                    for id_type in [nexus.get_identities(), nexus.get_all_chans()]:
                        for address in id_type:
                            if id_type[address]['enabled'] and address in access["primary_addresses"]:
                                return address

                from_address = admin_has_access(chan.address)
                if not from_address:
                    continue

                try:
                    options = json.loads(each_cmd.options)
                except:
                    options = {}

                if not options:
                    logger.info("{}: No options found for Admin command to send.".format(run_id))
                    continue

                for each_option in options:
                    dict_message = {
                        "version": config.VERSION_BITCHAN,
                        "timestamp_utc": nexus.get_utc(),
                        "message_type": "admin",
                        "action": each_cmd.action,
                        "action_type": each_cmd.action_type,
                        "message_id": each_cmd.message_id,
                        "thread_id": each_cmd.thread_id,
                        "chan_address": each_cmd.chan_address,
                        "options": {}
                    }

                    def is_expiring(ts_utc):
                        days = (nexus.get_utc() - ts_utc) / 60 / 60 / 24
                        if days > 20:
                            return True, days
                        else:
                            return False, days

                    option_ts = "{}_timestamp_utc".format(each_option)
                    if each_option in config.ADMIN_OPTIONS and option_ts in options:
                        expiring, days = is_expiring(options[option_ts])
                        if expiring:
                            logger.info("{}: {} {:.1f} days old: expiring".format(
                                run_id, each_option, days))
                            dict_message["options"][each_option] = options[each_option]
                        else:
                            logger.info("{}: {} {:.1f} days old: not expiring".format(
                                run_id, each_option, days))

                    if not dict_message["options"]:
                        logger.info("{}: No options nearing expiration".format(run_id))
                        continue

                    pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                    if chan.pgp_passphrase_msg:
                        pgp_passphrase_msg = chan.pgp_passphrase_msg

                    str_message = json.dumps(dict_message)
                    gpg = gnupg.GPG()
                    message_encrypted = gpg.encrypt(
                        str_message,
                        symmetric="AES256",
                        passphrase=pgp_passphrase_msg,
                        recipients=None)
                    message_send = base64.b64encode(message_encrypted.data).decode()

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
                                logger.info("{}: Sent command options. Return: {}".format(
                                    run_id, return_str))
                                nexus.post_delete_queue(from_address, return_str)
                            time.sleep(0.1)
                        finally:
                            lf.lock_release(config.LOCKFILE_API)
    except:
        logger.exception("send_commands()")


def admin_set_options(msg_dict, admin_dict):
    """
    Set custom options for board or list
    e.g. Banner, spoiler, CSS, word replace, access
    """
    from bitchan_flask import nexus

    error = []

    if admin_dict["timestamp_utc"] - (60 * 60 * 6) > nexus.get_utc():
        # message timestamp is in the distant future. Delete.
        logger.error("{}: Command has future timestamp. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        nexus.trash_message(msg_dict["msgid"])
        return

    if "options" not in admin_dict:
        logger.error("{}: Missing 'options' to set.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        nexus.trash_message(msg_dict["msgid"])
        return

    if "banner_base64" in admin_dict["options"]:
        # Verify image is not larger than max dimensions
        im = Image.open(BytesIO(base64.b64decode(admin_dict["options"]["banner_base64"])))
        media_width, media_height = im.size
        if media_width > config.BANNER_MAX_WIDTH or media_height > config.BANNER_MAX_HEIGHT:
            logger.error("{}: Banner image too large. Discarding admin message.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            nexus.trash_message(msg_dict["msgid"])
            return

    if "spoiler_base64" in admin_dict["options"]:
        # Verify spoiler is not larger than max dimensions
        im = Image.open(BytesIO(base64.b64decode(admin_dict["options"]["spoiler_base64"])))
        media_width, media_height = im.size
        if media_width > config.SPOILER_MAX_WIDTH or media_height > config.SPOILER_MAX_HEIGHT:
            logger.error("{}: Spoiler image too large. Discarding admin message.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            nexus.trash_message(msg_dict["msgid"])
            return

    if not msg_dict['toAddress']:
        nexus.trash_message(msg_dict["msgid"])
        return

    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == msg_dict['toAddress']).first()
        admin_cmd = new_session.query(Command).filter(and_(
            Command.chan_address == msg_dict['toAddress'],
            Command.action == "set",
            Command.action_type == "options")).first()

        access_same = is_access_same_as_db(admin_dict["options"], chan)

        if admin_cmd:
            # Modify current entry
            admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
            options = json.loads(admin_cmd.options)

            # Set modify_admin_addresses
            if "modify_admin_addresses" in admin_dict["options"]:
                # Check addresses
                for each_add in admin_dict["options"]["modify_admin_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid admin address: {}".format(each_add))
                # Add/Mod addresses
                if "modify_admin_addresses_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["modify_admin_addresses_timestamp_utc"]:
                        options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                        options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                    options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                # Last pass, delete entries if same as in chan db
                if access_same["secondary_access"]:
                    options.pop('modify_admin_addresses', None)
                    options.pop('modify_admin_addresses_timestamp_utc', None)

            # Set modify_user_addresses
            if "modify_user_addresses" in admin_dict["options"]:
                # Check addresses
                for each_add in admin_dict["options"]["modify_user_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid user address: {}".format(each_add))
                # Add/Mod addresses
                if "modify_user_addresses_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["modify_user_addresses_timestamp_utc"]:
                        options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                        options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                    options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                # Last pass, delete entries if same as in chan db
                if access_same["tertiary_access"]:
                    options.pop('modify_user_addresses', None)
                    options.pop('modify_user_addresses_timestamp_utc', None)

            # Set modify_restricted_addresses
            if "modify_restricted_addresses" in admin_dict["options"]:
                # Check addresses
                for each_add in admin_dict["options"]["modify_restricted_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid restricted address: {}".format(each_add))
                # Add/Mod addresses
                if "modify_restricted_addresses_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["modify_restricted_addresses_timestamp_utc"]:
                        options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                        options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                    options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                # Last pass, delete entries if same as in chan db
                if access_same["restricted_access"]:
                    options.pop('modify_restricted_addresses', None)
                    options.pop('modify_restricted_addresses_timestamp_utc', None)

            # Set banner
            if "banner_base64" in admin_dict["options"]:
                if "banner_base64_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["banner_base64_timestamp_utc"]:
                        options["banner_base64"] = admin_dict["options"]["banner_base64"]
                        options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["banner_base64"] = admin_dict["options"]["banner_base64"]
                    options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]

            # Set spoiler
            if "spoiler_base64" in admin_dict["options"]:
                if "spoiler_base64_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["spoiler_base64_timestamp_utc"]:
                        options["spoiler_base64"] = admin_dict["options"]["spoiler_base64"]
                        options["spoiler_base64_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["spoiler_base64"] = admin_dict["options"]["spoiler_base64"]
                    options["spoiler_base64_timestamp_utc"] = admin_dict["timestamp_utc"]

            # Set Long Description
            if "long_description" in admin_dict["options"]:
                if "long_description_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["long_description_timestamp_utc"]:
                        if len(admin_dict["options"]["long_description"]) > config.LONG_DESCRIPTION_LENGTH:
                            error.append("Long Description too long ({} characters). Max is {}.".format(
                                len(admin_dict["options"]["long_description"]),
                                config.LONG_DESCRIPTION_LENGTH))
                        else:
                            options["long_description"] = admin_dict["options"]["long_description"]
                            options["long_description_display"] = process_replacements(
                                html.escape(admin_dict["options"]["long_description"]),
                                msg_dict["msgid"],
                                msg_dict["msgid"])
                            options["long_description_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    if len(admin_dict["options"]["long_description"]) > config.LONG_DESCRIPTION_LENGTH:
                        error.append("Long Description too long ({} characters). Max is {}.".format(
                            len(admin_dict["options"]["long_description"]),
                            config.LONG_DESCRIPTION_LENGTH))
                    else:
                        options["long_description"] = admin_dict["options"]["long_description"]
                        options["long_description_display"] = process_replacements(
                            html.escape(admin_dict["options"]["long_description"]),
                            msg_dict["msgid"],
                            msg_dict["msgid"])
                        options["long_description_timestamp_utc"] = admin_dict["timestamp_utc"]

            # Set CSS
            if "css" in admin_dict["options"]:
                chan.allow_css = False
                new_session.commit()
                if "css_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["css_timestamp_utc"]:
                        options["css"] = admin_dict["options"]["css"]
                        options["css_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["css"] = admin_dict["options"]["css"]
                    options["css_timestamp_utc"] = admin_dict["timestamp_utc"]

            # Set word replace
            if "word_replace" in admin_dict["options"]:
                if "word_replace_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["word_replace_timestamp_utc"]:
                        options["word_replace"] = admin_dict["options"]["word_replace"]
                        options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["word_replace"] = admin_dict["options"]["word_replace"]
                    options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]

            if error:
                pass
            elif json.dumps(options) == admin_cmd.options:
                error.append("Options same as in DB. Not updating.")
            else:
                admin_cmd.options = json.dumps(options)
        else:
            # Create new entry
            admin_cmd = Command()
            admin_cmd.chan_address = msg_dict['toAddress']
            admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
            admin_cmd.action = "set"
            admin_cmd.action_type = "options"
            options = {}

            if ("modify_admin_addresses" in admin_dict["options"] and
                    not access_same["secondary_access"]):
                # Check addresses
                for each_add in admin_dict["options"]["modify_admin_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid admin address: {}".format(each_add))
                options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]

            if ("modify_user_addresses" in admin_dict["options"] and
                    not access_same["tertiary_access"]):
                # Check addresses
                for each_add in admin_dict["options"]["modify_user_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid user address: {}".format(each_add))
                options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]

            if ("modify_restricted_addresses" in admin_dict["options"] and
                    not access_same["restricted_access"]):
                # Check addresses
                for each_add in admin_dict["options"]["modify_restricted_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid restricted address: {}".format(each_add))
                options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]

            if "banner_base64" in admin_dict["options"]:
                options["banner_base64"] = admin_dict["options"]["banner_base64"]
                options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]

            if "spoiler_base64" in admin_dict["options"]:
                options["spoiler_base64"] = admin_dict["options"]["spoiler_base64"]
                options["spoiler_base64_timestamp_utc"] = admin_dict["timestamp_utc"]

            if "long_description" in admin_dict["options"]:
                options["long_description"] = admin_dict["options"]["long_description"]
                options["long_description_display"] = process_replacements(
                    html.escape(admin_dict["options"]["long_description"]),
                    msg_dict["msgid"],
                    msg_dict["msgid"])
                options["long_description_timestamp_utc"] = admin_dict["timestamp_utc"]

            if "css" in admin_dict["options"]:
                chan.allow_css = False
                new_session.commit()
                options["css"] = admin_dict["options"]["css"]
                options["css_timestamp_utc"] = admin_dict["timestamp_utc"]

            if "word_replace" in admin_dict["options"]:
                options["word_replace"] = admin_dict["options"]["word_replace"]
                options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]

            if options:
                admin_cmd.options = json.dumps(options)
            else:
                error.append("No valid options received. Not saving.")
            if not error:
                new_session.add(admin_cmd)

        if error:
            logger.info("{}: Errors found while processing custom options for {}".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
            for err in error:
                logger.error("{}: {}".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), err))
        else:
            logger.info("{}: Setting custom options for {}".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
            new_session.commit()

    nexus.trash_message(msg_dict["msgid"])


def admin_delete_from_board(msg_dict, admin_dict):
    from bitchan_flask import nexus

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            logger.error("{}: Admin message contains delete request".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            with session_scope(DB_PATH) as new_session:
                # Check if command already exists
                commands = new_session.query(Command).filter(and_(
                    Command.chan_address == msg_dict['toAddress'],
                    Command.action == "delete",
                    Command.action_type == "delete_post")).all()
                command_exists = False
                for each_cmd in commands:
                    try:
                        options = json.loads(each_cmd.options)
                    except:
                        options = {}
                    if (
                            ("delete_post" in options and
                             "message_id" in options["delete_post"] and
                             "options" in admin_dict and
                             "delete_post" in admin_dict["options"] and
                             "message_id" in admin_dict["options"]["delete_post"] and
                             options["delete_post"]["message_id"] == admin_dict["options"]["delete_post"]["message_id"]) or

                            ("delete_thread" in options and
                             "message_id" in options["delete_thread"] and
                             "thread_id" in options["delete_thread"] and
                             "options" in admin_dict and
                             "delete_thread" in admin_dict["options"] and
                             "message_id" in admin_dict["options"]["delete_thread"] and
                             "thread_id" in admin_dict["options"]["delete_thread"] and
                             options["delete_thread"]["message_id"] == admin_dict["options"]["delete_thread"]["message_id"] and
                             options["delete_thread"]["thread_id"] == admin_dict["options"]["delete_thread"]["thread_id"])
                    ):
                        command_exists = True
                        if "delete_thread" in options:
                            options["delete_thread_timestamp_utc"] = nexus.get_utc()
                        elif "delete_post" in options:
                            options["delete_post_timestamp_utc"] = nexus.get_utc()
                        each_cmd.options = json.dumps(options)
                        logger.error("{}: Admin command already exists. Updating.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))

                if not command_exists:
                    new_admin = Command()
                    new_admin.action = admin_dict["action"]
                    new_admin.action_type = admin_dict["action_type"]

                    if (admin_dict["action_type"] == "delete_post" and
                            "delete_post" in admin_dict["options"] and
                            "thread_id" in admin_dict["options"]["delete_post"] and
                            "message_id" in admin_dict["options"]["delete_post"]):
                        new_admin.chan_address = msg_dict['toAddress']
                        new_admin.options = json.dumps({
                            "delete_post": {
                                "thread_id": admin_dict["options"]["delete_post"]["thread_id"],
                                "message_id": admin_dict["options"]["delete_post"]["message_id"]
                            },
                            "delete_post_timestamp_utc": nexus.get_utc()
                        })
                    elif (admin_dict["action_type"] == "delete_thread" and
                          "delete_thread" in admin_dict["options"] and
                          "thread_id" in admin_dict["options"]["delete_thread"] and
                          "message_id" in admin_dict["options"]["delete_thread"]):
                        new_admin.chan_address = msg_dict['toAddress']
                        new_admin.options = json.dumps({
                            "delete_thread": {
                                "thread_id": admin_dict["options"]["delete_thread"]["thread_id"],
                                "message_id": admin_dict["options"]["delete_thread"]["message_id"]
                            },
                            "delete_thread_timestamp_utc": nexus.get_utc()
                        })
                    else:
                        logger.error("{}: Unknown admin action type: {}".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict["action_type"]))
                        nexus.trash_message(msg_dict["msgid"])
                        return
                    new_session.add(new_admin)
                    new_session.commit()

            # Find if thread/post exist and delete
            if msg_dict['toAddress']:
                with session_scope(DB_PATH) as new_session:
                    admin_chan = new_session.query(Chan).filter(
                        Chan.address == msg_dict['toAddress']).first()
                    if not admin_chan:
                        logger.error("{}: Unknown board in Admin message. Discarding.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        nexus.trash_message(msg_dict["msgid"])
                        return

                logger.error("{}: Admin message board found".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))

                # Admin: Delete post
                if (admin_dict["action_type"] == "delete_post" and
                        "delete_post" in admin_dict["options"] and
                        "thread_id" in admin_dict["options"]["delete_post"] and
                        "message_id" in admin_dict["options"]["delete_post"]):
                    logger.error("{}: Admin message to delete post {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict["options"]["delete_post"]["message_id"]))
                    delete_db_message(admin_dict["options"]["delete_post"]["message_id"])
                    try:
                        nexus.delete_message(
                            msg_dict['toAddress'],
                            admin_dict["options"]["delete_post"]["thread_id"],
                            admin_dict["options"]["delete_post"]["message_id"])
                    except:
                        pass

                # Admin: Delete thread
                elif (admin_dict["action_type"] == "delete_thread" and
                      "delete_thread" in admin_dict["options"] and
                      "thread_id" in admin_dict["options"]["delete_thread"] and
                      "message_id" in admin_dict["options"]["delete_thread"]):
                    logger.error("{}: Admin message to delete thread {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict["options"]["delete_thread"]["thread_id"]))
                    # Delete all messages in thread
                    messages = new_session.query(Messages).filter(
                        Messages.thread_id == admin_dict["options"]["delete_thread"]["thread_id"]).all()
                    for message in messages:
                        delete_db_message(message.message_id)
                    # Delete the thread
                    thread = new_session.query(Threads).filter(
                        Threads.thread_hash == admin_dict["options"]["delete_thread"]["thread_id"]).first()
                    if thread:
                        new_session.delete(thread)
                        new_session.commit()
                    try:
                        nexus.delete_thread(
                            msg_dict['toAddress'],
                            admin_dict["options"]["delete_thread"]["thread_id"])
                    except:
                        pass
                nexus.trash_message(msg_dict["msgid"])
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)


def admin_delete_from_board_with_comment(msg_dict, admin_dict):
    """Delete a post with comment (really just replace the message and removes attachments)"""
    from bitchan_flask import nexus

    try:
        logger.error("{}: Admin message contains delete with comment request".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        with session_scope(DB_PATH) as new_session:
            # Find if thread/post exist and delete
            admin_chan = new_session.query(Chan).filter(
                Chan.address == msg_dict['toAddress']).first()
            if not admin_chan:
                logger.error("{}: Unknown board in Admin message. Discarding.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                nexus.trash_message(msg_dict["msgid"])
                return

            # Check if command already exists
            commands = new_session.query(Command).filter(and_(
                Command.chan_address == msg_dict['toAddress'],
                Command.action == "delete_comment",
                Command.action_type == "post")).all()
            command_exists = False
            for each_cmd in commands:
                try:
                    options = json.loads(each_cmd.options)
                except:
                    options = {}
                if ("delete_comment" in options and
                        "message_id" in options["delete_comment"] and
                        "comment" in options["delete_comment"] and
                        options["delete_comment"]["message_id"] == admin_dict["options"]["delete_comment"][
                            "message_id"]):
                    command_exists = True
                    options["delete_comment_timestamp_utc"] = nexus.get_utc()
                    each_cmd.options = json.dumps(options)
                    logger.error("{}: Admin command already exists. Updating.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))

            if not command_exists:
                new_admin = Command()
                new_admin.action = admin_dict["action"]
                new_admin.action_type = admin_dict["action_type"]
                new_admin.chan_address = msg_dict['toAddress']
                new_admin.options = json.dumps({
                    "delete_comment": {
                        "comment": admin_dict["options"]["delete_comment"]["comment"],
                        "message_id": admin_dict["options"]["delete_comment"]["message_id"]
                    },
                    "delete_comment_timestamp_utc": nexus.get_utc()
                })
                new_session.add(new_admin)
                new_session.commit()

            if (admin_dict["options"]["delete_comment"]["message_id"] and
                    admin_dict["options"]["delete_comment"]["comment"]):
                logger.error("{}: Admin message to delete post {} with comment".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict["options"]["delete_comment"]["message_id"]))
                delete_and_replace_comment(
                    admin_dict["options"]["delete_comment"]["message_id"],
                    admin_dict["options"]["delete_comment"]["comment"])
    finally:
        nexus.trash_message(msg_dict["msgid"])


def admin_ban_address_from_board(msg_dict, admin_dict):
    from bitchan_flask import nexus

    if admin_dict["options"]["ban_address"] in nexus._identity_dict:
        # Don't ban yournexus, fool
        nexus.trash_message(msg_dict["msgid"])
        return

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            logger.error("{}: Admin message contains ban request".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            with session_scope(DB_PATH) as new_session:
                # Check if admin entry already exists
                command_exists = False
                commands = new_session.query(Command).filter(and_(
                    Command.action == admin_dict["action"],
                    Command.action_type == admin_dict["action_type"],
                    Command.chan_address == admin_dict["chan_address"])).all()
                for each_cmd in commands:
                    try:
                        options = json.loads(each_cmd.options)
                    except:
                        options = {}
                    if ("ban_address" in options and
                            admin_dict["options"]["ban_address"] == options["ban_address"]):
                        logger.error("{}: Ban already exists in database. Updating".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        options["ban_address_timestamp_utc"] = admin_dict["timestamp_utc"]
                        each_cmd.options = json.dumps(options)
                        command_exists = True

                if not command_exists:
                    logger.error("{}: Adding ban to database".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    new_admin = Command()
                    new_admin.action = admin_dict["action"]
                    new_admin.action_type = admin_dict["action_type"]
                    new_admin.chan_address = admin_dict["chan_address"]
                    options = {
                        "ban_address": admin_dict["options"]["ban_address"],
                        "ban_address_timestamp_utc": nexus.get_utc()
                    }
                    new_admin.options = json.dumps(options)
                    new_session.add(new_admin)
                    new_session.commit()

            # Find messages and delete
            with session_scope(DB_PATH) as new_session:
                messages = new_session.query(Messages).filter(
                    Messages.address_from == admin_dict["options"]["ban_address"]).all()
                if messages:
                    # Admin: Delete post
                    for each_message in messages:
                        if each_message.thread.chan.address == admin_dict["chan_address"]:
                            delete_db_message(each_message.message_id)
            nexus.trash_message(msg_dict["msgid"])
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)
