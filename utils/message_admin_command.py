import base64
import json
import logging
import time
from io import BytesIO

import gnupg
from PIL import Image
from sqlalchemy import and_
from sqlalchemy import or_

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Command
from database.models import Messages
from database.models import Threads
from database.utils import session_scope
from utils.files import LF
from utils.gateway import api
from utils.gateway import delete_and_replace_comment
from utils.general import get_random_alphanumeric_string
from utils.general import is_bitmessage_address
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.replacements import process_replacements
from utils.replacements import replace_lt_gt
from utils.shared import add_mod_log_entry
from utils.shared import get_access
from utils.shared import is_access_same_as_db
from utils.shared import regenerate_card_popup_post_html

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.admin_command')
daemon_com = DaemonCom()


def send_commands():
    """Send admin commands prior to them expiring to ensure options are available to all users"""
    try:
        run_id = get_random_alphanumeric_string(
            6, with_punctuation=False, with_spaces=False)
        with session_scope(DB_PATH) as new_session:
            admin_cmds = new_session.query(Command).filter(
                Command.do_not_send.is_(False)).all()
            for each_cmd in admin_cmds:
                try:
                    options = json.loads(each_cmd.options)
                except:
                    options = {}

                if (not each_cmd.options and
                        not each_cmd.thread_sticky_timestamp_utc and
                        not each_cmd.thread_lock_timestamp_utc and
                        not each_cmd.thread_anchor_timestamp_utc):
                    logger.info("{}: No options found for Admin command to send.".format(run_id))
                    continue

                # Determine if we have an authorized address to send from
                chan = new_session.query(Chan).filter(
                    Chan.address == each_cmd.chan_address).first()
                if not chan:
                    logger.info("{}: Chan not found in DB".format(run_id))
                    continue

                def admin_has_access(address):
                    access = get_access(address)
                    for id_type in [daemon_com.get_identities(), daemon_com.get_all_chans()]:
                        for address in id_type:
                            if id_type[address]['enabled'] and address in access["primary_addresses"]:
                                return address

                from_address = admin_has_access(chan.address)
                if not from_address:
                    continue

                # Add thread settings to options dict
                if each_cmd.thread_sticky_timestamp_utc:
                    options["sticky"] = each_cmd.thread_sticky
                    options["sticky_timestamp_utc"] = each_cmd.thread_sticky_timestamp_utc
                if each_cmd.thread_lock_timestamp_utc:
                    options["lock"] = each_cmd.thread_lock
                    options["lock_ts"] = each_cmd.thread_lock_ts
                    options["lock_timestamp_utc"] = each_cmd.thread_lock_timestamp_utc
                if each_cmd.thread_anchor_timestamp_utc:
                    options["anchor"] = each_cmd.thread_anchor
                    options["anchor_ts"] = each_cmd.thread_anchor_ts
                    options["anchor_timestamp_utc"] = each_cmd.thread_anchor_timestamp_utc

                logger.info("{}: Checking commands for board {}".format(
                    run_id, each_cmd.chan_address))

                for each_option in options:
                    # Send a new admin command message for each option or option set if it's near expiration
                    dict_message = {
                        "version": config.VERSION_MSG,
                        "timestamp_utc": daemon_com.get_utc(),
                        "message_type": "admin",
                        "action": each_cmd.action,
                        "action_type": each_cmd.action_type,
                        "message_id": each_cmd.message_id,
                        "thread_id": each_cmd.thread_id,
                        "chan_address": each_cmd.chan_address,
                        "options": {}
                    }

                    def is_expiring(ts_utc):
                        exp_days = (daemon_com.get_utc() - ts_utc) / 60 / 60 / 24
                        if exp_days > 20:
                            return True, exp_days
                        else:
                            return False, exp_days

                    option_ts = "{}_timestamp_utc".format(each_option)

                    # Board/list options
                    if each_option in config.ADMIN_OPTIONS and option_ts in options:
                        expiring, days = is_expiring(options[option_ts])
                        if expiring:
                            logger.info("{}: {} {:.1f} days old: expiring".format(
                                run_id, each_option, days))
                            dict_message["options"][each_option] = options[each_option]

                            # Extra options
                            if each_option in ["board_ban_silent", "board_ban_public"] and "reason" in options:
                                dict_message["options"]["reason"] = options["reason"]
                        else:
                            logger.info("{}: {} {:.1f} days old: not expiring".format(
                                run_id, each_option, days))

                    # Thread options (require extra timestamp variable to be sent for lock/anchor)
                    elif each_option in ["sticky", "lock", "anchor"]:
                        expiring, days = is_expiring(options[option_ts])
                        if expiring:
                            logger.info("{}: {}: {} {:.1f} days old: expiring".format(
                                run_id, each_cmd.thread_id[-12:], each_option, days))
                            dict_message["options"][each_option] = options[each_option]

                            # Extra options
                            if each_option == "lock" and "lock_ts" in options:
                                dict_message["options"]["lock_ts"] = options["lock_ts"]
                            if each_option == "anchor" and "anchor_ts" in options:
                                dict_message["options"]["anchor_ts"] = options["anchor_ts"]
                        else:
                            logger.info("{}: {}: {} {:.1f} days old: not expiring".format(
                                run_id, each_cmd.thread_id[-12:], each_option, days))

                    if not dict_message["options"]:
                        logger.debug("{}: No options nearing expiration".format(run_id))
                        continue

                    pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                    if chan.pgp_passphrase_msg:
                        pgp_passphrase_msg = chan.pgp_passphrase_msg

                    logger.info("{}: Cmd dict: {}".format(run_id, dict_message))
                    logger.info("{}: From {}, To: {}".format(run_id, from_address, chan.address))

                    str_message = json.dumps(dict_message)
                    gpg = gnupg.GPG()
                    message_encrypted = gpg.encrypt(
                        str_message,
                        symmetric="AES256",
                        passphrase=pgp_passphrase_msg,
                        recipients=None)
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
                                "Could not detect Bitmessage running.".format(run_id))
                            return
                        time.sleep(1)

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
                                logger.info("{}: Sent command options. Return: {}".format(
                                    run_id, return_str))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)
    except:
        logger.exception("send_commands()")


def admin_set_options(msg_dict, admin_dict):
    """
    Set custom options for board or list
    e.g. Banner, CSS, word replace, access
    """
    error = []

    if admin_dict["timestamp_utc"] - (60 * 60 * 6) > daemon_com.get_utc():
        # message timestamp is in the distant future. Delete.
        logger.error("{}: Command has future timestamp. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(msg_dict["msgid"])
        return

    if "options" not in admin_dict:
        logger.error("{}: Missing 'options' to set.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(msg_dict["msgid"])
        return

    if "banner_base64" in admin_dict["options"]:
        # Verify image is not larger than max dimensions
        im = Image.open(BytesIO(base64.b64decode(admin_dict["options"]["banner_base64"])))
        media_width, media_height = im.size
        if media_width > config.BANNER_MAX_WIDTH or media_height > config.BANNER_MAX_HEIGHT:
            logger.error("{}: Banner image too large. Discarding admin message.".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            daemon_com.trash_message(msg_dict["msgid"])
            return

    if not msg_dict['toAddress']:
        logger.error("No toAddress found in dict")
        daemon_com.trash_message(msg_dict["msgid"])
        return

    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == msg_dict['toAddress']).first()
        admin_cmd = new_session.query(Command).filter(and_(
            Command.chan_address == msg_dict['toAddress'],
            Command.action == "set",
            Command.action_type == "options")).first()

        access_same = is_access_same_as_db(admin_dict["options"], chan)

        add_mod_log = False

        if admin_cmd:
            # Modify current entry
            if admin_dict["timestamp_utc"] > admin_cmd.timestamp_utc:
                admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
            try:
                options = json.loads(admin_cmd.options)
            except:
                options = {}
            log_description_list = []

            # Set modify_admin_addresses
            if "modify_admin_addresses" in admin_dict["options"]:
                do_log = False

                if "modify_admin_addresses" in options and access_same["secondary_access"]:
                    do_log = "Revert to original Admin list"
                    add_mod_log = True

                # Check addresses
                for each_add in admin_dict["options"]["modify_admin_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid admin address: {}".format(each_add))

                # Add/Mod addresses
                if "modify_admin_addresses_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["modify_admin_addresses_timestamp_utc"]:
                        if (not access_same["secondary_access"] and
                                (
                                    ("modify_admin_addresses" in options and
                                     options["modify_admin_addresses"] != admin_dict["options"]["modify_admin_addresses"])
                                    or
                                    "modify_admin_addresses" not in options
                                )):
                            do_log = admin_dict["options"]["modify_admin_addresses"]
                            add_mod_log = True
                        options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                        options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                    options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    if not access_same["secondary_access"]:
                        do_log = admin_dict["options"]["modify_admin_addresses"]
                        add_mod_log = True

                # Last pass, delete entries if same as in chan db
                if access_same["secondary_access"]:
                    options.pop('modify_admin_addresses', None)

                if do_log:
                    log_description_list.append("Admin addresses: {}".format(do_log))

                regenerate_card_popup_post_html(all_posts_of_board_address=msg_dict['toAddress'])

            # Set modify_user_addresses
            if "modify_user_addresses" in admin_dict["options"]:
                do_log = False

                if "modify_user_addresses" in options and access_same["tertiary_access"]:
                    do_log = "Revert to original User list"
                    add_mod_log = True

                # Check addresses
                for each_add in admin_dict["options"]["modify_user_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid user address: {}".format(each_add))

                # Add/Mod addresses
                if "modify_user_addresses_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["modify_user_addresses_timestamp_utc"]:
                        if (not access_same["tertiary_access"] and
                                (
                                    ("modify_user_addresses" in options and
                                     options["modify_user_addresses"] != admin_dict["options"][
                                         "modify_user_addresses"])
                                    or
                                    "modify_user_addresses" not in options
                                )):
                            do_log = admin_dict["options"]["modify_user_addresses"]
                            add_mod_log = True
                        options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                        options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                    options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    if not access_same["tertiary_access"]:
                        do_log = admin_dict["options"]["modify_user_addresses"]
                        add_mod_log = True

                # Last pass, delete entries if same as in chan db
                if access_same["tertiary_access"]:
                    options.pop('modify_user_addresses', None)

                if do_log:
                    log_description_list.append("User addresses: {}".format(do_log))

            # Set modify_restricted_addresses
            if "modify_restricted_addresses" in admin_dict["options"]:
                do_log = False

                if "modify_restricted_addresses" in options and access_same["restricted_access"]:
                    do_log = "Revert to original Restricted list"
                    add_mod_log = True

                # Check addresses
                for each_add in admin_dict["options"]["modify_restricted_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid restricted address: {}".format(each_add))

                # Add/Mod addresses
                if "modify_restricted_addresses_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["modify_restricted_addresses_timestamp_utc"]:
                        if (not access_same["restricted_access"] and
                                (
                                    ("modify_restricted_addresses" in options and
                                     options["modify_restricted_addresses"] != admin_dict["options"][
                                         "modify_restricted_addresses"])
                                    or
                                    "modify_restricted_addresses" not in options
                                )):
                            do_log = admin_dict["options"]["modify_restricted_addresses"]
                            add_mod_log = True
                        options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                        options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                else:
                    options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                    options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                    if not access_same["restricted_access"]:
                        do_log = admin_dict["options"]["modify_restricted_addresses"]
                        add_mod_log = True

                # Last pass, delete entries if same as in chan db
                if access_same["restricted_access"]:
                    options.pop('modify_restricted_addresses', None)

                if do_log:
                    log_description_list.append("Restricted addresses: {}".format(do_log))

            # Set banner
            if "banner_base64" in admin_dict["options"]:
                do_log = False
                if "banner_base64_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["banner_base64_timestamp_utc"]:
                        if options["banner_base64"] != admin_dict["options"]["banner_base64"]:
                            add_mod_log = True
                        options["banner_base64"] = admin_dict["options"]["banner_base64"]
                        options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]
                        do_log = "Update"
                else:
                    options["banner_base64"] = admin_dict["options"]["banner_base64"]
                    options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]
                    do_log = "Set"
                    add_mod_log = True
                if do_log:
                    log_description_list.append("Banner Image: {}".format(do_log))

            # Set Long Description
            if "long_description" in admin_dict["options"]:
                do_log = False
                if "long_description_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["long_description_timestamp_utc"]:
                        if len(admin_dict["options"]["long_description"]) > config.LONG_DESCRIPTION_LENGTH:
                            error.append("Long Description too long ({} characters). Max is {}.".format(
                                len(admin_dict["options"]["long_description"]),
                                config.LONG_DESCRIPTION_LENGTH))
                        else:
                            if options["long_description"] != admin_dict["options"]["long_description"]:
                                add_mod_log = True
                            options["long_description"] = admin_dict["options"]["long_description"]
                            options["long_description_display"] = process_replacements(
                                replace_lt_gt(admin_dict["options"]["long_description"]),
                                msg_dict["msgid"],
                                msg_dict["msgid"])
                            options["long_description_timestamp_utc"] = admin_dict["timestamp_utc"]
                            do_log = "Update"
                else:
                    if len(admin_dict["options"]["long_description"]) > config.LONG_DESCRIPTION_LENGTH:
                        error.append("Long Description too long ({} characters). Max is {}.".format(
                            len(admin_dict["options"]["long_description"]),
                            config.LONG_DESCRIPTION_LENGTH))
                    else:
                        options["long_description"] = admin_dict["options"]["long_description"]
                        options["long_description_display"] = process_replacements(
                            replace_lt_gt(admin_dict["options"]["long_description"]),
                            msg_dict["msgid"],
                            msg_dict["msgid"])
                        options["long_description_timestamp_utc"] = admin_dict["timestamp_utc"]
                        do_log = "Set"
                        add_mod_log = True
                if do_log:
                    log_description_list.append("Description: {}".format(do_log))

            # Set CSS
            if "css" in admin_dict["options"]:
                do_log = False
                chan.allow_css = False
                new_session.commit()
                if "css_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["css_timestamp_utc"]:
                        if options["css"] != admin_dict["options"]["css"]:
                            add_mod_log = True
                        options["css"] = admin_dict["options"]["css"]
                        options["css_timestamp_utc"] = admin_dict["timestamp_utc"]
                        do_log = "Update"
                else:
                    options["css"] = admin_dict["options"]["css"]
                    options["css_timestamp_utc"] = admin_dict["timestamp_utc"]
                    do_log = "Set"
                    add_mod_log = True
                if do_log:
                    log_description_list.append("Custom CSS: {}".format(do_log))

            # Set word replace
            if "word_replace" in admin_dict["options"]:
                do_log = False
                if "word_replace_timestamp_utc" in options:
                    if admin_dict["timestamp_utc"] > options["word_replace_timestamp_utc"]:
                        if options["word_replace"] != admin_dict["options"]["word_replace"]:
                            add_mod_log = True
                        options["word_replace"] = admin_dict["options"]["word_replace"]
                        options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]
                        do_log = "Update"
                else:
                    options["word_replace"] = admin_dict["options"]["word_replace"]
                    options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]
                    do_log = "Set"
                    add_mod_log = True
                if do_log:
                    log_description_list.append("Word Replacements: {}".format(do_log))

            log_description = "Options modified: {}".format(
                ", ".join(log_description_list))

            if error:
                pass
            elif json.dumps(options) == admin_cmd.options:
                logger.info("Options same as in DB. Not updating options, only TS.")
            else:
                admin_cmd.options = json.dumps(options)

            if not error:
                logger.info("{}: Modifying custom options for {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
                new_session.commit()
        else:
            # Create new entry
            admin_cmd = Command()
            admin_cmd.chan_address = msg_dict['toAddress']
            admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
            admin_cmd.action = "set"
            admin_cmd.action_type = "options"
            options = {}
            log_description_list = []

            if ("modify_admin_addresses" in admin_dict["options"] and
                    not access_same["secondary_access"]):
                # Check addresses
                for each_add in admin_dict["options"]["modify_admin_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid admin address: {}".format(each_add))
                options["modify_admin_addresses"] = admin_dict["options"]["modify_admin_addresses"]
                options["modify_admin_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                log_description_list.append(
                    "Admin addresses: {}".format(
                        admin_dict["options"]["modify_admin_addresses"]))

                regenerate_card_popup_post_html(all_posts_of_board_address=msg_dict['toAddress'])

            if ("modify_user_addresses" in admin_dict["options"] and
                    not access_same["tertiary_access"]):
                # Check addresses
                for each_add in admin_dict["options"]["modify_user_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid user address: {}".format(each_add))
                options["modify_user_addresses"] = admin_dict["options"]["modify_user_addresses"]
                options["modify_user_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                log_description_list.append(
                    "User addresses: {}".format(
                        admin_dict["options"]["modify_user_addresses"]))

            if ("modify_restricted_addresses" in admin_dict["options"] and
                    not access_same["restricted_access"]):
                # Check addresses
                for each_add in admin_dict["options"]["modify_restricted_addresses"]:
                    if not is_bitmessage_address(each_add):
                        error.append("Invalid restricted address: {}".format(each_add))
                options["modify_restricted_addresses"] = admin_dict["options"]["modify_restricted_addresses"]
                options["modify_restricted_addresses_timestamp_utc"] = admin_dict["timestamp_utc"]
                log_description_list.append(
                    "Restricted addresses: {}".format(
                        admin_dict["options"]["modify_restricted_addresses"]))

            if "banner_base64" in admin_dict["options"]:
                options["banner_base64"] = admin_dict["options"]["banner_base64"]
                options["banner_base64_timestamp_utc"] = admin_dict["timestamp_utc"]
                log_description_list.append("Banner Image")

            if "long_description" in admin_dict["options"]:
                options["long_description"] = admin_dict["options"]["long_description"]
                options["long_description_display"] = process_replacements(
                    replace_lt_gt(admin_dict["options"]["long_description"]),
                    msg_dict["msgid"],
                    msg_dict["msgid"])
                options["long_description_timestamp_utc"] = admin_dict["timestamp_utc"]
                log_description_list.append("Description")

            if "css" in admin_dict["options"]:
                chan.allow_css = False
                new_session.commit()
                options["css"] = admin_dict["options"]["css"]
                options["css_timestamp_utc"] = admin_dict["timestamp_utc"]
                log_description_list.append("Custom CSS")

            if "word_replace" in admin_dict["options"]:
                options["word_replace"] = admin_dict["options"]["word_replace"]
                options["word_replace_timestamp_utc"] = admin_dict["timestamp_utc"]
                log_description_list.append("Word Replacements")

            add_mod_log = True
            log_description = "Options initially set: {}".format(
                ", ".join(log_description_list))

            if options:
                admin_cmd.options = json.dumps(options)
            else:
                error.append("No valid options received. Not saving.")

            if not error:
                logger.info("{}: Saving new custom options for {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
                new_session.add(admin_cmd)

        if add_mod_log and not error:
            add_mod_log_entry(
                log_description,
                user_from=msg_dict['fromAddress'],
                board_address=msg_dict['toAddress'])

        if error:
            logger.info("{}: Errors found while processing custom options for {}".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper(), msg_dict['toAddress']))
            for err in error:
                logger.error("{}: {}".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), err))

    daemon_com.trash_message(msg_dict["msgid"])


def admin_set_thread_options(msg_dict, admin_dict):
    """
    Set options for thread
    e.g. sticky, lock
    """
    error = []
    message_id = None

    if admin_dict["timestamp_utc"] - (60 * 60 * 6) > daemon_com.get_utc():
        # message timestamp is in the distant future. Delete.
        logger.error("{}: Command has future timestamp. Deleting.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(msg_dict["msgid"])
        return

    if "options" not in admin_dict:
        logger.error("{}: Missing 'options' to set.".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        daemon_com.trash_message(msg_dict["msgid"])
        return

    if not msg_dict['toAddress']:
        logger.error("No toAddress found in dict")
        daemon_com.trash_message(msg_dict["msgid"])
        return

    add_mod_log = False

    with session_scope(DB_PATH) as new_session:
        admin_cmd = new_session.query(Command).filter(and_(
            Command.chan_address == msg_dict['toAddress'],
            Command.thread_id == admin_dict['thread_id'],
            Command.action == "set",
            Command.action_type == "thread_options")).first()

        if admin_cmd:
            # Modify current entry
            if admin_dict["timestamp_utc"] > admin_cmd.timestamp_utc:
                admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
            log_description_list = []

            # Set sticky
            if "sticky" in admin_dict["options"]:
                do_log = False
                if admin_cmd.thread_sticky_timestamp_utc:
                    if admin_dict["timestamp_utc"] > admin_cmd.thread_sticky_timestamp_utc:
                        if admin_cmd.thread_sticky != admin_dict["options"]["sticky"]:
                            add_mod_log = True
                        admin_cmd.thread_sticky = admin_dict["options"]["sticky"]
                        admin_cmd.thread_sticky_timestamp_utc = admin_dict["timestamp_utc"]
                        do_log = "Update"
                else:
                    admin_cmd.thread_sticky = admin_dict["options"]["sticky"]
                    admin_cmd.thread_sticky_timestamp_utc = admin_dict["timestamp_utc"]
                    do_log = "Set"
                    add_mod_log = True
                if do_log:
                    log_description_list.append("Sticky: {} {}".format(
                        do_log, admin_dict["options"]["sticky"]))

            # Set lock
            if "lock" in admin_dict["options"]:
                do_log = False
                if admin_cmd.thread_lock_timestamp_utc:
                    if admin_dict["timestamp_utc"] > admin_cmd.thread_lock_timestamp_utc:
                        if admin_cmd.thread_lock != admin_dict["options"]["lock"]:
                            add_mod_log = True
                        admin_cmd.thread_lock = admin_dict["options"]["lock"]
                        admin_cmd.thread_lock_ts = admin_dict["options"]["lock_ts"]
                        admin_cmd.thread_lock_timestamp_utc = admin_dict["timestamp_utc"]
                        do_log = "Update"
                else:
                    admin_cmd.thread_lock = admin_dict["options"]["lock"]
                    admin_cmd.thread_lock_ts = admin_dict["options"]["lock_ts"]
                    admin_cmd.thread_lock_timestamp_utc = admin_dict["timestamp_utc"]
                    do_log = "Set"
                    add_mod_log = True
                if do_log:
                    log_description_list.append("Lock: {} {}".format(
                        do_log, admin_dict["options"]["lock"]))

            # Set anchor
            if "anchor" in admin_dict["options"]:
                do_log = False
                if admin_cmd.thread_anchor_timestamp_utc:
                    if admin_dict["timestamp_utc"] > admin_cmd.thread_anchor_timestamp_utc:
                        if admin_cmd.thread_anchor != admin_dict["options"]["anchor"]:
                            add_mod_log = True
                        admin_cmd.thread_anchor = admin_dict["options"]["anchor"]
                        admin_cmd.thread_anchor_ts = admin_dict["options"]["anchor_ts"]
                        admin_cmd.thread_anchor_timestamp_utc = admin_dict["timestamp_utc"]
                        do_log = "Update"
                else:
                    admin_cmd.thread_anchor = admin_dict["options"]["anchor"]
                    admin_cmd.thread_anchor_ts = admin_dict["options"]["anchor_ts"]
                    admin_cmd.thread_anchor_timestamp_utc = admin_dict["timestamp_utc"]
                    do_log = "Set"
                    add_mod_log = True
                if do_log:
                    log_description_list.append("Anchor: {} {}".format(
                        do_log, admin_dict["options"]["anchor"]))

            log_description = "Thread options modified: {}".format(
                ", ".join(log_description_list))

            if not error:
                logger.info("{}: Modifying options for thread {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict['thread_id']))
                new_session.commit()
        else:
            # Create new entry
            admin_cmd = Command()
            admin_cmd.chan_address = msg_dict['toAddress']
            admin_cmd.thread_id = admin_dict['thread_id']
            admin_cmd.timestamp_utc = admin_dict["timestamp_utc"]
            admin_cmd.action = "set"
            admin_cmd.action_type = "thread_options"
            log_description_list = []

            if "sticky" in admin_dict["options"]:
                admin_cmd.thread_sticky = admin_dict["options"]["sticky"]
                admin_cmd.thread_sticky_timestamp_utc = admin_dict["timestamp_utc"]
                log_description_list.append("Sticky {}".format(admin_dict["options"]["sticky"]))

            if "lock" in admin_dict["options"]:
                admin_cmd.thread_lock = admin_dict["options"]["lock"]
                admin_cmd.thread_lock_ts = admin_dict["options"]["lock_ts"]
                admin_cmd.thread_lock_timestamp_utc = admin_dict["timestamp_utc"]
                log_description_list.append("Lock {}".format(admin_dict["options"]["lock"]))

            if "anchor" in admin_dict["options"]:
                admin_cmd.thread_anchor = admin_dict["options"]["anchor"]
                admin_cmd.thread_anchor_ts = admin_dict["options"]["anchor_ts"]
                admin_cmd.thread_anchor_timestamp_utc = admin_dict["timestamp_utc"]
                log_description_list.append("Anchor {}".format(admin_dict["options"]["anchor"]))

            add_mod_log = True
            log_description = "Thread options initially set: {}".format(
                ", ".join(log_description_list))

            if not error:
                logger.info("{}: Saving new thread options for thread {} of board {}".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict['thread_id'], msg_dict['toAddress']))
                new_session.add(admin_cmd)
                new_session.commit()

        thread = new_session.query(Threads).filter(
            Threads.thread_hash == admin_dict['thread_id']).first()
        if thread:
            message = new_session.query(Messages).filter(and_(
                Messages.thread_id == thread.id,
                Messages.is_op.is_(True))).first()
            if message:
                message_id = message.message_id
        new_session.expunge_all()
        new_session.close()

    if not error:
        if thread:
            regenerate_card_popup_post_html(thread_hash=thread.thread_hash)

        if add_mod_log:
            add_mod_log_entry(
                log_description,
                message_id=message_id,
                user_from=msg_dict['fromAddress'],
                board_address=msg_dict['toAddress'],
                thread_hash=admin_dict['thread_id'])

    if error:
        logger.info("{}: Errors found while processing options for thread {}".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict['thread_id']))
        for err in error:
            logger.error("{}: {}".format(msg_dict["msgid"][-config.ID_LENGTH:].upper(), err))

    daemon_com.trash_message(msg_dict["msgid"])


def admin_delete_from_board(msg_dict, admin_dict):
    """ Admin command to remotely delete a thread or post from a board """
    local_override = False

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
        try:
            logger.error("{}: Admin message contains delete request".format(
                msg_dict["msgid"][-config.ID_LENGTH:].upper()))
            with session_scope(DB_PATH) as new_session:
                # Check if command already exists
                commands = new_session.query(Command).filter(
                    and_(Command.chan_address == msg_dict['toAddress'],
                         Command.action == "delete",
                         or_(Command.action_type == "delete_post",
                             Command.action_type == "delete_thread"))).all()
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
                             options["delete_post"]["message_id"] == admin_dict["options"]["delete_post"]["message_id"])

                            or

                            ("delete_thread" in options and
                             "thread_id" in options["delete_thread"] and
                             "options" in admin_dict and
                             "delete_thread" in admin_dict["options"] and
                             "thread_id" in admin_dict["options"]["delete_thread"] and
                             options["delete_thread"]["thread_id"] == admin_dict["options"]["delete_thread"]["thread_id"])
                    ):
                        command_exists = True
                        if "delete_thread" in options:
                            options["delete_thread_timestamp_utc"] = daemon_com.get_utc()
                        elif "delete_post" in options:
                            options["delete_post_timestamp_utc"] = daemon_com.get_utc()
                        each_cmd.options = json.dumps(options)
                        logger.error("{}: Admin command already exists. Updating.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        if each_cmd.locally_restored or each_cmd.locally_deleted:
                            local_override = True
                        break

                if not command_exists:
                    new_admin = Command()
                    new_admin.action = admin_dict["action"]
                    new_admin.action_type = admin_dict["action_type"]

                    if (admin_dict["action_type"] == "delete_post" and
                            "delete_post" in admin_dict["options"] and
                            "message_id" in admin_dict["options"]["delete_post"]):
                        new_admin.chan_address = msg_dict['toAddress']
                        new_admin.options = json.dumps({
                            "delete_post": {
                                "message_id": admin_dict["options"]["delete_post"]["message_id"]
                            },
                            "delete_post_timestamp_utc": daemon_com.get_utc()
                        })
                    elif (admin_dict["action_type"] == "delete_thread" and
                          "delete_thread" in admin_dict["options"] and
                          "thread_id" in admin_dict["options"]["delete_thread"]):
                        new_admin.chan_address = msg_dict['toAddress']
                        new_admin.options = json.dumps({
                            "delete_thread": {
                                "thread_id": admin_dict["options"]["delete_thread"]["thread_id"]
                            },
                            "delete_thread_timestamp_utc": daemon_com.get_utc()
                        })
                    else:
                        logger.error("{}: Unknown admin action type: {}".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper(), admin_dict["action_type"]))
                        daemon_com.trash_message(msg_dict["msgid"])
                        return
                    new_session.add(new_admin)
                    new_session.commit()

            if local_override:
                logger.info("{}: Admin cannot delete post/thread due to local override".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))

            # Find if thread/post exist and delete
            elif msg_dict['toAddress']:
                with session_scope(DB_PATH) as new_session:
                    admin_chan = new_session.query(Chan).filter(
                        Chan.address == msg_dict['toAddress']).first()
                    if not admin_chan:
                        logger.error("{}: Unknown board in Admin message. Discarding.".format(
                            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                        daemon_com.trash_message(msg_dict["msgid"])
                        return

                logger.error("{}: Admin message board found".format(msg_dict["msgid"][-config.ID_LENGTH:].upper()))

                # Admin: Delete post
                if (admin_dict["action_type"] == "delete_post" and
                        "delete_post" in admin_dict["options"] and
                        "message_id" in admin_dict["options"]["delete_post"]):
                    logger.error("{}: Admin message to delete post {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                        admin_dict["options"]["delete_post"]["message_id"]))
                    delete_post(admin_dict["options"]["delete_post"]["message_id"], only_hide=True)

                    with session_scope(DB_PATH) as new_session:
                        message = new_session.query(Messages).filter(
                            Messages.message_id == admin_dict["options"]["delete_post"]["message_id"]).first()
                        thread_hash = None
                        if message and message.thread:
                            thread_hash = message.thread.thread_hash

                        add_mod_log_entry(
                            "Remotely delete post (locally hidden)",
                            message_id=admin_dict["options"]["delete_post"]["message_id"],
                            user_from=msg_dict['fromAddress'],
                            board_address=msg_dict['toAddress'],
                            thread_hash=thread_hash,
                            hidden=True)

                # Admin: Delete thread
                elif (admin_dict["action_type"] == "delete_thread" and
                      "delete_thread" in admin_dict["options"] and
                      "thread_id" in admin_dict["options"]["delete_thread"]):
                    logger.error("{}: Admin message to delete thread {}".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                        admin_dict["options"]["delete_thread"]["thread_id"]))
                    # Delete all messages in thread
                    messages = new_session.query(Messages).filter(
                        Messages.thread_id == admin_dict["options"]["delete_thread"]["thread_id"]).all()
                    for message in messages:
                        delete_post(message.message_id, only_hide=True)

                    thread = new_session.query(Threads).filter(
                        Threads.thread_hash == admin_dict["options"]["delete_thread"]["thread_id"]).first()
                    if thread:
                        log_description = 'Remotely deleted thread: "{}" (locally hidden)'.format(thread.subject)

                        add_mod_log_entry(
                            log_description,
                            user_from=msg_dict['fromAddress'],
                            board_address=msg_dict['toAddress'],
                            thread_hash=admin_dict["options"]["delete_thread"]["thread_id"],
                            hidden=True)

                        # Delete the thread
                        delete_thread(admin_dict["options"]["delete_thread"]["thread_id"], only_hide=True)
                    logger.error("{}: Cannot delete thread that doesn't exist".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))

                daemon_com.trash_message(msg_dict["msgid"])
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)


def admin_delete_from_board_with_comment(msg_dict, admin_dict):
    """Delete a post with comment (really just replace the message and removes attachments)"""
    local_override = False

    try:
        logger.info("{}: Admin message contains delete with comment request".format(
            msg_dict["msgid"][-config.ID_LENGTH:].upper()))
        with session_scope(DB_PATH) as new_session:
            # Find if thread/post exist and delete
            admin_chan = new_session.query(Chan).filter(
                Chan.address == msg_dict['toAddress']).first()
            if not admin_chan:
                logger.error("{}: Unknown board in Admin message. Discarding.".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                daemon_com.trash_message(msg_dict["msgid"])
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
                        options["delete_comment"]["message_id"] == admin_dict["options"]["delete_comment"]["message_id"]):
                    command_exists = True
                    options["delete_comment_timestamp_utc"] = daemon_com.get_utc()
                    each_cmd.options = json.dumps(options)
                    logger.info("{}: Admin command already exists. Updating.".format(
                        msg_dict["msgid"][-config.ID_LENGTH:].upper()))
                    if each_cmd.locally_restored or each_cmd.locally_deleted:
                        local_override = True
                    break

            if not command_exists:
                new_admin = Command()
                new_admin.action = admin_dict["action"]
                new_admin.action_type = admin_dict["action_type"]
                new_admin.chan_address = msg_dict['toAddress']
                options_dict = {
                    "delete_comment": {
                        "comment": admin_dict["options"]["delete_comment"]["comment"],
                        "message_id": admin_dict["options"]["delete_comment"]["message_id"]
                    },
                    "delete_comment_timestamp_utc": daemon_com.get_utc()
                }
                if "from_address" in admin_dict["options"]["delete_comment"]:
                    options_dict["from_address"] = admin_dict["options"]["delete_comment"]["from_address"]
                else:
                    options_dict["from_address"] = msg_dict['fromAddress']
                new_admin.options = json.dumps(options_dict)
                new_session.add(new_admin)
                new_session.commit()

            if local_override:
                logger.info("{}: Admin cannot delete post with comment due to local override".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper()))

            elif (admin_dict["options"]["delete_comment"]["message_id"] and
                    admin_dict["options"]["delete_comment"]["comment"]):
                logger.info("{}: Admin message to delete post {} with comment".format(
                    msg_dict["msgid"][-config.ID_LENGTH:].upper(),
                    admin_dict["options"]["delete_comment"]["message_id"]))

                if "from_address" in admin_dict["options"]["delete_comment"]:
                    from_address = admin_dict["options"]["delete_comment"]["from_address"]
                else:
                    from_address = msg_dict['fromAddress']

                delete_and_replace_comment(
                    admin_dict["options"]["delete_comment"]["message_id"],
                    admin_dict["options"]["delete_comment"]["comment"],
                    from_address=from_address,
                    local_delete=False,
                    only_hide=True)
    finally:
        daemon_com.trash_message(msg_dict["msgid"])


def admin_ban_address_from_board(msg_dict, admin_dict):
    if admin_dict["options"]["ban_address"] in daemon_com.get_identities():
        # Don't ban your own identity address, fool
        daemon_com.trash_message(msg_dict["msgid"])
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
                        "ban_address_timestamp_utc": daemon_com.get_utc()
                    }
                    if "reason" in admin_dict and admin_dict["reason"]:
                        options["reason"] = admin_dict["reason"]
                    new_admin.options = json.dumps(options)
                    new_session.add(new_admin)
                    new_session.commit()

                if admin_dict["action"] == "board_ban_public":
                    log_description = "Refresh Ban {}".format(admin_dict["options"]["ban_address"])
                    if "reason" in admin_dict and admin_dict["reason"]:
                        log_description += ": Reason: {}".format(admin_dict["reason"])
                    add_mod_log_entry(
                        log_description,
                        user_from=msg_dict["fromAddress"],
                        board_address=admin_dict["chan_address"])

            # Find messages and delete
            with session_scope(DB_PATH) as new_session:
                messages = new_session.query(Messages).filter(
                    Messages.address_from == admin_dict["options"]["ban_address"]).all()
                if messages:
                    # Admin: Delete post
                    for each_message in messages:
                        if each_message.thread.chan.address == admin_dict["chan_address"]:
                            delete_post(each_message.message_id)
            daemon_com.trash_message(msg_dict["msgid"])
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)
