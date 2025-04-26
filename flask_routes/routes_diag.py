import base64
import datetime
import html
import json
import logging
import os
import re
import subprocess
import time
from threading import Thread

import qbittorrentapi
from flask import Response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_
from sqlalchemy import or_
from zipstream import ZIP_DEFLATED
from zipstream import ZipStream

import config
from bitchan_client import DaemonCom
from database.models import Alembic
from database.models import BanedHashes
from database.models import BanedWords
from database.models import Captcha
from database.models import Chan
from database.models import Command
from database.models import DeletedMessages
from database.models import Games
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import ModLog
from database.models import StringReplace
from database.models import Threads
from database.models import UploadSites
from database.models import UploadTorrents
from database.models import regenerate_upload_sites
from flask_routes import flask_session_login
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_board
from forms import forms_settings
from utils import themes
from utils.download import process_attachments
from utils.encryption_decrypt import decrypt_safe_size
from utils.files import LF
from utils.files import delete_file
from utils.files import delete_files_recursive
from utils.gateway import api
from utils.gateway import generate_identity
from utils.general import process_passphrase
from utils.hashing import regen_all_hashes
from utils.posts import delete_post
from utils.posts import process_message_replies
from utils.posts import update_board_timestamp
from utils.posts import update_thread_timestamp
from utils.replacements import process_replacements
from utils.replacements import replace_dict_keys_with_values
from utils.replacements import replace_lt_gt
from utils.routes import allowed_access
from utils.routes import ban_and_delete
from utils.routes import ban_and_delete_word
from utils.routes import get_logged_in_user_name
from utils.routes import get_max_ttl
from utils.routes import page_dict
from utils.shared import add_mod_log_entry
from utils.shared import regenerate_card_popup_post_html

logger = logging.getLogger('bitchan.routes_diag')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_diag',
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


@blueprint.route('/diag', methods=('GET', 'POST'))
@count_views
def diag():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    status_msg = session.get('status_msg', {"status_message": []})
    form_diag = forms_settings.Diag()

    # get all messages sending
    import sqlite3
    from binascii import hexlify
    row = []
    try:
        conn = sqlite3.connect('file:{}'.format(config.BM_MESSAGES_DAT), uri=True)
        conn.text_factory = bytes
        c = conn.cursor()
        c.execute(
            "SELECT msgid, fromaddress, toaddress, lastactiontime, message, status "
            "FROM sent "
            "WHERE folder='sent'")
        row = c.fetchall()
        conn.commit()
        conn.close()
    except Exception as err:
        logger.exception("Error checking for POW: {}".format(err))

    # Convert msg IDs
    sending_msgs = []
    for each_row in row:
        if each_row[5].decode() in ["doingmsgpow", "msgqueued", "awaitingpubkey"]:
            sending_msgs.append(
                (hexlify(each_row[0]).decode(),
                 each_row[1].decode(),
                 each_row[2].decode(),
                 each_row[3],
                 len(each_row[4]),
                 each_row[5].decode()))

    if request.method == 'POST':
        if form_diag.del_sending_msg.data:
            cancel_send_id_list = []
            for each_input in request.form:
                if each_input.startswith("delsendingmsgid_"):
                    cancel_send_id_list.append(each_input.split("delsendingmsgid_")[1])

            if not cancel_send_id_list:
                status_msg['status_message'].append(
                    "Must select at least one message to cancel the sending of.")

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                    try:
                        for each_id in cancel_send_id_list:
                            logger.info("Trashing msg with ID: {}".format(each_id))
                            api.trashSentMessage(each_id)
                            time.sleep(0.1)
                        time.sleep(1)
                        daemon_com.restart_bitmessage()
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(
                            "Deleted message(s) being sent and restarting Bitmessage. "
                            "Please wait at least 60 seconds before canceling another send.")
                    except Exception as err:
                        logger.error("Error: {}".format(err))
                    finally:
                        time.sleep(config.API_PAUSE)
                        lf.lock_release(config.LOCKFILE_API)

        elif form_diag.del_banned_hashes.data:
            list_unban_hashes = []
            for each_input in request.form:
                if each_input.startswith("delhashes_id_"):
                    list_unban_hashes.append(each_input.split("delhashes_id_")[1])

            if not list_unban_hashes:
                status_msg['status_message'].append(
                    "Must select at least one hash to unban.")

            if not status_msg['status_message']:
                user_name = get_logged_in_user_name()
                admin_name = user_name if user_name else "LOCAL ADMIN"

                for each_hash_id in list_unban_hashes:
                    hash_entry = BanedHashes.query.filter(BanedHashes.id == each_hash_id).first()
                    if hash_entry:
                        add_mod_log_entry(
                            f"Unbanned file attachment SHA256 hash {hash_entry.hash} "
                            f"and hash fingerprint {hash_entry.imagehash} ({hash_entry.name})",
                            user_from=admin_name)
                        hash_entry.delete()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Unbanned selected hashes.")

        elif form_diag.add_banned_hash.data:
            user_name = get_logged_in_user_name()
            admin_name = user_name if user_name else "LOCAL ADMIN"

            try:
                if not form_diag.hash_to_ban.data and not form_diag.imagehash_to_ban.data:
                    status_msg['status_message'].append("A hash is required.")
                else:
                    ban_and_delete(
                        sha256_hash=form_diag.hash_to_ban.data,
                        imagehash_hash=form_diag.imagehash_to_ban.data,
                        name=form_diag.hash_name.data,
                        delete_posts=form_diag.delete_present_posts.data,
                        delete_threads=form_diag.delete_present_threads.data,
                        user_name=admin_name,
                        only_board_address=form_diag.board_addresses.data)

                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(f"Banned file with hash")
            except Exception as err:
                status_msg['status_message'].append(f"Couldn't ban file with hash: {err}")
                logger.exception(f"Couldn't ban file with hash")

        elif form_diag.edit_hash_table.data:
            for each_input in request.form:
                if each_input.startswith("hashname_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        hash_name = request.form[each_input]
                        hash_entry = BanedHashes.query.filter(BanedHashes.id == int(entry_id)).first()
                        if hash_entry and hash_entry.name != hash_name:
                            hash_entry.name = hash_name
                            hash_entry.save()
                    except:
                        logger.exception("Setting hash")

                elif each_input.startswith("boardaddress_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        board_address = request.form[each_input]
                        hash_entry = BanedHashes.query.filter(BanedHashes.id == int(entry_id)).first()
                        if hash_entry and hash_entry.only_board_address != board_address:
                            hash_entry.only_board_address = board_address
                            hash_entry.save()
                    except:
                        logger.exception("Setting board address")

            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(f"Renamed hash entries")

        elif form_diag.regenerate_hashes.data:
            try:
                regen_hashes_thread = Thread(target=regen_all_hashes)
                regen_hashes_thread.start()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Regenerating file hashes in the background. Give it sufficient time to complete.")
            except Exception as err:
                status_msg['status_message'].append("Couldn't regenerate hashes: {}".format(err))
                logger.exception("Couldn't regenerate hashes")

        elif form_diag.del_banned_words.data:
            list_unban_words = []
            for each_input in request.form:
                if each_input.startswith("delwords_"):
                    list_unban_words.append(each_input.split("delwords_")[1])

            if not list_unban_words:
                status_msg['status_message'].append(
                    "Must select at least one word to unban.")

            if not status_msg['status_message']:
                user_name = get_logged_in_user_name()
                admin_name = user_name if user_name else "LOCAL ADMIN"

                for each_id in list_unban_words:
                    word_entry = BanedWords.query.filter(BanedWords.id == int(each_id)).first()
                    if word_entry:
                        add_mod_log_entry(
                            f"Unbanned word with name {word_entry.name}.",
                            user_from=admin_name)
                        word_entry.delete()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Unbanned selected words.")

        elif form_diag.add_banned_word.data:
            user_name = get_logged_in_user_name()
            admin_name = user_name if user_name else "LOCAL ADMIN"

            try:
                if not form_diag.word_to_ban.data:
                    status_msg['status_message'].append("A word is required.")
                else:
                    ban_and_delete_word(
                        word=form_diag.word_to_ban.data,
                        name=form_diag.word_name.data,
                        is_regex=form_diag.word_is_regex.data,
                        delete_posts=form_diag.word_delete_present_posts.data,
                        delete_threads=form_diag.word_delete_present_threads.data,
                        user_name=admin_name,
                        only_board_address=form_diag.word_board_addresses.data)

                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(f"Banned word")
            except Exception as err:
                status_msg['status_message'].append(f"Couldn't ban word: {err}")
                logger.exception(f"Couldn't ban file with hash")

        elif form_diag.edit_word_table.data:
            regex_checkboxes = {}

            for each_input in request.form:
                if each_input.startswith("wordname_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        word_name = request.form[each_input]
                        word_entry = BanedWords.query.filter(BanedWords.id == int(entry_id)).first()
                        if word_entry and word_entry.name != word_name:
                            word_entry.name = word_name
                            word_entry.save()
                    except:
                        logger.exception("Setting name")

                elif each_input.startswith("wordword_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        if entry_id not in regex_checkboxes:
                            regex_checkboxes[entry_id] = False
                        word_word = request.form[each_input]
                        word_entry = BanedWords.query.filter(BanedWords.id == int(entry_id)).first()
                        if word_entry and word_entry.word != word_word:
                            word_entry.word = word_word
                            word_entry.save()
                    except:
                        logger.exception("Setting word")

                elif each_input.startswith("wordboardaddress_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        board_address = request.form[each_input]
                        word_entry = BanedWords.query.filter(BanedWords.id == int(entry_id)).first()
                        if word_entry and word_entry.only_board_address != board_address:
                            word_entry.only_board_address = board_address
                            word_entry.save()
                    except:
                        logger.exception("Setting board address")

                elif each_input.startswith("isregexword_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        is_regex = request.form[each_input]
                        if is_regex:
                            regex_checkboxes[entry_id] = True
                    except:
                        logger.exception("Setting board address")

            # Change if entry is regex
            for each_id in regex_checkboxes:
                word_entry = BanedWords.query.filter(BanedWords.id == int(each_id)).first()
                if word_entry:
                    word_entry.is_regex = regex_checkboxes[each_id]
                    word_entry.save()

            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(f"Renamed word entries")

        elif form_diag.del_string_replacement.data:
            list_unban_words = []
            for each_input in request.form:
                if each_input.startswith("delstringreplace_"):
                    list_unban_words.append(each_input.split("delstringreplace_")[1])

            if not list_unban_words:
                status_msg['status_message'].append(
                    "Must select at least one word to unban.")

            if not status_msg['status_message']:
                user_name = get_logged_in_user_name()
                admin_name = user_name if user_name else "LOCAL ADMIN"

                for each_id in list_unban_words:
                    string_entry = StringReplace.query.filter(StringReplace.id == int(each_id)).first()
                    if string_entry:
                        add_mod_log_entry(
                            f"Removed string replacement: string '{string_entry.string}' "
                            f"and/or regex '{string_entry.regex}' "
                            f"to '{string_entry.string_replacement}' ({string_entry.name}).",
                            user_from=admin_name)
                        string_entry.delete()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Removed string replacement.")

        elif form_diag.add_string_replacement.data:
            user_name = get_logged_in_user_name()
            admin_name = user_name if user_name else "LOCAL ADMIN"

            try:
                if ((not form_diag.string_to_replace.data and
                     not form_diag.regex_to_match.data) or
                        not form_diag.string_to_replace_with.data):
                    status_msg['status_message'].append("A string or regex and a string to replace with is required.")
                else:
                    # String replacement
                    string_replace = StringReplace()
                    string_replace.name = form_diag.string_name.data
                    string_replace.string = form_diag.string_to_replace.data
                    string_replace.regex = form_diag.regex_to_match.data
                    string_replace.string_replacement = form_diag.string_to_replace_with.data
                    string_replace.only_board_address = form_diag.string_board_addresses.data

                    add_mod_log_entry(
                        f"Added string replacement: string '{form_diag.string_to_replace.data}' and/or "
                        f"regex '{form_diag.regex_to_match.data}' "
                        f"to '{form_diag.string_to_replace_with.data}' ({form_diag.string_name.data})",
                        user_from=admin_name)

                    string_replace.save()

                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(f"Added string replacement")
            except Exception as err:
                status_msg['status_message'].append(f"Couldn't add string replacement: {err}")
                logger.exception(f"Couldn't add string replacement")

        elif form_diag.edit_string_table.data:
            for each_input in request.form:
                if each_input.startswith("stringrepname_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        word_name = request.form[each_input]
                        rep_entry = StringReplace.query.filter(StringReplace.id == int(entry_id)).first()
                        if rep_entry and rep_entry.name != word_name:
                            rep_entry.name = word_name
                            rep_entry.save()
                    except:
                        logger.exception("Setting name")

                elif each_input.startswith("stringtoreplace_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        string = request.form[each_input]
                        rep_entry = StringReplace.query.filter(StringReplace.id == int(entry_id)).first()
                        if rep_entry and rep_entry.string != string:
                            rep_entry.string = string
                            rep_entry.save()
                    except:
                        logger.exception("Setting string to replace")

                elif each_input.startswith("regexreplace_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        regex_ = request.form[each_input]
                        rep_entry = StringReplace.query.filter(StringReplace.id == int(entry_id)).first()
                        if rep_entry and rep_entry.regex != regex_:
                            rep_entry.regex = regex_
                            rep_entry.save()
                    except:
                        logger.exception("Setting regex")

                elif each_input.startswith("stringtoreplacewith_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        string_replacement = request.form[each_input]
                        rep_entry = StringReplace.query.filter(StringReplace.id == int(entry_id)).first()
                        if rep_entry and rep_entry.string_replacement != string_replacement:
                            rep_entry.string_replacement = string_replacement
                            rep_entry.save()
                    except:
                        logger.exception("Setting string to replace with")

                elif each_input.startswith("stringrepboardaddress_"):
                    try:
                        entry_id = each_input.split("_")[1]
                        board_address = request.form[each_input]
                        rep_entry = StringReplace.query.filter(StringReplace.id == int(entry_id)).first()
                        if rep_entry and rep_entry.only_board_address != board_address:
                            rep_entry.only_board_address = board_address
                            rep_entry.save()
                    except:
                        logger.exception("Setting board address")

            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(f"Renamed hash entries")

        elif form_diag.stop_bitmessage_and_daemon.data:
            try:
                if config.DOCKER:
                    p = subprocess.Popen('docker stop -t 30 bitchan_daemon', shell=True, stdout=subprocess.PIPE)
                    out, err = p.communicate()
                    logger.info(f"Stop bitchan_daemon Output: {out}, Error: {err}")
                    p = subprocess.Popen('docker stop -t 30 bitchan_bitmessage', shell=True, stdout=subprocess.PIPE)
                    out, err = p.communicate()
                    logger.info(f"Stop bitchan_mitmessage Output: {out}, Error: {err}")
                else:
                    subprocess.Popen('service bitchan_bitmessage stop', shell=True)
                    subprocess.Popen('service bitchan_daemon stop', shell=True)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Stopping Bitmessage and Daemon. Give it time to complete.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't stop Bitmessage and Daemon: {}".format(err))
                logger.exception("Couldn't stop Bitmessage and Daemon")

        elif form_diag.start_bitmessage_and_daemon.data:
            try:
                if config.DOCKER:
                    p = subprocess.Popen('docker start bitchan_bitmessage', shell=True, stdout=subprocess.PIPE)
                    out, err = p.communicate()
                    logger.info(f"Start bitchan_bitmessage Output: {out}, Error: {err}")
                    p = subprocess.Popen('docker start bitchan_daemon', shell=True, stdout=subprocess.PIPE)
                    out, err = p.communicate()
                    logger.info(f"Start bitchan_daemon Output: {out}, Error: {err}")
                else:
                    subprocess.Popen('service bitchan_bitmessage start', shell=True)
                    subprocess.Popen('service bitchan_daemon start', shell=True)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Starting Bitmessage and Daemon. Give it time to complete.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't stop Bitmessage and Daemon: {}".format(err))
                logger.exception("Couldn't stop Bitmessage and Daemon")

        elif form_diag.restart_bitmessage.data:
            try:
                daemon_com.restart_bitmessage()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Restarting Bitmessage. Give it time to complete.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't restart Bitmessage: {}".format(err))
                logger.exception("Couldn't restart Bitmessage")

        elif form_diag.del_inventory.data:
            try:
                daemon_com.clear_bm_inventory()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Deleted Bitmessage inventory and restarting Bitmessage. Give it time to resync.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete Bitmessage inventory: {}".format(err))
                logger.exception("Couldn't delete BM inventory")

        elif form_diag.del_deleted_msg_db.data:
            try:
                deleted_msgs = DeletedMessages.query.all()
                for each_msg in deleted_msgs:
                    logger.info("DeletedMessages: Deleting entry: {}".format(each_msg.message_id))
                    each_msg.delete()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Cleared Deleted Message table")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't clear Deleted Message table: {}".format(err))
                logger.exception("Couldn't clear Deleted Message table")

        elif form_diag.del_non_bc_msg_list.data:
            try:
                settings = GlobalSettings.query.first()
                settings.discard_message_ids = "[]"
                settings.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Cleared Non-BC Message List")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't clear Non-BC Message List: {}".format(err))
                logger.exception("Couldn't clear Non-BC Message List")

        elif form_diag.del_trash.data:
            try:
                daemon_com.delete_and_vacuum()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted Bitmessage Trash items.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete Bitmessage Trash items: {}".format(err))
                logger.exception("Couldn't delete BM Trash Items")

        elif form_diag.del_mod_log.data:
            try:
                mod_logs = ModLog.query.all()
                for each_entry in mod_logs:
                    each_entry.delete()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted Mod Log.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete Mod Log: {}".format(err))
                logger.exception("Couldn't delete Mod Log")

        elif form_diag.del_orphaned_identities.data:
            try:
                bm_identities = daemon_com.get_identities()
                identities = Identity.query.all()
                if len(bm_identities):
                    for each_ident in identities:
                        if each_ident.address not in bm_identities:
                            logger.info("Deleting orphaned Identity: {}".format(each_ident.address))
                            each_ident.delete()
                        else:
                            logger.info("Found confirmed Identity: {}".format(each_ident.address))
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted orphaned Identities.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete orphaned Identities: {}".format(err))
                logger.exception("Couldn't delete orphaned Identities")

        elif form_diag.add_orphaned_identities.data:
            try:
                bm_identities = daemon_com.get_identities()
                identities = Identity.query.all()

                if len(bm_identities):
                    added_identity = False
                    return_list = []

                    for each_ident in identities:
                        if each_ident.address not in bm_identities:
                            added_identity = True
                            logger.info("Adding orphaned Identity: {}".format(each_ident.address))

                            passphrase = base64.b64decode(each_ident.passphrase_base64).decode()
                            errors, dict_chan_info = process_passphrase(passphrase)

                            if dict_chan_info:
                                return_list.append(
                                    "Invalid passphrase passphrase for identity address {}".format(each_ident.address))

                            if not status_msg['status_message']:
                                return_str = generate_identity(
                                    each_ident.passphrase_base64, each_ident.short_address)

                                if return_str:
                                    if ("addresses" in return_str and
                                            len(return_str["addresses"]) == 1 and
                                            return_str["addresses"][0]):
                                        return_list.append(
                                            "Created identity {} with address {}.".format(
                                                each_ident.label, return_str["addresses"][0]))
                                    else:
                                        return_list.append(
                                            "Error creating Identity {} with address {}".format(
                                                each_ident.label, each_ident.address))
                                else:
                                    return_list.append("Error creating Identity")
                        else:
                            logger.info("Found confirmed Identity: {}".format(each_ident.address))

                    if added_identity:
                        daemon_com.refresh_identities()

                    for each_ret in return_list:
                        status_msg['status_message'].append(each_ret)

                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("Added orphaned Identities.")
                else:
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("No Bitmessage Identities found.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't add orphaned Identities: {}".format(err))
                logger.exception("Couldn't add orphaned Identities")

        elif form_diag.del_posts_without_thread.data:
            try:
                messages = Messages.query.all()
                for each_msg in messages:
                    if not each_msg.thread:
                        each_msg.delete()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted orphaned posts.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete orphaned posts: {}".format(err))
                logger.exception("Couldn't delete orphaned posts")

        elif form_diag.fix_thread_board_timestamps.data:
            try:
                threads = Threads.query.all()
                for each_thread in threads:
                    latest_post = Messages.query.filter(
                        Messages.thread_id == each_thread.id).order_by(
                            Messages.timestamp_sent.desc()).first()
                    if latest_post:
                        each_thread.timestamp_sent = latest_post.timestamp_sent
                        each_thread.save()

                boards = Chan.query.filter(Chan.type == "board").all()
                for each_board in boards:
                    latest_thread = Threads.query.filter(
                        Threads.chan_id == each_board.id).order_by(
                            Threads.timestamp_sent.desc()).first()
                    if latest_thread:
                        each_board.timestamp_sent = latest_thread.timestamp_sent
                        each_board.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Fixed thread and board timestamps.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't fix thread and board timestamps: {}".format(err))
                logger.exception("Couldn't fix thread and board timestamps")

        elif form_diag.del_game_table.data:
            try:
                games = Games.query.all()
                for each_game in games:
                    each_game.delete()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted game data")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete game data: {}".format(err))
                logger.exception("Couldn't delete game data")

        elif form_diag.del_captcha_table.data:
            try:
                captchas = Captcha.query.all()
                for each_captcha in captchas:
                    each_captcha.delete()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted captcha data")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete captcha data: {}".format(err))
                logger.exception("Couldn't delete captcha data")

        elif form_diag.fix_thread_short_hashes.data:
            try:
                threads = Threads.query.all()
                for each_thread in threads:
                    if each_thread.thread_hash_short != each_thread.thread_hash[-12:]:
                        each_thread.thread_hash_short = each_thread.thread_hash[-12:]
                        each_thread.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Fixed thread short hashes")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't fix thread short hashes: {}".format(err))
                logger.exception("Couldn't fix thread short hashes")

        elif form_diag.fix_chan_thread_timestamps.data:
            try:
                for each_thread in Threads.query.all():
                    update_thread_timestamp(each_thread.thread_hash)
                for each_chan in Chan.query.all():
                    update_board_timestamp(each_chan.address)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Fixed chan/thread timestamps")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't fix chan/thread timestamps: {}".format(err))
                logger.exception("Couldn't fix chan/thread timestamps")

        elif form_diag.reset_downloads.data:
            try:
                list_msg_ids = []
                msgs = Messages.query.filter(Messages.file_currently_downloading.is_(True)).all()
                for msg in msgs:
                    list_msg_ids.append(msg.message_id)
                    msg.file_currently_downloading = False
                    msg.save()
                for msg_id in list_msg_ids:
                    regenerate_card_popup_post_html(message_id=msg_id)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Reset downloads")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't reset downloads: {}".format(err))
                logger.exception("Couldn't reset downloads")

        elif form_diag.start_all_downloads.data:
            try:
                settings = GlobalSettings.query.first()
                if settings.maintenance_mode:
                    status_msg['status_message'].append(
                        "Cannot initiate attachment download while Maintenance Mode is enabled.")
                else:
                    msgs = Messages.query.filter(
                        and_(or_(Messages.file_download_successful.is_(False),
                                 Messages.file_download_successful.is_(None)),
                             Messages.file_currently_downloading.is_(False))).all()
                    for msg in msgs:
                        logger.info(f"Starting download for post with message ID {msg.message_id}")
                        daemon_com.set_start_download(msg.message_id)
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("Start all downloads")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't start all downloads: {}".format(err))
                logger.exception("Couldn't start all downloads")

        elif form_diag.regenerate_all_thumbnails.data:
            try:
                for each_msg in Messages.query.filter(and_(Messages.file_amount.is_not(None), Messages.file_amount != 0)).all():
                    extract_path = "{}/{}".format(config.FILE_DIRECTORY, each_msg.message_id)
                    errors_files, media_info, message_steg = process_attachments(
                        each_msg.message_id, extract_path, progress=False, silent=True, overwrite_thumbs=True)
                    if errors_files:
                        for each_err in errors_files:
                            logger.error(f"Message {each_msg.message_id} Error: {each_err}")
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Regenerated all thumbnails.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't regenerated all thumbnails: {}".format(err))
                logger.exception("Couldn't regenerated all thumbnails")

        elif form_diag.regenerate_post_thumbnails.data:
            if not form_diag.regenerate_post_thumbnails_id.data:
                status_msg['status_message'].append("A Post ID is required")
            else:
                post_id = form_diag.regenerate_post_thumbnails_id.data.replace(" ", "").upper()
                message = Messages.query.filter(Messages.post_id == post_id).first()
                if message:
                    try:
                        extract_path = "{}/{}".format(config.FILE_DIRECTORY, message.message_id)
                        errors_files, media_info, message_steg = process_attachments(
                            message.message_id, extract_path, progress=False, overwrite_thumbs=True)
                        if errors_files:
                            for each_err in errors_files:
                                status_msg['status_message'].append(f"Error: {each_err}.")
                        else:
                            status_msg['status_title'] = "Success"
                            status_msg['status_message'].append(f"Regenerated thumbnails for post {post_id}.")
                    except Exception as err:
                        status_msg['status_message'].append(
                            f"Couldn't regenerate thumbnails for post {post_id}: {err}")
                        logger.exception(f"Couldn't regenerate thumbnails for post {post_id}")
                else:
                    status_msg['status_message'].append("Post not found")

        elif form_diag.regenerate_all_html.data:
            try:
                for board in Chan.query.all():
                    regenerate_card_popup_post_html(
                        all_posts_of_board_address=board.address)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted HTML for all posts, popups, cards.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete HTML for all posts, popups, cards: {}".format(err))
                logger.exception("Couldn't delete HTML for all posts, popups, cards")

        elif form_diag.regenerate_post_html.data:
            if not form_diag.regenerate_post_id.data:
                status_msg['status_message'].append("A Post ID is required")
            else:
                post_id = form_diag.regenerate_post_id.data.replace(" ", "").upper()
                message = Messages.query.filter(Messages.post_id == post_id).first()
                if message:
                    try:
                        regenerate_card_popup_post_html(message_id=message.message_id)
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(f"Regenerated HTML for post {post_id}.")
                    except Exception as err:
                        status_msg['status_message'].append(
                            f"Couldn't regenerate HTML for post {post_id}: {err}")
                        logger.exception(f"Couldn't regenerate HTML for post {post_id}")

                    try:
                        process_replacements(
                            message.original_message, message.message_id, message.message_id,
                            address=message.thread.chan.address, force_replacements=True)
                    except Exception as err:
                        status_msg['status_message'].append(
                            f"Couldn't process replacements for post {post_id}: {err}")
                        logger.exception(f"Couldn't process replacements for for post {post_id}")
                else:
                    status_msg['status_message'].append("Post not found")

        elif form_diag.decrypt_regenerate_post_html.data:
            if not form_diag.decrypt_regenerate_post_id.data:
                status_msg['status_message'].append("A Post ID is required")
            else:
                post_id = form_diag.decrypt_regenerate_post_id.data.replace(" ", "").upper()
                message = Messages.query.filter(Messages.post_id == post_id).first()
                if message and message.thread and message.thread.chan:
                    status_msg = decrypt_and_regen_html(message, post_id, status_msg)
                else:
                    status_msg['status_message'].append("Post not found")

        elif form_diag.decrypt_regenerate_post_all_html.data:
            messages = Messages.query.filter(
                or_(Messages.original_message == "",
                    Messages.original_message.is_(None))).all()
            for each_msg in messages:
                if each_msg and each_msg.thread and each_msg.thread.chan:
                    try:
                        post_id = each_msg.post_id.upper()
                        status_msg = decrypt_and_regen_html(each_msg, post_id, status_msg)
                    except Exception as err:
                        logger.error(f"{each_msg}: Error decrypting and regenerating HTML: {err}")
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(f"Finished running: decrypting and regenerating post HTML")

        elif form_diag.regenerate_thread_post_html.data:
            if not form_diag.regenerate_thread_post_id.data:
                status_msg['status_message'].append("A Post ID is required")
            else:
                post_id = form_diag.regenerate_thread_post_id.data.replace(" ", "").upper()
                message = Messages.query.filter(Messages.post_id == post_id).first()
                if message:
                    messages = Messages.query.filter(Messages.thread_id == message.thread_id).all()
                    try:
                        for each_msg in messages:
                            regenerate_card_popup_post_html(message_id=each_msg.message_id)
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(f"Deleted HTML for all posts of thread OP {post_id}.")
                    except Exception as err:
                        status_msg['status_message'].append(
                            f"Couldn't delete HTML for all posts of thread OP {post_id}: {err}")
                        logger.exception(f"Couldn't delete HTML for all posts of thread OP {post_id}")
                else:
                    status_msg['status_message'].append("Post not found")

        elif form_diag.regenerate_popup_html.data:
            try:
                for board in Chan.query.all():
                    regenerate_card_popup_post_html(
                        all_posts_of_board_address=board.address,
                        regenerate_post_html=False,
                        regenerate_cards=False)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted popup HTML for all messages.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete popup HTML: {}".format(err))
                logger.exception("Couldn't delete popup HTML")

        elif form_diag.regenerate_cards.data:
            try:
                for board in Chan.query.all():
                    regenerate_card_popup_post_html(
                        all_posts_of_board_address=board.address,
                        regenerate_post_html=False,
                        regenerate_popup_html=False)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted cards.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete cards: {}".format(err))
                logger.exception("Couldn't delete cards")

        elif form_diag.regenerate_all_post_html.data:
            try:
                for board in Chan.query.all():
                    regenerate_card_popup_post_html(
                        all_posts_of_board_address=board.address,
                        regenerate_popup_html=False,
                        regenerate_cards=False)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Regenerated all post HTML")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't regenerate all post HTML: {}".format(err))
                logger.exception("Couldn't regenerate all post HTML")

        elif form_diag.regenerate_reply_post_ids.data:
            try:
                for each_msg in Messages.query.all():
                    each_msg.post_ids_replied_to = "[]"
                    each_msg.post_ids_replying_to_msg = "[]"
                    each_msg.regenerate_post_html = True
                    each_msg.save()

                for each_msg in Messages.query.all():
                    each_msg.post_ids_replied_to = json.dumps(
                        process_message_replies(each_msg.message_id, each_msg.message))
                    each_msg.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Regenerated all reply post IDs")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't regenerate all reply post IDs: {}".format(err))
                logger.exception("Couldn't regenerate all reply post IDs")

        elif form_diag.regenerate_upload_sites.data:
            try:
                for site in UploadSites.query.all():
                    site.delete()
                regenerate_upload_sites()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Regenerated all upload sites")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't regenerate all upload sites: {}".format(err))
                logger.exception("Couldn't regenerate all upload sites")

        elif form_diag.recheck_attachments.data:
            msg_ids = []
            msgs_rebuild = {}

            # find posts that indicate need to download attachments
            for each_msg in Messages.query.filter(and_(
                    Messages.file_amount.is_not(True),
                    Messages.file_download_successful.is_not(True),
                    Messages.file_currently_downloading.is_(False))).all():
                msg_ids.append(each_msg.message_id)

            # Check if those files already exist
            for each_id in msg_ids:
                attach_path = f"{config.FILE_DIRECTORY}/{each_id}"
                if os.path.exists(attach_path):
                    errors_files, media_info, message_steg = process_attachments(each_id, attach_path, silent=True)
                    if errors_files:
                        logger.error(
                            f"{each_id[-config.ID_LENGTH:].upper()}: Error: {errors_files}")
                    elif media_info:
                        msgs_rebuild[each_id] = {"media_info": media_info, "message_steg": message_steg}

            logger.info(f"Found {len(msgs_rebuild)} messages needing attachments to be fixed.")

            # if they exist, modify message entry
            for msg_id in msgs_rebuild:
                logger.info(
                    f"{msg_id[-config.ID_LENGTH:].upper()}: "
                    f"Fixing message attachments: {msgs_rebuild[msg_id]['media_info']}")
                msg = Messages.query.filter(Messages.message_id == msg_id).first()
                if msg:
                    msg.file_download_successful = True
                    msg.file_do_not_download = False
                    msg.file_progress = None
                    msg.media_info = json.dumps(msgs_rebuild[msg_id]["media_info"])
                    msg.file_sha256_hashes_match = True
                    msg.message_steg = json.dumps(msgs_rebuild[msg_id]["message_steg"])
                    msg.save()

                    regenerate_card_popup_post_html(
                        thread_hash=msg.thread.thread_hash,
                        message_id=msg_id)

        elif form_diag.delete_orphaned_attachments.data:
            found = 0
            n_found = 0
            for dirpath, dirnames, filenames in os.walk(config.FILE_DIRECTORY):
                for each_dir in dirnames:
                    try:
                        if "_" not in each_dir:
                            message_id = each_dir
                        else:
                            message_id = each_dir.split("_")[0]
                        if len(message_id) != 64:
                            logger.info(f"Message ID not 64 len: {len(message_id)}, {message_id}")
                        else:
                            if not Messages.query.filter(Messages.message_id == message_id).first():
                                n_found += 1
                                path = os.path.join(dirpath, each_dir)
                                logger.info(f"Message with ID {message_id} not found, deleting {path}")
                                delete_files_recursive(path)
                            else:
                                found += 1
                    except:
                        logger.exception("scanning for orphaned attachments")
            logger.info(f"Attachment summary: found {found} with posts, found {n_found} without posts (and were deleted).")

        elif form_diag.delete_all_torrents.data:
            torrent_hashes = []

            conn_info = dict(host=config.QBITTORRENT_HOST, port=8080)
            qbt_client = qbittorrentapi.Client(**conn_info)
            try:
                qbt_client.auth_log_in()

                # Get all hashes
                for torrent in qbt_client.torrents_info():
                    torrent_hashes.append(torrent.hash)

                # Delete torrents
                with qbittorrentapi.Client(**conn_info) as qbt_client:
                    qbt_client.torrents_delete(delete_files=True, torrent_hashes=torrent_hashes)

                # Delete DB entries
                torrents_all = UploadTorrents.query.all()
                for torrent in torrents_all:
                    logger.info(f"Deleting DB entry for {torrent.file_hash}")
                    torrent.delete()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted all torrents and DB entries")
            except:
                logger.exception("deleting all torrents")
            finally:
                qbt_client.auth_log_out()

            logger.info(f"Deleted all torrents and DB entries")

        elif form_diag.delete_post_id_submit.data:
            if form_diag.delete_post_id.data:
                post_id = form_diag.delete_post_id.data.replace(" ", "").upper()
                post = Messages.query.filter(Messages.post_id == post_id).first()
                if not post:
                    status_msg['status_message'].append(f"Invalid Post ID: {post_id}")
                else:
                    delete_post(post.message_id)
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(f"Deleted post with ID {post_id}")

        elif form_diag.bulk_delete_threads_submit.data:
            address = "0"
            if form_diag.bulk_delete_threads_address.data:
                board = Chan.query.filter(Chan.address == form_diag.bulk_delete_threads_address.data)
                if not board.count():
                    status_msg['status_message'].append(
                        "Invalid Address: {}".format(form_diag.bulk_delete_threads_address.data))
                else:
                    address = board.address

            return redirect(url_for("routes_admin.bulk_delete_thread", current_chan=address))

        elif form_diag.knownnodes_submit.data:
            if form_diag.knownnodes_dat_txt.data:
                try:
                    knownnodes_dat_list = json.loads(form_diag.knownnodes_dat_txt.data)
                    if type(knownnodes_dat_list) == list:
                        combine_knownnodes = Thread(
                            target=daemon_com.combine_bm_knownnodes, args=(knownnodes_dat_list,))
                        combine_knownnodes.start()
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(
                        f"Sent knownnodes.dat contents to daemon to be combined with current knownnodes.dat. "
                        f"View the daemon log for further updates.")
                except Exception as err:
                    status_msg['status_message'].append(f"Error: {err}")


        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    captcha_entry_count = Captcha.query.count()
    game_entry_count = Games.query.count()

    try:  # Ensure /diag page can still be accessed even if BitChan daemon isn't running
        bm_identities = daemon_com.get_identities()
    except:
        bm_identities = []

    bc_identities = Identity.query.all()
    orphaned_identities_bm = 0
    orphaned_identities_bc = 0
    if len(bm_identities):
        for each_ident in bc_identities:
            if each_ident.address not in bm_identities:
                orphaned_identities_bc += 1

        for each_ident_addr in bm_identities:
            bc_identities = Identity.query.filter(Identity.address == each_ident_addr).first()
            if not bc_identities:
                orphaned_identities_bm += 1

    banned_hashes = BanedHashes.query.all()
    banned_words = BanedWords.query.all()
    replaced_strings = StringReplace.query.all()

    return render_template("pages/diag.html",
                           banned_hashes=banned_hashes,
                           banned_words=banned_words,
                           captcha_entry_count=captcha_entry_count,
                           flask_session_login=flask_session_login,
                           form_diag=form_diag,
                           game_entry_count=game_entry_count,
                           orphaned_identities_bc=orphaned_identities_bc,
                           orphaned_identities_bm=orphaned_identities_bm,
                           replace_lt_gt=replace_lt_gt,
                           replaced_strings=replaced_strings,
                           sending_msgs=sending_msgs,
                           settings=GlobalSettings.query.first(),
                           status_msg=status_msg,
                           themes=themes.themes)


@blueprint.route('/bug_report', methods=('GET', 'POST'))
@count_views
def bug_report():
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    status_msg = session.get('status_msg', {"status_message": []})
    form_bug = forms_board.BugReport()

    if request.method == 'POST':
        if form_bug.send.data and form_bug.bug_report.data:
            try:
                # Only send from a board or list. Do not send from an identity.
                if config.DEFAULT_CHANS[0]["address"] in daemon_com.get_all_chans():
                    address_from = config.DEFAULT_CHANS[0]["address"]
                elif daemon_com.get_all_chans():
                    address_from = list(daemon_com.get_all_chans().keys())[0]
                else:
                    status_msg['status_message'].append(
                        "Could not find address to send from. "
                        "Join/Create a board or list and try again.")
                    address_from = None

                if not address_from:
                    status_msg['status_message'].append("Missing from address")

                settings = GlobalSettings.query.first()
                if settings.enable_kiosk_mode:
                    now = time.time()
                    last_post_ts = daemon_com.get_last_post_ts()
                    if now < last_post_ts + settings.kiosk_post_rate_limit:
                        status_msg['status_message'].append(
                            "Posting is limited to 1 post per {} second period. Wait {:.0f} more seconds.".format(
                                settings.kiosk_post_rate_limit,
                                (last_post_ts + settings.kiosk_post_rate_limit) - now))

                if not status_msg['status_message']:
                    alembic_version = Alembic.query.first().version_num
                    message_compiled = "BitChan version: {}\n".format(config.VERSION_BITCHAN)
                    message_compiled += "Database version: {} (should be {})\n\n".format(
                        alembic_version, config.VERSION_ALEMBIC)
                    message_compiled += "Message:\n\n{}".format(form_bug.bug_report.data)
                    message_b64 = base64.b64encode(message_compiled.encode()).decode()

                    ts = datetime.datetime.fromtimestamp(
                        daemon_com.get_utc()).strftime('%Y-%m-%d %H:%M:%S')
                    subject = "Bug Report {} ({})".format(config.VERSION_BITCHAN, ts)
                    subject_b64 = base64.b64encode(subject.encode()).decode()

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

                    lf = LF()
                    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                        try:
                            return_str = api.sendMessage(
                                config.BITCHAN_BUG_REPORT_ADDRESS,
                                address_from,
                                subject_b64,
                                message_b64,
                                2,
                                get_max_ttl())
                            if return_str:
                                daemon_com.set_last_post_ts(time.time())
                                status_msg['status_title'] = "Success"
                                status_msg['status_message'].append(
                                    "Sent. Thank you for your feedback. "
                                    "Send returned: {}".format(return_str))
                        finally:
                            time.sleep(config.API_PAUSE)
                            lf.lock_release(config.LOCKFILE_API)
            except Exception as err:
                status_msg['status_message'].append("Could not send: {}".format(err))
                logger.exception("Could not send bug report: {}".format(err))

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/bug_report.html",
                           form_bug=form_bug,
                           replace_lt_gt=replace_lt_gt,
                           settings=GlobalSettings.query.first(),
                           status_msg=status_msg,
                           themes=themes.themes)


@blueprint.route('/regex', methods=('GET', 'POST'))
@count_views
def regex():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    regex_return = {}
    form_data = {"regex": "", "text": ""}
    status_msg = session.get('status_msg', {"status_message": []})
    form_regex = forms_settings.Regex()

    if request.method == "POST":
        if form_regex.test_regex.data:
            form_data = {"regex": form_regex.regex.data, "text": form_regex.text.data}
            regex_return = {
                "findall": re.findall(form_regex.regex.data, form_regex.text.data),
                "search": re.search(form_regex.regex.data, form_regex.text.data),
                "finditer": re.finditer(form_regex.regex.data, form_regex.text.data),
                "match": re.match(form_regex.regex.data, form_regex.text.data)
            }

    return render_template("pages/regex.html",
                           form_regex=form_regex,
                           regex_return=regex_return,
                           status_msg=status_msg,
                           form_data=form_data)

def decrypt_and_regen_html(message, post_id, status_msg):
    try:
        # Decode message
        msg = base64.b64decode(message.message_original).decode()

        # Check if message is an encrypted PGP message
        if not msg.startswith("-----BEGIN PGP MESSAGE-----"):
            status_msg['status_message'].append("{}: Message doesn't appear to be PGP message. Deleting.".format(
                message.message_id[-config.ID_LENGTH:].upper()))

        pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
        if message.thread.chan.pgp_passphrase_msg:
            pgp_passphrase_msg = message.thread.chan.pgp_passphrase_msg

        # Decrypt the message
        # Protect against explosive PGP message size exploit
        msg_decrypted = decrypt_safe_size(msg, pgp_passphrase_msg, 400000)

        if msg_decrypted is not None:
            msg_decrypted_dict = json.loads(msg_decrypted)
            if not msg_decrypted_dict["message"]:
                return status_msg

            msg_decrypted_dict["message"] = html.escape(msg_decrypted_dict["message"])

            # perform admin command word replacements
            admin_cmd = Command.query.filter(and_(
                Command.chan_address == message.thread.chan.address,
                Command.action == "set",
                Command.action_type == "options")).first()
            if admin_cmd and admin_cmd.options:
                try:
                    options = json.loads(admin_cmd.options)
                except:
                    options = {}
                if "word_replace" in options:
                    msg_decrypted_dict["message"] = replace_dict_keys_with_values(
                        msg_decrypted_dict["message"], options["word_replace"])

            message.original_message = msg_decrypted_dict["message"]
            message.save()
    except Exception as err:
        status_msg['status_message'].append(
            f"Couldn't decrypt post {post_id}: {err}")
        logger.exception(f"Couldn't decrypt post {post_id}")

    try:
        regenerate_card_popup_post_html(message_id=message.message_id)
        status_msg['status_title'] = "Success"
        status_msg['status_message'].append(f"Decrypted and Regenerated HTML for post {post_id}.")
    except Exception as err:
        status_msg['status_message'].append(
            f"Couldn't decrypt and regenerate HTML for post {post_id}: {err}")
        logger.exception(f"Couldn't decrypt and regenerate HTML for post {post_id}")

    try:
        process_replacements(
            message.original_message, message.message_id, message.message_id,
            address=message.thread.chan.address, force_replacements=True)
    except Exception as err:
        status_msg['status_message'].append(
            f"Couldn't process replacements for post {post_id}: {err}")
        logger.exception(f"Couldn't process replacements for for post {post_id}")

    return status_msg
