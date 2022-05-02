import base64
import datetime
import glob
import json
import logging
import subprocess
import time
from threading import Thread

from flask import redirect
from flask import render_template
from flask import request
from flask import send_file
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

import config
from bitchan_client import DaemonCom
from database.models import Alembic
from database.models import Captcha
from database.models import Chan
from database.models import DeletedMessages
from database.models import Games
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import ModLog
from database.models import Threads
from database.models import UploadSites
from database.models import regenerate_upload_sites
from flask_routes import flask_session_login
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_board
from forms import forms_settings
from utils import themes
from utils.files import LF
from utils.files import delete_file
from utils.gateway import api
from utils.gateway import generate_identity
from utils.general import process_passphrase
from utils.posts import process_message_replies
from utils.replacements import replace_lt_gt
from utils.routes import allowed_access
from utils.routes import page_dict
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
        conn = sqlite3.connect('file:{}'.format(config.messages_dat), uri=True)
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
                    cancel_send_id_list.append(each_input.split("_")[1])

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

        if form_diag.del_inventory.data:
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

        elif form_diag.reset_downloads.data:
            try:
                msgs = Messages.query.filter(Messages.file_currently_downloading.is_(True)).all()
                for msg in msgs:
                    msg.file_currently_downloading = False
                    regenerate_card_popup_post_html(message_id=msg.message_id)
                    msg.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Reset downloads")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't reset downloads: {}".format(err))
                logger.exception("Couldn't reset downloads")

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

        elif form_diag.regenerate_all_post_numbers.data:
            try:
                daemon_com.generate_post_numbers(all_boards=True)
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Regenerated all post numbers")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't regenerate all post numbers: {}".format(err))
                logger.exception("Couldn't regenerate all post numbers")

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

        elif form_diag.download_backup.data:
            date_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            filename = 'bitchan-backup_{}.tar'.format(date_now)
            save_path = '/home/{}'.format(filename)

            def delete_backup_files():
                time.sleep(7200)
                delete_files = glob.glob("/home/*.tar")
                delete_files.append('/home/bitchan/bitchan_backup-usr_bitchan.tar')
                delete_files.append('/home/bitchan/bitchan_backup-usr_bitmessage.tar')
                delete_files.append('/home/bitchan/bitchan_backup-i2p.tar')
                for each_file in delete_files:
                    delete_file(each_file)

            try:
                cmd = 'tar -cvf /home/bitchan/bitchan_backup-usr_bitchan.tar /usr/local/bitchan'
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                cmd = 'tar -cvf /home/bitchan/bitchan_backup-usr_bitmessage.tar /usr/local/bitmessage'
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                cmd = 'tar -cvf /home/bitchan/bitchan_backup-i2p.tar /i2p/.i2p'
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                cmd = 'tar -cvf {} /home/bitchan'.format(save_path)
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                thread_download = Thread(target=delete_backup_files)
                thread_download.start()

                return send_file(save_path, mimetype='application/x-tar')
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't generate backup archive: {}".format(err))
                logger.exception("Couldn't generate backup archive")

        elif form_diag.restore_backup_file.data:
            try:
                save_path = '/tmp/bitchan-backup_to_restore.tar'
                delete_file(save_path)
                form_diag.restore_backup_file.data.save(save_path)

                cmd = 'tar -xvf {} -C /'.format(save_path)
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                cmd = 'tar -xvf /home/bitchan/bitchan_backup-usr_bitchan.tar -C /'
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                cmd = 'tar -xvf /home/bitchan/bitchan_backup-usr_bitmessage.tar -C /'
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                cmd = 'tar -xvf /home/bitchan/bitchan_backup-i2p -C /'
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                def delete_backup_files():
                    delete_files = [
                        save_path,
                        '/home/bitchan/bitchan_backup-usr_bitchan.tar',
                        '/home/bitchan/bitchan_backup-usr_bitmessage.tar'
                        '/home/bitchan/bitchan_backup-i2p.tar'
                    ]
                    for each_file in delete_files:
                        delete_file(each_file)

                subprocess.Popen('docker stop -t 15 bitchan_daemon 2>&1', shell=True)
                time.sleep(15)
                subprocess.Popen('docker start bitchan_daemon 2>&1', shell=True)

                subprocess.Popen('docker stop -t 15 bitchan_bitmessage 2>&1', shell=True)
                time.sleep(15)
                subprocess.Popen('docker start bitchan_bitmessage 2>&1', shell=True)

                subprocess.Popen('docker stop -t 15 bitchan_i2p 2>&1', shell=True)
                time.sleep(15)
                subprocess.Popen('docker start bitchan_i2p 2>&1', shell=True)

                thread_download = Thread(target=delete_backup_files)
                thread_download.start()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Restored backup and restarted Bitmessage and BitChan")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't restore backup: {}".format(err))
                logger.exception("Couldn't restore backup archive")

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

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    captcha_entry_count = Captcha.query.count()
    game_entry_count = Games.query.count()

    bm_identities = daemon_com.get_identities()
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

    return render_template("pages/diag.html",
                           captcha_entry_count=captcha_entry_count,
                           flask_session_login=flask_session_login,
                           form_diag=form_diag,
                           game_entry_count=game_entry_count,
                           orphaned_identities_bc=orphaned_identities_bc,
                           orphaned_identities_bm=orphaned_identities_bm,
                           replace_lt_gt=replace_lt_gt,
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
                # Only send from a board or list
                # Do not send from an identity
                if config.DEFAULT_CHANS[0]["address"] in daemon_com.get_all_chans():
                    address_from = config.DEFAULT_CHANS[0]["address"]
                elif daemon_com.get_all_chans():
                    address_from = list(daemon_com.get_all_chans().keys())[0]
                else:
                    status_msg['status_message'].append(
                        "Could not find address to send from. "
                        "Join/Create a board or list and try again.")
                    address_from = None

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

                if not status_msg['status_message']:
                    if address_from:
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
                                        config.BITCHAN_BUG_REPORT_ADDRESS,
                                        address_from,
                                        subject_b64,
                                        message_b64,
                                        2,
                                        config.BM_TTL)
                                    if return_str:
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
