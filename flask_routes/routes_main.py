import base64
import csv
import datetime
import html
import json
import logging
import os
import subprocess
import time
import zipfile
from collections import OrderedDict
from io import StringIO

from PIL import Image
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_
from sqlalchemy import or_
from stem import CircStatus
from stem import Signal
from stem.connection import PasswordAuthFailed
from stem.control import Controller
from werkzeug.wrappers import Response

import config
from bitchan_client import DaemonCom
from database.models import AddressBook
from database.models import Chan
from database.models import Command
from database.models import Flags
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import ModLog
from database.models import Threads
from database.models import UploadProgress
from database.models import UploadSites
from flask_routes.utils import is_verified
from flask_routes.utils import rate_limit
from forms import forms_board
from forms import forms_settings
from utils.cards import generate_card
from utils.files import LF
from utils.files import delete_file
from utils.gateway import api
from utils.general import display_time
from utils.general import get_random_alphanumeric_string
from utils.html_truncate import truncate
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.routes import allowed_access
from utils.routes import page_dict
from utils.tor import path_torrc
from utils.tor import str_custom_enabled
from utils.tor import str_random_enabled

logger = logging.getLogger('bitchan.routes_main')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_main',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.before_request
def before_view():
    logger.info("Pre request session: {}".format(session))
    if not is_verified():
        return redirect(url_for('routes_verify.verify_wait'))


@blueprint.route('/', methods=('GET', 'POST'))
@rate_limit
def index():
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    try:
        status = daemon_com.get_api_status()
    except:
        status = False
    status_msg = {"status_message": []}
    settings = GlobalSettings.query.first()

    if status is not True:
        status_msg['status_title'] = "Error"
        if status == "ConnectionRefusedError(111, 'Connection refused')":
            status_msg['status_message'].append("Is Bitmessage running?")

    # Get OP and up to 3 replies for up to 3 threads from each board
    cards = OrderedDict()
    now = time.time()
    ts_month = now - (60 * 60 * 24 * 30)

    boards = Chan.query.filter(Chan.type == "board").order_by(
        Chan.timestamp_sent.desc())

    lists = Chan.query.filter(Chan.type == "list").order_by(
        Chan.list_timestamp_changed.desc())

    count = 0
    for each_board in boards.all():
        time_wipe = None
        rules = json.loads(each_board.rules)
        if "automatic_wipe" in rules and "wipe_epoch" in rules["automatic_wipe"]:
            time_wipe = datetime.datetime.fromtimestamp(
                rules["automatic_wipe"]["wipe_epoch"]).strftime('%Y-%m-%d %H:%M')

        threads = Threads.query.filter(
            Threads.chan_id == each_board.id).order_by(
                Threads.timestamp_sent.desc()).limit(4).all()
        for each_thread in threads:
            if each_board not in cards:
                cards[each_board] = {
                    "type": "board",
                    "threads": OrderedDict(),
                    "latest_timestamp": each_board.timestamp_sent,
                    "total_threads": 0,
                    "total_posts": 0,
                    "wipe_date": time_wipe
                }
                count += 1

            cards[each_board]["threads"][each_thread.thread_hash] = {
                "last_post_past": None,
                "messages": [],
                "ppm": 0
            }

            # PPM
            cards[each_board]["threads"][each_thread.thread_hash]["ppm"] = Messages.query.filter(and_(
                Messages.thread_id == each_thread.id,
                Messages.timestamp_sent > ts_month)).count()

            # OP
            op_message = Messages.query.filter(and_(
                Messages.thread_id == each_thread.id,
                Messages.is_op.is_(True))).first()
            cards[each_board]["threads"][each_thread.thread_hash]["messages"].append(op_message)

            # Replies
            message = Messages.query.filter(
                and_(
                    Messages.thread_id == each_thread.id,
                    Messages.is_op.is_(False))).order_by(
                        Messages.timestamp_sent.desc()).first()
            if message:
                str_past = display_time(now - message.timestamp_sent)
                cards[each_board]["threads"][each_thread.thread_hash]["last_post_past"] = str_past
            elif op_message:
                str_past = display_time(now - op_message.timestamp_sent)
                cards[each_board]["threads"][each_thread.thread_hash]["last_post_past"] = str_past

        if each_board in cards:
            cards[each_board]["total_threads"] = Threads.query.filter(
                Threads.chan_id == each_board.id).count()

            threads = Threads.query.filter(
                Threads.chan_id == each_board.id).all()
            for each_thread in threads:
                cards[each_board]["total_posts"] += Messages.query.filter(
                    Messages.thread_id == each_thread.id).count()

        if count >= settings.chan_update_display_number:
            break

    count = 0
    for each_list in lists.all():
        time_wipe = None
        rules = json.loads(each_list.rules)
        if "automatic_wipe" in rules and "wipe_epoch" in rules["automatic_wipe"]:
            time_wipe = datetime.datetime.fromtimestamp(
                rules["automatic_wipe"]["wipe_epoch"]).strftime('%Y-%m-%d %H:%M')

        if each_list.list_timestamp_changed:
            str_past = display_time(time.time() - each_list.list_timestamp_changed)
            try:
                cards[each_list] = {
                    "type": "list",
                    "latest_timestamp": each_list.list_timestamp_changed,
                    "last_post_past": str_past,
                    "list_entries": len(json.loads(each_list.list)),
                    "wipe_date": time_wipe
                }
                count += 1
            except:
                logger.exception("Parsing list contents")

        if count >= settings.chan_update_display_number:
            break

    # Sort boards by latest post
    sorted_cards = OrderedDict(
        sorted(cards.items(), key=lambda x: x[1]['latest_timestamp'], reverse=True))

    sorted_counted_cards = OrderedDict()
    for i, (each_key, each_value) in enumerate(sorted_cards.items(), 1):
        sorted_counted_cards[each_key] = each_value
        if i >= settings.chan_update_display_number:
            break

    return render_template("pages/index.html",
                           generate_card=generate_card,
                           current_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
                           newest_posts=sorted_counted_cards,
                           status_msg=status_msg)


@blueprint.route('/overboard/<address>/<int:current_page>')
@rate_limit
def overboard(address, current_page):
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    settings = GlobalSettings.query.first()
    status_msg = {"status_message": []}
    now = time.time()

    # Get OP and up to 3 replies for up to 3 threads from each board
    thread_info = OrderedDict()
    ts_month = time.time() - (60 * 60 * 24 * 30)

    overboard_info = {
        "single_board": False
    }

    if address != "0":
        per_page = settings.results_per_page_catalog
        post_start = (current_page - 1) * per_page
        post_end = (current_page * per_page) - 1

        chan = Chan.query.filter(
            Chan.address == address).first()
        if chan:
            overboard_info["single_board"] = True
            overboard_info["board_label"] = chan.label
            overboard_info["board_description"] = chan.description
            overboard_info["board_address"] = chan.address

            # Get remotely stickied threads
            admin_cmds = Command.query.filter(and_(
                Command.chan_address == chan.address,
                Command.thread_sticky.is_(True)))
            sticky_thread_ids = []
            for each_adm in admin_cmds.all():
                sticky_thread_ids.append(each_adm.thread_id)

            # Get locally stickied threads
            stickied_threads = Threads.query.filter(and_(
                Threads.chan_id == chan.id,
                Threads.stickied_local))
            for each_stick in stickied_threads:
                if each_stick.thread_hash not in sticky_thread_ids:
                    sticky_thread_ids.append(each_stick.thread_hash)

            threads = Threads.query.filter(
                Threads.chan_id == chan.id).order_by(
                    Threads.timestamp_sent.desc())
            overboard_info["thread_count"] = threads.count()

            threads_stickied_list = []
            for each_thread_id in sticky_thread_ids:
                thread_add = Threads.query.filter(
                    Threads.thread_hash == each_thread_id).first()
                if thread_add:
                    threads_stickied_list.append(thread_add)

            thread_count = 0
            for h, each_thread_set in enumerate([threads_stickied_list, threads.all()]):
                for each_thread in each_thread_set:
                    if h == 1 and each_thread.thread_hash in sticky_thread_ids:
                        continue
                    if thread_count > post_end:
                        break
                    if post_start <= thread_count:
                        thread_info[each_thread.thread_hash] = {
                            "board_address": each_thread.chan.address,
                            "board_label": each_thread.chan.label,
                            "board_description": each_thread.chan.description,
                            "last_post_past": None,
                            "messages": [],
                            "total_posts": Messages.query.filter(
                                Messages.thread_id == each_thread.id).count(),
                            "ppm": Messages.query.filter(and_(
                                Messages.thread_id == each_thread.id,
                                Messages.timestamp_sent > ts_month)).count()
                        }

                        # OP
                        op_message = Messages.query.filter(and_(
                            Messages.thread_id == each_thread.id,
                            Messages.is_op.is_(True))).first()
                        thread_info[each_thread.thread_hash]["messages"].append(op_message)

                        # Replies
                        message = Messages.query.filter(
                            and_(
                                Messages.thread_id == each_thread.id,
                                Messages.is_op.is_(False))).order_by(
                            Messages.timestamp_sent.desc()).first()
                        if message:
                            str_past = display_time(now - message.timestamp_sent)
                            thread_info[each_thread.thread_hash]["last_post_past"] = str_past
                        elif op_message:
                            str_past = display_time(now - op_message.timestamp_sent)
                            thread_info[each_thread.thread_hash]["last_post_past"] = str_past
                    thread_count += 1
    else:
        per_page = settings.results_per_page_overboard
        post_start = (current_page - 1) * per_page
        post_end = (current_page * per_page) - 1

        threads = Threads.query.order_by(
            Threads.timestamp_sent.desc())
        overboard_info["thread_count"] = threads.count()

        for i, each_thread in enumerate(threads.all()):
            if i > post_end:
                break
            if post_start <= i:
                thread_info[each_thread.thread_hash] = {
                    "board_address": each_thread.chan.address,
                    "board_label": each_thread.chan.label,
                    "board_description": each_thread.chan.description,
                    "last_post_past": None,
                    "messages": [],
                    "total_posts": Messages.query.filter(
                        Messages.thread_id == each_thread.id).count(),
                    "ppm": Messages.query.filter(and_(
                        Messages.thread_id == each_thread.id,
                        Messages.timestamp_sent > ts_month)).count()
                }

                # OP
                op_message = Messages.query.filter(and_(
                    Messages.thread_id == each_thread.id,
                    Messages.is_op.is_(True))).first()
                thread_info[each_thread.thread_hash]["messages"].append(op_message)

                # Replies
                message = Messages.query.filter(
                    and_(
                        Messages.thread_id == each_thread.id,
                        Messages.is_op.is_(False))).order_by(
                            Messages.timestamp_sent.desc()).first()
                if message:
                    str_past = display_time(now - message.timestamp_sent)
                    thread_info[each_thread.thread_hash]["last_post_past"] = str_past
                elif op_message:
                    str_past = display_time(now - op_message.timestamp_sent)
                    thread_info[each_thread.thread_hash]["last_post_past"] = str_past

    return render_template("pages/overboard.html",
                           address=address,
                           current_page=current_page,
                           generate_card=generate_card,
                           overboard_info=overboard_info,
                           per_page=per_page,
                           thread_info=thread_info,
                           truncate=truncate,
                           status_msg=status_msg)


def delete_posts_threads(message_ids):
    post_ids_delete = []
    thread_hashes_delete = []
    for each_msg_id in message_ids:
        msg = Messages.query.filter(
            Messages.message_id == each_msg_id).first()
        if msg:
            if msg.is_op:
                # Delete thread
                if msg.thread:
                    thread_hashes_delete.append(msg.thread.thread_hash)
            else:
                post_ids_delete.append(msg.message_id)

    # Delete individual messages
    for each_msg_id in post_ids_delete:
        delete_post(each_msg_id)

    # Delete messages of a thread and the thread
    for each_thread_hash in thread_hashes_delete:
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


@blueprint.route('/recent/<address>/<int:current_page>', methods=('GET', 'POST'))
@rate_limit
def recent_posts(address, current_page):
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    settings = GlobalSettings.query.first()
    status_msg = {"status_message": []}

    msg_count = 0

    recent_info = {
        "single_board": False
    }

    if request.method == 'POST':
        global_admin, allow_msg = allowed_access(
            check_is_global_admin=True)
        if not global_admin:
            return allow_msg

        try:
            delete_bulk_message_ids = []
            for each_input in request.form:
                if each_input.startswith("deletebulk_"):
                    delete_bulk_message_ids.append(each_input.split("_")[1])

            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
                try:
                    delete_posts_threads(delete_bulk_message_ids)
                    status_msg['status_message'].append("Deleted posts/threads")
                except Exception as err:
                    logger.error("Exception while deleting posts/threads: {}".format(err))
                finally:
                    daemon_com.signal_generate_post_numbers()
                    lf.lock_release(config.LOCKFILE_MSG_PROC)

            status_msg['status_title'] = "Success"
            status_msg['status_title'] = "Deleted Posts/Threads"
        except:
            logger.exception("deleting posts/threads")

    post_start = (current_page - 1) * settings.results_per_page_recent
    post_end = (current_page * settings.results_per_page_recent) - 1
    recent_results = []

    if address != "0":
        chan = Chan.query.filter(
            Chan.address == address).first()
        if chan:
            recent_info["single_board"] = True
            recent_info["board_label"] = chan.label
            recent_info["board_description"] = chan.description
            recent_info["board_address"] = chan.address

            messages = Messages.query.join(Threads).join(Chan).filter(
                Chan.address == address).order_by(
                    Messages.timestamp_sent.desc())
            msg_count = messages.count()

            msg_total = 0
            for result in messages.all():
                if msg_total > post_end:
                    break
                if post_start <= msg_total:
                    recent_results.append(result)
                msg_total += 1
    else:
        messages = Messages.query.order_by(
            Messages.timestamp_sent.desc())
        msg_count = messages.count()
        for i, result in enumerate(messages.all()):
            if i > post_end:
                break
            if post_start <= i:
                recent_results.append(result)

    return render_template("pages/recent.html",
                           recent_page=current_page,
                           msg_count=msg_count,
                           now=time.time(),
                           recent_info=recent_info,
                           recent_results=recent_results,
                           status_msg=status_msg)


@blueprint.route('/search/<search_b64>/<int:current_page>', methods=('GET', 'POST'))
@rate_limit
def search(search_b64, current_page):
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    settings = GlobalSettings.query.first()
    status_msg = {"status_message": []}
    search_string_b64 = search_b64
    search_results = []
    search_count = 0
    if search_b64 == '0':
        search_string = ""
    else:
        search_string = base64.b64decode(search_b64.encode()).decode()

    form_search = forms_board.Search()

    if request.method == 'POST':
        if form_search.submit.data:
            if not form_search.search.data or len(form_search.search.data) < 3:
                status_msg['status_message'].append(
                    "At search string of at least 3 characters is required.")
            else:
                current_page = 1

            if not status_msg['status_message']:
                search_string = form_search.search.data
                search_string_b64 = base64.urlsafe_b64encode(search_string.encode()).decode()
                status_msg['status_title'] = "Success"

        else:
            global_admin, allow_msg = allowed_access(
                check_is_global_admin=True)
            if not global_admin:
                return allow_msg

            try:
                delete_bulk_message_ids = []
                for each_input in request.form:
                    if each_input.startswith("deletebulk_"):
                        delete_bulk_message_ids.append(each_input.split("_")[1])

                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
                    try:
                        delete_posts_threads(delete_bulk_message_ids)
                        status_msg['status_message'].append("Deleted posts/threads")
                    except Exception as err:
                        logger.error("Exception while deleting posts/threads: {}".format(err))
                    finally:
                        daemon_com.signal_generate_post_numbers()
                        lf.lock_release(config.LOCKFILE_MSG_PROC)

                status_msg['status_title'] = "Success"
                status_msg['status_title'] = "Deleted Posts/Threads"
            except:
                logger.exception("deleting posts/threads")

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    if search_string:
        search = Messages.query.filter(or_(
            Messages.message.contains(search_string),
            Messages.message_id.contains(search_string.lower()),
            and_(Messages.subject.contains(search_string),
                 Messages.is_op.is_(True))
        )).order_by(Messages.timestamp_sent.desc())

        search_count = search.count()

        search_start = (current_page - 1) * settings.results_per_page_search
        search_end = (current_page * settings.results_per_page_search) - 1
        search_results = []
        for i, result in enumerate(search.all()):
            if i > search_end:
                break
            if search_start <= i:
                search_results.append(result)

    return render_template("pages/search.html",
                           now=time.time(),
                           search_page=current_page,
                           search_count=search_count,
                           search_results=search_results,
                           search_string=search_string,
                           search_string_b64=search_string_b64,
                           status_msg=status_msg)


@blueprint.route('/mod_log/<address>/<int:current_page>', methods=('GET', 'POST'))
@rate_limit
def mod_log(address, current_page):
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    settings = GlobalSettings.query.first()

    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    if settings.kiosk_only_admin_access_mod_log and not global_admin:
        return allow_msg

    status_msg = {"status_message": []}

    if request.method == 'POST':
        global_admin, allow_msg = allowed_access(
            check_is_global_admin=True)
        if not global_admin:
            return allow_msg

        try:
            delete_bulk_mod_log_ids = []
            for each_input in request.form:
                if each_input.startswith("deletebulk_"):
                    delete_bulk_mod_log_ids.append(each_input.split("_")[1])

            if not delete_bulk_mod_log_ids:
                status_msg['status_title'] = "Error"
                status_msg['status_message'].append("Must select at least one entry to delete")

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
                    try:
                        for each_id in delete_bulk_mod_log_ids:
                            mod_log_entry = ModLog.query.filter(ModLog.id == each_id).first()
                            if mod_log_entry:
                                mod_log_entry.delete()

                        status_msg['status_message'].append(
                            "Deleted {} Mod Log {}".format(
                                len(delete_bulk_mod_log_ids),
                                "entries" if len(delete_bulk_mod_log_ids) > 1 else "entry"))
                        status_msg['status_title'] = "Success"
                    except Exception as err:
                        logger.error("Exception while deleting Mod Log entries: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_MSG_PROC)
        except:
            logger.exception("deleting Mod Log entries")

    if address != "0":
        mod_log = ModLog.query.filter(
            ModLog.board_address == address).order_by(ModLog.timestamp.desc())
    else:
        mod_log = ModLog.query.order_by(ModLog.timestamp.desc())

    mod_log_count = mod_log.count()

    post_start = (current_page - 1) * settings.results_per_page_mod_log
    post_end = (current_page * settings.results_per_page_mod_log) - 1
    mod_log_results = []
    for i, result in enumerate(mod_log.all()):
        if i > post_end:
            break
        if post_start <= i:
            mod_log_results.append(result)

    return render_template("pages/mod_log.html",
                           address=address,
                           now=time.time(),
                           mod_log_page=current_page,
                           mod_log_count=mod_log_count,
                           mod_log=mod_log_results,
                           status_msg=status_msg)


@blueprint.route('/help')
@rate_limit
def help_docs():
    allowed, allow_msg = allowed_access(check_can_view=True)
    if not allowed:
        return allow_msg

    return render_template("pages/help.html")


@blueprint.route('/configure', methods=('GET', 'POST'))
def configure():
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    if not global_admin:
        return allow_msg

    form_settings = forms_settings.Settings()
    form_flag = forms_settings.Flag()

    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_flag.flag_upload.data:
            flag_save_path = None

            if not form_flag.flag_file.data:
                status_msg['status_message'].append("A file upload is required.")
            if not form_flag.flag_name.data:
                status_msg['status_message'].append("A flag name is required.")
            if len(form_flag.flag_name.data) > 64:
                status_msg['status_message'].append("Flag name must be a maximum of 64 characters")

            if not status_msg['status_message']:
                flag_filename = html.escape(form_flag.flag_file.data.filename)
                flag_extension = html.escape(os.path.splitext(flag_filename)[1].split(".")[-1].lower())
                if flag_extension not in config.FILE_EXTENSIONS_IMAGE:
                    status_msg['status_message'].append(
                        "Unsurrpoted extension. Supported: {}".format(config.FILE_EXTENSIONS_IMAGE))

            if not status_msg['status_message']:
                flag_save_path = "/tmp/{}.{}".format(
                    get_random_alphanumeric_string(
                        12, with_spaces=False, with_punctuation=False),
                    flag_extension)

                # Save file to disk
                form_flag.flag_file.data.save(flag_save_path)

                flag_file_size = os.path.getsize(flag_save_path)
                flag = Image.open(flag_save_path)
                flag_width, flag_height = flag.size
                logger.info("Uploaded flag is {} wide x {} high, {} bytes".format(
                    flag_width, flag_height, flag_file_size))
                if flag_width > config.FLAG_MAX_WIDTH or flag_height > config.FLAG_MAX_HEIGHT:
                    status_msg['status_message'].append(
                        "At least one of the flag's dimensions is too large. Max 25px width, 15px height.")
                if flag_file_size > config.FLAG_MAX_SIZE:
                    status_msg['status_message'].append(
                        "Flag file size is too large. Must be less than or equal to 3500 bytes.")

            if not status_msg['status_message']:
                new_flag = Flags()
                new_flag.name = form_flag.flag_name.data
                new_flag.flag_extension = flag_extension
                new_flag.flag_base64 = base64.b64encode(open(flag_save_path, "rb").read()).decode()
                new_flag.save()

            if flag_save_path:
                delete_file(flag_save_path)

        elif form_flag.flag_rename.data:
            if not form_flag.flag_name.data:
                status_msg['status_message'].append("A flag name is required.")

            if not status_msg['status_message']:
                flag = Flags.query.filter(Flags.id == int(form_flag.flag_id.data)).first()
                if flag:
                    flag.name = form_flag.flag_name.data
                    flag.save()

        elif form_flag.flag_delete.data:
            flag = Flags.query.filter(Flags.id == int(form_flag.flag_id.data)).first()
            if flag:
                flag.delete()

        elif form_settings.save.data:
            settings = GlobalSettings.query.first()
            if form_settings.theme.data:
                settings.theme = form_settings.theme.data
            settings.max_download_size = form_settings.max_download_size.data
            settings.max_extract_size = form_settings.max_extract_size.data
            settings.allow_net_file_size_check = form_settings.allow_net_file_size_check.data
            settings.allow_net_book_quote = form_settings.allow_net_book_quote.data
            settings.allow_net_ntp = form_settings.allow_net_ntp.data
            settings.never_auto_download_unencrypted = form_settings.never_auto_download_unencrypted.data
            settings.auto_dl_from_unknown_upload_sites = form_settings.auto_dl_from_unknown_upload_sites.data
            settings.delete_sent_identity_msgs = form_settings.delete_sent_identity_msgs.data
            settings.home_page_msg = form_settings.home_page_msg.data
            settings.html_head = form_settings.html_head.data
            settings.html_body = form_settings.html_body.data
            settings.results_per_page_board = form_settings.results_per_page_board.data
            settings.results_per_page_recent = form_settings.results_per_page_recent.data
            settings.results_per_page_search = form_settings.results_per_page_search.data
            settings.results_per_page_overboard = form_settings.results_per_page_overboard.data
            settings.results_per_page_catalog = form_settings.results_per_page_catalog.data
            settings.results_per_page_mod_log = form_settings.results_per_page_mod_log.data

            # Security
            settings.enable_captcha = form_settings.enable_captcha.data
            settings.enable_verification = form_settings.enable_verification.data
            settings.enable_page_rate_limit = form_settings.enable_page_rate_limit.data
            settings.max_requests_per_period = form_settings.max_requests_per_period.data
            settings.rate_limit_period_seconds = form_settings.rate_limit_period_seconds.data
            settings.hide_all_board_list_passphrases = form_settings.hide_all_board_list_passphrases.data

            # Kioks mode
            settings.enable_kiosk_mode = form_settings.enable_kiosk_mode.data
            settings.kiosk_login_to_view = form_settings.kiosk_login_to_view.data
            settings.kiosk_allow_posting = form_settings.kiosk_allow_posting.data
            settings.kiosk_disable_bm_attach = form_settings.kiosk_disable_bm_attach.data
            settings.kiosk_allow_download = form_settings.kiosk_allow_download.data
            settings.kiosk_post_rate_limit = form_settings.kiosk_post_rate_limit.data
            settings.kiosk_attempts_login = form_settings.kiosk_attempts_login.data
            settings.kiosk_ban_login_sec = form_settings.kiosk_ban_login_sec.data
            settings.kiosk_only_admin_access_mod_log = form_settings.kiosk_only_admin_access_mod_log.data

            if (form_settings.chan_update_display_number.data and
                    form_settings.chan_update_display_number.data >= 0):
                settings.chan_update_display_number = form_settings.chan_update_display_number.data
            settings.save()
            daemon_com.refresh_settings()
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append("Settings saved")

        elif form_settings.export_chans.data:
            def export_boards_lists(chans):
                data = StringIO()
                w = csv.writer(data)

                w.writerow(('type', 'label', 'description', 'access', 'address', 'passphrase'))
                yield data.getvalue()
                data.seek(0)
                data.truncate(0)

                for each_chan in chans:
                    w.writerow((
                        each_chan.type,
                        each_chan.label,
                        each_chan.description,
                        each_chan.access,
                        each_chan.address,
                        each_chan.passphrase
                    ))
                    yield data.getvalue()
                    data.seek(0)
                    data.truncate(0)

            chans = Chan.query.order_by(
                Chan.type.asc(),
                Chan.label.asc()).all()
            response = Response(export_boards_lists(chans), mimetype='text/csv')
            response.headers.set(
                "Content-Disposition",
                "attachment",
                filename="BitChan Backup Board-List {}.csv".format(
                    datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S")))
            return response

        elif form_settings.export_identities.data:
            def export_identities(identities):
                data = StringIO()
                w = csv.writer(data)

                w.writerow(('label', 'address', 'passphrase'))
                yield data.getvalue()
                data.seek(0)
                data.truncate(0)

                for each_ident in identities:
                    w.writerow((
                        each_ident.label,
                        each_ident.address,
                        base64.b64decode(each_ident.passphrase_base64).decode()
                    ))
                    yield data.getvalue()
                    data.seek(0)
                    data.truncate(0)

            identities = Identity.query.order_by(
                Identity.label.asc()).all()
            response = Response(export_identities(identities), mimetype='text/csv')
            response.headers.set(
                "Content-Disposition",
                "attachment",
                filename="BitChan Backup Identities {}.csv".format(
                    datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S")))
            return response

        elif form_settings.export_address_book.data:
            def export_address_book(address_book):
                data = StringIO()
                w = csv.writer(data)

                w.writerow(('label', 'address'))
                yield data.getvalue()
                data.seek(0)
                data.truncate(0)

                for each_ab in address_book:
                    w.writerow((
                        each_ab.label,
                        each_ab.address
                    ))
                    yield data.getvalue()
                    data.seek(0)
                    data.truncate(0)

            address_book = AddressBook.query.order_by(
                AddressBook.label.asc()).all()
            response = Response(export_address_book(address_book), mimetype='text/csv')
            response.headers.set(
                "Content-Disposition",
                "attachment",
                filename="BitChan Backup Address Book {}.csv".format(
                    datetime.datetime.now().strftime("%Y-%m-%d %H_%M_%S")))
            return response

        elif form_settings.save_tor_settings.data or form_settings.get_new_rand_tor.data:
            if form_settings.enable_cus_tor_address.data and not form_settings.tor_file.data:
                status_msg['status_message'].append(
                    "If a custom address is enabled, a ZIP needs to be selected.")
            elif form_settings.get_new_rand_tor.data and not form_settings.enable_rand_tor_address.data:
                status_msg['status_message'].append(
                    "Random address needs to be enabled to get a new random address.")
            else:
                if form_settings.enable_cus_tor_address.data and form_settings.tor_file.data:
                    try:
                        logger.info("Saving zip")
                        zip_filename = html.escape(form_settings.tor_file.data.filename)
                        save_path = "/usr/local/tor/cus/{}".format(zip_filename)
                        form_settings.tor_file.data.save(save_path)

                        logger.info("Extracting zip")
                        with zipfile.ZipFile(save_path, 'r') as zipObj:
                            zipObj.extractall("/usr/local/tor/cus/")

                        logger.info("Deleting zip")
                        delete_file(save_path)
                    except Exception as err:
                        status_msg['status_message'].append(
                            "Error enabling custom onion address: {}".format(err))

                if (form_settings.save_tor_settings.data or
                        (form_settings.get_new_rand_tor.data and
                         form_settings.enable_cus_tor_address.data)):
                    if form_settings.enable_rand_tor_address.data:
                        daemon_com.tor_enable_random_address()
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(
                            "Enable random onion address.")
                    else:
                        daemon_com.tor_disable_random_address()
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(
                            "Disabled random onion address.")

                    if form_settings.enable_cus_tor_address.data:
                        daemon_com.tor_enable_custom_address()
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(
                            "Enable custom onion address.")
                    else:
                        daemon_com.tor_disable_custom_address()
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(
                            "Disabled custom onion address.")

                if form_settings.get_new_rand_tor.data:
                    daemon_com.tor_get_new_random_address()
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(
                        "Getting new random onion address.")

                if not form_settings.enable_cus_tor_address.data:
                    daemon_com.tor_restart()

                status_msg['status_message'].append(
                    "Changes will take effect in a minute.")

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_main.configure"))

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

    return render_template("pages/configure.html",
                           form_settings=form_settings,
                           status_msg=status_msg,
                           tor_address_rand=tor_address_rand,
                           tor_enabled_rand=tor_enabled_rand,
                           tor_address_cus=tor_address_cus,
                           tor_enabled_cus=tor_enabled_cus,
                           upload_sites=UploadSites.query.all())


@blueprint.route('/upload_site/<action>/<upload_site_id>', methods=('GET', 'POST'))
def upload_site(action, upload_site_id):
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    if not global_admin:
        return allow_msg

    form_upload_site = forms_settings.UploadSite()

    status_msg = session.get('status_msg', {"status_message": []})
    site_options = None
    current_upload_site = None

    if action in ["edit", "delete"]:
        current_upload_site = UploadSites.query.filter(
            UploadSites.id == int(upload_site_id)).first()
    elif action == "add_msg_id":
        try:
            site_options = json.loads(Messages.query.filter(
                Messages.message_id == upload_site_id).first().file_upload_settings)
        except:
            pass

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_upload_site.add.data:
            if action == "add_msg_id":
                if site_options:
                    upload_site = UploadSites()
                    upload_site.domain = site_options["domain"]
                    upload_site.type = site_options["type"]
                    upload_site.uri = site_options["uri"]
                    upload_site.download_prefix = site_options["download_prefix"]
                    upload_site.response = site_options["response"]
                    upload_site.direct_dl_url = site_options["direct_dl_url"]
                    upload_site.extra_curl_options = site_options["extra_curl_options"]
                    upload_site.upload_word = site_options["upload_word"]
                    upload_site.form_name = site_options["form_name"]
                    upload_site.save()
                else:
                    status_msg['status_msg'].append("Message not found")
            elif action == "add":
                new_site = UploadSites()
                new_site.domain = form_upload_site.domain.data
                new_site.type = form_upload_site.type.data
                new_site.uri = form_upload_site.uri.data
                new_site.download_prefix = form_upload_site.download_prefix.data
                new_site.response = form_upload_site.response.data
                new_site.direct_dl_url = form_upload_site.direct_dl_url.data
                new_site.extra_curl_options = form_upload_site.extra_curl_options.data
                new_site.upload_word = form_upload_site.upload_word.data
                new_site.form_name = form_upload_site.form_name.data
                new_site.save()

            status_msg['status_message'].append("Upload site added")
            status_msg['status_title'] = "Success"

        elif form_upload_site.save.data:
            upload_site = UploadSites.query.filter(UploadSites.id == int(upload_site_id)).first()
            if upload_site:
                if form_upload_site.domain.data:
                    upload_site.domain = form_upload_site.domain.data
                else:
                    upload_site.domain = None
                if form_upload_site.type.data:
                    upload_site.type = form_upload_site.type.data
                else:
                    upload_site.type = None
                if form_upload_site.uri.data:
                    upload_site.uri = form_upload_site.uri.data
                else:
                    upload_site.uri = None
                if form_upload_site.download_prefix.data:
                    upload_site.download_prefix = form_upload_site.download_prefix.data
                else:
                    upload_site.download_prefix = None
                if form_upload_site.response.data:
                    upload_site.response = form_upload_site.response.data
                else:
                    upload_site.response = None
                upload_site.direct_dl_url = form_upload_site.direct_dl_url.data
                if form_upload_site.extra_curl_options.data:
                    upload_site.extra_curl_options = form_upload_site.extra_curl_options.data
                else:
                    upload_site.extra_curl_options = None
                if form_upload_site.upload_word.data:
                    upload_site.upload_word = form_upload_site.upload_word.data
                else:
                    upload_site.upload_word = None
                if form_upload_site.form_name.data:
                    upload_site.form_name = form_upload_site.form_name.data
                else:
                    upload_site.form_name = None
                upload_site.save()

                status_msg['status_message'].append("Upload site saved")
                status_msg['status_title'] = "Success"
            else:
                status_msg['status_msg'].append("Upload site not found")

        elif form_upload_site.delete.data:
            upload_site = UploadSites.query.filter(UploadSites.id == upload_site_id).first()
            if upload_site:
                upload_site.delete()

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_main.configure"))

    return render_template("pages/upload_site.html",
                           action=action,
                           current_upload_site=current_upload_site,
                           form_upload_site=form_upload_site,
                           site_options=site_options,
                           status_msg=status_msg,
                           upload_sites=UploadSites.query.all())


@blueprint.route('/status', methods=('GET', 'POST'))
def status():
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    if not global_admin:
        return allow_msg

    status_msg = session.get('status_msg', {"status_message": []})
    bm_status = {}
    tor_status = {"Circuit Established": False}
    form_status = forms_settings.Status()
    logging.getLogger("stem").setLevel(logging.WARNING)

    if request.method == 'POST':
        if form_status.tor_newnym.data:
            try:
                with Controller.from_port(address=config.TOR_HOST, port=config.TOR_CONTROL_PORT) as controller:
                    controller.authenticate(password=config.TOR_PASS)
                    controller.signal(Signal.NEWNYM)
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("New tor identity requested")
            except Exception as err:
                status_msg['status_message'].append("Error getting new tor identity: {}".format(err))

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
        try:
            bm_status_raw = api.clientStatus()
            bm_status = OrderedDict(sorted(bm_status_raw.items()))
        except Exception as err:
            logger.error("Error: {}".format(err))
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API)

    try:
        tor_version = subprocess.check_output(
            'docker exec -i tor tor --version --quiet', shell=True, text=True)
    except:
        logger.exception("getting tor version")
        tor_version = "Error getting tor version"

    tor_circuit_dict = {}
    try:
        with Controller.from_port(address=config.TOR_HOST, port=config.TOR_CONTROL_PORT) as controller:
            controller.authenticate(password=config.TOR_PASS)

            tor_status["Circuit Established"] = bool(controller.get_info('status/circuit-established'))

            for circ in sorted(controller.get_circuits()):
                if circ.status != CircStatus.BUILT:
                    continue

                tor_circuit_dict[circ.id] = {
                    "purpose": circ.purpose,
                    "subcircuits": []
                }

                for i, entry in enumerate(circ.path):
                    div = '+' if (i == len(circ.path) - 1) else '|'
                    fingerprint, nickname = entry

                    desc = controller.get_network_status(fingerprint, None)
                    address = desc.address if desc else 'unknown'

                    tor_circuit_dict[circ.id]["subcircuits"].append({
                        "div": div,
                        "fingerprint": fingerprint,
                        "nickname": nickname,
                        "address": address
                    })
    except PasswordAuthFailed:
        logger.error('Unable to authenticate, password is incorrect')
    except Exception:
        logger.exception("Tor stats")

    return render_template("pages/status.html",
                           bm_status=bm_status,
                           form_status=form_status,
                           status_msg=status_msg,
                           tor_circuit_dict=tor_circuit_dict,
                           tor_status=tor_status,
                           tor_version=tor_version,
                           upload_progress=UploadProgress.query.all())


@blueprint.route('/log', methods=('GET', 'POST'))
def log():
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    if not global_admin:
        return allow_msg

    form_log = forms_board.Log()

    log_file = "/usr/local/bitchan/log/bitchan.log"

    lines = 40
    if form_log.lines.data:
        lines = form_log.lines.data

    command = 'cat {log} | tail -n {lines}'.format(
        log=log_file, lines=lines)

    if command:
        log_ = subprocess.Popen(
            command, stdout=subprocess.PIPE, shell=True)
        (log_output, _) = log_.communicate()
        log_.wait()
        log_output = html.escape(str(log_output, 'latin-1')).replace("\n", "<br/>")
    else:
        log_output = 404

    return render_template("pages/log.html",
                           lines=lines,
                           log_output=log_output)
