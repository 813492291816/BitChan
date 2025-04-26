import base64
import csv
import datetime
import html
import json
import logging
import os
import subprocess
import sys
import time
import zipfile
from collections import OrderedDict
from io import BytesIO
from io import StringIO
from threading import Thread

import matplotlib.pyplot as plt
import numpy as np
import pytz
from PIL import Image
from feedgen.feed import FeedGenerator
from flask import current_app
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import send_from_directory
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
from database.models import Alembic
from database.models import Auth
from database.models import Chan
from database.models import Command
from database.models import EndpointCount
from database.models import Flags
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import ModLog
from database.models import Threads
from database.models import UploadProgress
from database.models import UploadSites
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from flask_routes.utils import rate_limit
from forms import forms_board
from forms import forms_settings
from utils.cards import generate_card
from utils.files import LF
from utils.files import delete_file
from utils.files import get_directory_size
from utils.files import human_readable_size
from utils.gateway import api
from utils.general import display_time
from utils.general import get_random_alphanumeric_string
from utils.html_truncate import truncate
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.posts import restore_post
from utils.posts import restore_thread
from utils.routes import allowed_access
from utils.routes import get_logged_in_user_name
from utils.routes import get_onion_info
from utils.routes import page_dict
from utils.routes import rate_limit_check
from utils.shared import add_mod_log_entry
from utils.shared import check_tld_i2p
from utils.shared import regenerate_card_popup_post_html

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
    try:  # Don't require login for RSS feed
        if request.url_rule.rule.startswith("/rss/"):
            return
    except:
        pass
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


@blueprint.route('/bc.ico')
def favicon():
    return send_from_directory(os.path.join(current_app.root_path, 'static'),
                               'bc.ico', mimetype='image/vnd.microsoft.icon')


@blueprint.route('/', methods=('GET', 'POST'))
@count_views
@rate_limit
def index():
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    global_admin, _ = allowed_access("is_global_admin")

    status_msg = {"status_message": []}
    settings = GlobalSettings.query.first()

    try:
        inventory_timer_epoch = daemon_com.get_timer_clear_inventory()
        now = time.time()
        if inventory_timer_epoch < now:
            inventory_timer = None
        else:
            inventory_timer = int(inventory_timer_epoch - now)
    except:
        inventory_timer = None

    try:
        api_available = daemon_com.get_api_status()
    except:
        api_available = False

    if not api_available:
        status_msg['status_title'] = "Error"
        status_msg['status_message'].append(
            "Cannot connect to Bitmessage. Is it running and is BitChan configured to connect to its API?")

    # Get OP and up to 3 replies for up to 3 threads from each board
    cards = OrderedDict()
    now = time.time()
    ts_month = now - (60 * 60 * 24 * 30)

    board_order = Chan.timestamp_sent.desc()
    thread_order_desc = Threads.timestamp_sent.desc()
    if settings.post_timestamp == 'received':
        board_order = Chan.timestamp_received.desc()
        thread_order_desc = Threads.timestamp_received.desc()

    if global_admin:
        boards = Chan.query.filter(
            Chan.type == "board").order_by(board_order)

        lists = Chan.query.filter(
            Chan.type == "list").order_by(Chan.list_timestamp_changed.desc())
    else:
        boards = Chan.query.filter(
            Chan.type == "board",
            Chan.unlisted.is_(False),
            Chan.restricted.is_(False)).order_by(board_order)

        lists = Chan.query.filter(
            Chan.type == "list",
            Chan.unlisted.is_(False),
            Chan.restricted.is_(False)).order_by(Chan.list_timestamp_changed.desc())

    count = 0
    for each_board in boards.all():
        wipe_epoch = None
        rules = json.loads(each_board.rules)
        if "automatic_wipe" in rules and "wipe_epoch" in rules["automatic_wipe"]:
            wipe_epoch = rules["automatic_wipe"]["wipe_epoch"]

        threads = Threads.query.filter(and_(
            Threads.chan_id == each_board.id,
            Threads.hide.is_(False))).order_by(thread_order_desc).limit(4).all()
        for each_thread in threads:
            post_order_desc = Messages.timestamp_sent.desc()
            if settings.post_timestamp == 'received':
                post_order_desc = Messages.timestamp_received.desc()

            if each_board not in cards:
                latest_timestamp = each_board.timestamp_sent
                if settings.post_timestamp == 'received':
                    latest_timestamp = each_board.timestamp_received

                cards[each_board] = {
                    "type": "board",
                    "threads": OrderedDict(),
                    "latest_timestamp": latest_timestamp,
                    "total_threads": 0,
                    "total_posts": 0,
                    "wipe_epoch": wipe_epoch
                }
                count += 1

            cards[each_board]["threads"][each_thread.thread_hash] = {
                "last_post_past": None,
                "total_posts": 0,
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
                    Messages.is_op.is_(False))).order_by(post_order_desc)
            if message.first():
                str_past = display_time(now - message.first().timestamp_sent)
                cards[each_board]["threads"][each_thread.thread_hash]["last_post_past"] = str_past
                cards[each_board]["threads"][each_thread.thread_hash]["total_posts"] = message.count()
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
        wipe_epoch = None
        rules = json.loads(each_list.rules)
        if "automatic_wipe" in rules and "wipe_epoch" in rules["automatic_wipe"]:
            wipe_epoch = rules["automatic_wipe"]["wipe_epoch"]

        if each_list.list_timestamp_changed:
            str_past = display_time(time.time() - each_list.list_timestamp_changed)
            try:
                cards[each_list] = {
                    "type": "list",
                    "latest_timestamp": each_list.list_timestamp_changed,
                    "last_post_past": str_past,
                    "list_entries": len(json.loads(each_list.list)),
                    "wipe_epoch": wipe_epoch
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
                           inventory_timer=inventory_timer,
                           current_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
                           newest_posts=sorted_counted_cards,
                           status_msg=status_msg)


@blueprint.route('/rss/<url>/<board_address>/<thread_id>')
@count_views
def rss(url, board_address, thread_id):
    """Generate RSS feed"""
    settings = GlobalSettings.query.first()
    if ((url == "tor" and not settings.rss_enable) or  # Check if enabled
            (url == "i2p" and not settings.rss_enable_i2p)):
        return "DISABLED"

    if url == "tor":
        url_domain = settings.rss_url
    elif url == "i2p":
        url_domain = settings.rss_url_i2p
    else:
        return "PAGE NOT FOUND"

    # Check rate limit
    if rate_limit_check(settings.rss_rate_limit_number_requests, settings.rss_rate_limit_period_sec, "RSS"):
        return "RATE LIMITED"

    if board_address != "0":
        # Check if board/thread exists
        chan = Chan.query.filter(Chan.address == board_address).first()
        if not chan:
            return "BOARD NOT FOUND"

    if thread_id != "0":
        if len(thread_id) == 12:
            thread = Threads.query.filter(Threads.thread_hash_short == thread_id).first()
        else:
            thread = Threads.query.filter(Threads.thread_hash == thread_id).first()
        if not thread:
            return "THREAD NOT FOUND"

    # Don't allow posts from restricted boards or hidden threads/posts to be returned
    posts = Messages.query.join(Threads).join(Chan).filter(and_(
        Chan.unlisted.is_(False),
        Chan.restricted.is_(False),
        Threads.hide.is_(False),
        Messages.hide.is_(False)))

    fg = FeedGenerator()

    # Generate the RSS file name, feed title and link, and select proper posts (for board or thread)
    if thread_id != "0" and thread:
        fg.description(f'Board Description: {chan.description}')
        fn = f"bitchan_{chan.label}_thread_{thread.subject}.rss"
        fg.title(f'/{chan.label}/ Thread Posts: {thread.subject}')
        fg.link(href=f'{url_domain}/thread/{board_address}/{thread.thread_hash_short}')
        posts = posts.filter(Threads.thread_hash == thread.thread_hash)
    elif board_address != "0" and chan:
        fg.description(f'Board Description: {chan.description}')
        fn = f"bitchan_{chan.label}.rss"
        fg.title(f'/{chan.label}/ Board Posts')
        fg.link(href=f'{url_domain}/board/{board_address}/1')
        posts = posts.filter(Chan.address == board_address)
    elif board_address == "0" and thread_id == "0":
        fg.description(f'BitChan')
        fn = f"bitchan.rss"
        fg.title(f'All Posts')
        fg.link(href=f'{url_domain}')
    else:
        return "INVALID RSS REQUEST"

    # Use the correct timestamp for post selection/sorting
    if settings.post_timestamp == 'received':
        posts = posts.order_by(Messages.timestamp_received.desc())
    else:
        posts = posts.order_by(Messages.timestamp_sent.desc())

    # Limit number of posts in feed
    try:
        last = int(request.args.get('last'))
    except:
        last = 0
    if 0 < last < settings.rss_number_posts:
        posts = posts.limit(last)
    else:
        posts = posts.limit(settings.rss_number_posts)

    for post in posts.all():
        content = ""

        # Check for attachments
        try:
            file_list = []
            file_order = json.loads(post.file_order)
            for file in file_order:
                if file:
                    file_list.append(file)
            if file_list:
                content += f"[Attachments: {', '.join(file_list)}]<br/><br/>"
        except:
            pass

        try:
            fe = fg.add_entry()
            fe.link(href=f"{url_domain}/thread/{post.thread.chan.address}/{post.thread.thread_hash_short}#{post.post_id.upper()}")
            fe.guid(post.post_id, permalink=True)
            fe.author(name=post.address_from)

            # Use the correct timestamp for each post
            if settings.post_timestamp == 'received':
                fe.pubDate(datetime.datetime.fromtimestamp(
                    post.timestamp_received, tz=pytz.timezone(settings.post_timestamp_timezone)))
            else:
                fe.pubDate(datetime.datetime.fromtimestamp(
                    post.timestamp_sent, tz=pytz.timezone(settings.post_timestamp_timezone)))

            # Indicate if post is OP or Reply
            if post.is_op:
                fe.title(f"{post.thread.subject} (OP)")
            else:
                fe.title(f"{post.thread.subject} (Reply)")

            # Determine if content will be plain text or include HTML formatting
            if settings.rss_use_html_posts and post.popup_html:
                # HTML content doesn't get to choose truncation length, uses whichever the popup HTML generator has set
                content += post.popup_html
                fe.content(content=content, type='CDATA')
            else:
                if len(post.message) > settings.rss_char_length:
                    is_truncated, str_trunc = truncate(post.message, settings.rss_char_length)
                    content += f'{str_trunc}...'
                    fe.description(content)
                else:
                    content += post.message
                    fe.description(content)
        except:
            logger.exception(f"Exception adding post {post.post_id.upper()} to RSS")

    response = make_response(fg.rss_str())
    response.headers.set('Content-Type', 'application/rss+xml')
    response.headers.set('Content-Disposition', f'attachment; filename={fn}')

    return response


@blueprint.route('/options_save', methods=('GET', 'POST'))
@count_views
@rate_limit
def options_save():
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    full_path_url = request.referrer
    if not full_path_url:
        full_path_url = url_for('routes_main.index')

    response = make_response(redirect(full_path_url))

    if request.method == "POST":
        if request.form.get('options_save_css'):
            response.set_cookie('options_css', request.form.get('options_css'))
        elif request.form.get('options_save_js'):
            response.set_cookie('options_js', request.form.get('options_js'))
        elif request.form.get('options_save_misc'):
            response.set_cookie('theme', request.form.get('options_theme'))

            if request.form.get('options_max_height'):
                response.set_cookie('options_max_height', '1')
            else:
                response.set_cookie('options_max_height', '0')

            if request.form.get('options_post_horizontal'):
                response.set_cookie('options_post_horizontal', '1')
            else:
                response.set_cookie('options_post_horizontal', '0')

            if request.form.get('options_hide_authors'):
                response.set_cookie('options_hide_authors', '1')
            else:
                response.set_cookie('options_hide_authors', '0')
        elif request.form.get('options_export'):
            from io import StringIO
            from flask import send_file
            user_options = {
                "options_css": request.cookies.get('options_css'),
                "options_js": request.cookies.get('options_js'),
                "options_theme": request.cookies.get('theme'),
                "options_max_height": request.cookies.get('options_max_height'),
                "options_post_horizontal": request.cookies.get('options_post_horizontal'),
                "options_hide_authors": request.cookies.get('options_hide_authors')
            }
            buffer = BytesIO()
            buffer.write(json.dumps(user_options).encode())
            buffer.seek(0)
            return send_file(
                buffer,
                download_name='bitchan_options_{}.json'.format(
                    datetime.datetime.now().strftime('%Y%m%d_%H%M%S')),
                as_attachment=True)
        elif request.form.get('options_import'):
            save_path = '/tmp/options_{}'.format(
                get_random_alphanumeric_string(10, with_spaces=False, with_punctuation=False))
            try:
                delete_file(save_path)
                f = request.files['options_import_file']
                f.save(save_path)
                with open(save_path) as f:
                    file_cont = json.loads(f.read())
                    response.set_cookie('options_css', file_cont['options_css'])
                    response.set_cookie('options_js', file_cont['options_js'])
                    response.set_cookie('theme', file_cont['options_theme'])
                    if file_cont['options_max_height']:
                        response.set_cookie('options_max_height', '1')
                    else:
                        response.set_cookie('options_max_height', '0')

                    if file_cont['options_post_horizontal']:
                        response.set_cookie('options_post_horizontal', '1')
                    else:
                        response.set_cookie('options_post_horizontal', '0')

                    if file_cont['options_hide_authors']:
                        response.set_cookie('options_hide_authors', '1')
                    else:
                        response.set_cookie('options_hide_authors', '0')
            except:
                logger.exception("Importing options")
            finally:
                delete_file(save_path)
        elif request.form.get('options_reset'):
            response.set_cookie('options_css', "")
            response.set_cookie('options_js', "")
            response.set_cookie('theme', "")
            response.set_cookie('options_max_height', '0')
            response.set_cookie('options_post_horizontal', '0')
            response.set_cookie('options_hide_authors', '0')

    return response


@blueprint.route('/overboard/<address>/<int:current_page>')
@count_views
@rate_limit
def overboard(address, current_page):
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    chan = Chan.query.filter(Chan.address == address).first()
    global_admin, _ = allowed_access("is_global_admin")

    if address != '0' and (not chan or (not global_admin and chan.restricted)):
        return render_template("pages/404-board.html",
                               board_address=address)

    settings = GlobalSettings.query.first()
    status_msg = {"status_message": []}
    now = time.time()

    thread_order_desc = Threads.timestamp_sent.desc()
    if settings.post_timestamp == 'received':
        thread_order_desc = Threads.timestamp_received.desc()

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
            overboard_info["unlisted"] = chan.unlisted
            overboard_info["restricted"] = chan.restricted
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
                Threads.chan_id == chan.id).order_by(thread_order_desc)
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
                        post_order_desc = Messages.timestamp_sent.desc()
                        if settings.post_timestamp == 'received':
                            post_order_desc = Messages.timestamp_received.desc()

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
                                Messages.is_op.is_(False))).order_by(post_order_desc).first()
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

        if global_admin:
            threads = Threads.query.join(Chan).order_by(thread_order_desc)
        else:
            threads = Threads.query.join(Chan).filter(and_(
                Chan.unlisted.is_(False),
                Chan.restricted.is_(False))).order_by(thread_order_desc)
        overboard_info["thread_count"] = threads.count()

        for i, each_thread in enumerate(threads.all()):
            if i > post_end:
                break
            if post_start <= i:
                post_order_desc = Messages.timestamp_sent.desc()
                if settings.post_timestamp == 'received':
                    post_order_desc = Messages.timestamp_received.desc()

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
                        Messages.is_op.is_(False))).order_by(post_order_desc).first()
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


@blueprint.route('/unlisted')
@count_views
@rate_limit
def unlisted():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    status_msg = {"status_message": []}

    return render_template("pages/unlisted.html",
                           status_msg=status_msg)


@blueprint.route('/restricted')
@count_views
@rate_limit
def restricted():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    status_msg = {"status_message": []}

    return render_template("pages/restricted.html",
                           status_msg=status_msg)


def delete_posts_threads(message_ids, user_from=None):
    thread_hashes = []
    board_addresses = []

    # Delete threads first
    for each_msg_id in message_ids:
        msg = Messages.query.filter(
            Messages.message_id == each_msg_id).first()
        if msg and msg.is_op and msg.thread:
            if msg.thread.chan.address not in board_addresses:
                board_addresses.append(msg.thread.chan.address)

            add_mod_log_entry(
                'Locally deleted thread "{}"'.format(msg.thread.subject),
                user_from=user_from,
                board_address=msg.thread.chan.address,
                thread_hash=msg.thread.thread_hash)

            list_delete_message_ids = []
            for message in msg.thread.messages:
                list_delete_message_ids.append(message.message_id)

            # First, delete messages from database
            for each_id in list_delete_message_ids:
                delete_post(each_id)

            # Next, delete thread from DB
            delete_thread(msg.thread.thread_hash)

    # Delete remaining posts
    for each_msg_id in message_ids:
        msg = Messages.query.filter(
            Messages.message_id == each_msg_id).first()
        if msg:
            if msg.thread and msg.thread.thread_hash not in thread_hashes:
                thread_hashes.append(msg.thread.thread_hash)
            if msg.thread and msg.thread.chan and msg.thread.chan.address not in board_addresses:
                board_addresses.append(msg.thread.chan.address)

            if msg.thread and msg.thread.chan:
                add_mod_log_entry(
                    'Locally deleted post from "{}"'.format(msg.thread.subject),
                    message_id=each_msg_id,
                    user_from=user_from,
                    board_address=msg.thread.chan.address,
                    thread_hash=msg.thread.thread_hash)
            delete_post(each_msg_id)


@blueprint.route('/recent/<address>/<int:current_page>', methods=('GET', 'POST'))
@count_views
@rate_limit
def recent_posts(address, current_page):
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    chan = Chan.query.filter(Chan.address == address).first()
    global_admin, _ = allowed_access("is_global_admin")

    if address != '0' and (not chan or (not global_admin and chan.restricted)):
        return render_template("pages/404-board.html",
                               board_address=address)

    form_recent = forms_board.Recent()

    settings = GlobalSettings.query.first()
    status_msg = {"status_message": []}

    msg_count = 0

    recent_info = {
        "single_board": False
    }

    if request.method == 'POST':
        global_admin, allow_msg = allowed_access("is_global_admin")
        janitor, allow_msg = allowed_access("is_janitor")
        if not global_admin and not janitor:
            return allow_msg

        if form_recent.start_download.data:
            if not global_admin:
                status_msg['status_message'].append("Only admins can start downloads.")
            else:
                message = Messages.query.filter(Messages.message_id == form_recent.message_id.data).first()
                if message:
                    can_download, allow_msg = allowed_access("can_download")
                    board_list_admin, allow_msg = allowed_access(
                        "is_board_list_admin", board_address=message.thread.chan.address)
                    if not can_download and not board_list_admin:
                        return allow_msg

                    if settings.maintenance_mode:
                        status_msg['status_title'] = "Error"
                        status_msg['status_message'].append(
                            "Cannot initiate attachment download while Maintenance Mode is enabled.")
                    else:
                        daemon_com.set_start_download(form_recent.message_id.data)
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append(
                            "File download initialized in the background. Give it time to download.")

        if form_recent.bulk_delete_threads.data:
            try:
                delete_bulk_message_ids = []
                for each_input in request.form:
                    if each_input.startswith("selectbulk_"):
                        delete_bulk_message_ids.append(each_input.split("_")[1])

                try:
                    user_from = None
                    if janitor:
                        user_from = get_logged_in_user_name()

                    delete_posts_threads(delete_bulk_message_ids, user_from=user_from)
                    status_msg['status_message'].append("Deleted posts/threads")
                    status_msg['status_title'] = "Success"
                except Exception as err:
                    logger.error("Exception while deleting posts/threads: {}".format(err))
            except:
                logger.exception("deleting posts/threads")

    post_start = (current_page - 1) * settings.results_per_page_recent
    post_end = (current_page * settings.results_per_page_recent) - 1
    recent_results = []

    post_order_desc = Messages.timestamp_sent.desc()
    if settings.post_timestamp == 'received':
        post_order_desc = Messages.timestamp_received.desc()

    if address != "0":
        chan = Chan.query.filter(
            Chan.address == address).first()
        if not chan:
            return render_template("pages/404-board.html",
                                   board_address=address)

        recent_info["single_board"] = True
        recent_info["board_label"] = chan.label
        recent_info["board_description"] = chan.description
        recent_info["board_address"] = chan.address

        messages = Messages.query.join(Threads).join(Chan).filter(
            Chan.address == address).order_by(post_order_desc)
        msg_count = messages.count()

        msg_total = 0
        for result in messages.all():
            if msg_total > post_end:
                break
            if post_start <= msg_total:
                recent_results.append(result)
            msg_total += 1
    else:
        if global_admin:
            messages = Messages.query.order_by(post_order_desc)
        else:
            messages = Messages.query.join(Threads).join(Chan).filter(and_(
                Chan.unlisted.is_(False),
                Chan.restricted.is_(False))).order_by(post_order_desc)
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
@count_views
@rate_limit
def search(search_b64, current_page):
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    settings = GlobalSettings.query.first()

    global_admin, allow_msg = allowed_access("is_global_admin")
    if settings.kiosk_only_admin_access_search and not global_admin:
        return allow_msg

    status_msg = {"status_message": []}
    search_string_b64 = search_b64

    if search_b64 == '0':
        search_string = ""
    else:
        search_string = base64.b64decode(search_b64.encode()).decode()

    form_search = forms_board.Search()

    if request.method == 'POST':
        if form_search.submit.data:
            current_page = 1

            if form_search.search.data and len(form_search.search.data) < 3:
                status_msg['status_message'].append(
                    "At search string of at least 3 characters is required.")

            if not status_msg['status_message']:
                search_string = form_search.search.data
                search_string_b64 = base64.urlsafe_b64encode(search_string.encode()).decode()
                if not search_string_b64:
                    search_string_b64 = "0"
                status_msg['status_title'] = "Success_Silent"

        elif form_search.bulk_delete.data:
            global_admin, allow_msg = allowed_access("is_global_admin")
            janitor, allow_msg = allowed_access("is_janitor")
            if not global_admin and not janitor:
                return allow_msg

            try:
                delete_bulk_message_ids = []
                for each_input in request.form:
                    if each_input.startswith("selectbulk_"):
                        delete_bulk_message_ids.append(each_input.split("_")[1])

                try:
                    user_from = None
                    if janitor:
                        user_from = get_logged_in_user_name()

                    delete_posts_threads(delete_bulk_message_ids, user_from=user_from)
                    status_msg['status_message'].append("Deleted posts/threads")
                    status_msg['status_title'] = "Success"
                except Exception as err:
                    logger.error("Exception while deleting posts/threads: {}".format(err))
            except:
                logger.exception("deleting posts/threads")

            return redirect(url_for("routes_main.search",
                                    search_b64=search_b64,
                                    current_page=current_page))

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    arg_filter_hidden = request.args.get('fh', default=False, type=bool)
    arg_filter_op = request.args.get('fo', default=False, type=bool)
    arg_filter_steg = request.args.get('fs', default=False, type=bool)
    arg_search_type = request.args.get('st', default="posts", type=str)
    arg_search_boards = request.args.get('sb', default="all", type=str)
    arg_search_from = request.args.get('sf', default=False, type=str)

    search_type = arg_search_type
    search_boards = arg_search_boards

    if form_search.search_type.data:
        search_type = form_search.search_type.data
    if form_search.search_boards.data:
        search_boards = form_search.search_boards.data

    filter_hidden = False
    filter_op = False
    filter_steg = False
    result_count = 0
    search_from = None
    search_results = []
    thread_results = []

    global_admin, allow_msg = allowed_access("is_global_admin")

    search_threads = Threads.query.join(Chan).join(Messages)
    search_msgs = Messages.query.join(Threads).join(Chan)

    if search_boards != 'all':
        if search_type == "posts":
            search_msgs = search_msgs.filter(Chan.address == search_boards)
        elif search_type == "threads":
            search_threads = search_threads.filter(Chan.address == search_boards)

    if search_string and len(search_string) > 2:
        if search_type == "posts":
            search_msgs = search_msgs.filter(or_(
                Messages.message.contains(search_string),
                Messages.message_id.contains(search_string.lower()),
                and_(Messages.subject.contains(search_string),
                     Messages.is_op.is_(True))
            ))
        elif search_type == "threads":
            search_threads = search_threads.filter(and_(
                Messages.is_op.is_(True),
                or_(Messages.message.contains(search_string),
                    Messages.message_id.contains(search_string.lower()),
                    Messages.subject.contains(search_string))))

    #
    # Search from address
    #
    if arg_search_from:
        search_from = arg_search_from
        search_msgs = search_msgs.filter(Messages.address_from == arg_search_from)

    #
    # Hidden
    #
    if form_search.filter_hidden.data or arg_filter_hidden:
        if global_admin:
            filter_hidden = True
            if search_type == "posts":
                search_msgs = search_msgs.filter(Messages.hide.is_(True))
            elif search_type == "threads":
                search_threads = search_threads.filter(Threads.hide.is_(True))
        else:
            status_msg['status_message'].append(allow_msg)
            status_msg['status_title'] = "Error"

    if not filter_hidden:
        if search_type == "posts":
            search_msgs = search_msgs.filter(Messages.hide.is_(False))
        elif search_type == "threads":
            search_threads = search_threads.filter(Threads.hide.is_(False))

    #
    # STEG
    #
    if form_search.filter_steg.data or arg_filter_steg:
        if global_admin:
            filter_steg = True
            if search_type == "posts":
                search_msgs = search_msgs.filter(Messages.message_steg != "{}")
        else:
            status_msg['status_message'].append(allow_msg)
            status_msg['status_title'] = "Error"

    if not filter_steg:
        if search_type == "posts":
            search_msgs = search_msgs.filter(Messages.message_steg == "{}")

    #
    # OP
    #
    if form_search.filter_op.data or arg_filter_op and search_type == "posts":
        filter_op = True
        search_msgs = search_msgs.filter(Messages.is_op.is_(True))

    if search_type == "posts":
        post_order_desc = Messages.timestamp_sent.desc()
        if settings.post_timestamp == 'received':
            post_order_desc = Messages.timestamp_received.desc()

        if global_admin:
            search_msgs = search_msgs.order_by(post_order_desc)
        else:
            search_msgs = search_msgs.filter(and_(
                Chan.unlisted.is_(False),
                Chan.restricted.is_(False))).order_by(post_order_desc)
        result_count = search_msgs.count()

    elif search_type == "threads":
        thread_order_desc = Threads.timestamp_sent.desc()
        if settings.post_timestamp == 'received':
            thread_order_desc = Threads.timestamp_received.desc()

        if global_admin:
            search_threads = search_threads.order_by(thread_order_desc)
        else:
            search_threads = search_threads.filter(and_(
                Chan.unlisted.is_(False),
                Chan.restricted.is_(False))).order_by(thread_order_desc)
        result_count = search_threads.count()

    search_start = (current_page - 1) * settings.results_per_page_search
    search_end = (current_page * settings.results_per_page_search) - 1

    if search_type == "posts":
        for i, result in enumerate(search_msgs.all()):
            if i > search_end:
                break
            if search_start <= i:
                search_results.append(result)

    if search_type == "threads":
        for i, result in enumerate(search_threads.all()):
            if i > search_end:
                break
            if search_start <= i:
                thread_results.append(result)

    return render_template("pages/search.html",
                           current_page=current_page,
                           filter_hidden=filter_hidden,
                           filter_op=filter_op,
                           filter_steg=filter_steg,
                           now=time.time(),
                           result_count=result_count,
                           search_boards=search_boards,
                           search_from=search_from,
                           search_results=search_results,
                           search_string=search_string,
                           search_string_b64=search_string_b64,
                           search_type=search_type,
                           status_msg=status_msg,
                           thread_results=thread_results)


@blueprint.route('/mod_log/<address>/<int:current_page>', methods=('GET', 'POST'))
@count_views
@rate_limit
def mod_log(address, current_page):
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    settings = GlobalSettings.query.first()

    global_admin, allow_msg = allowed_access("is_global_admin")
    if settings.kiosk_only_admin_access_mod_log and not global_admin:
        return allow_msg

    form_modlog = forms_board.ModLog()

    status_msg = {"status_message": []}

    if request.method == 'POST':
        if not global_admin:
            return allow_msg

        if form_modlog.bulk_delete_mod_log.data:
            try:
                delete_bulk_mod_log_ids = []
                for each_input in request.form:
                    if each_input.startswith("selectbulk_"):
                        delete_bulk_mod_log_ids.append(each_input.split("_")[1])

                if not delete_bulk_mod_log_ids:
                    status_msg['status_title'] = "Error"
                    status_msg['status_message'].append("Must select at least one entry to delete")

                if not status_msg['status_message']:
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
            except:
                logger.exception("deleting Mod Log entries")

        elif form_modlog.bulk_restore_post_mod_log.data or form_modlog.bulk_restore_thread_mod_log.data:
            try:
                delete_bulk_mod_log_ids = []
                for each_input in request.form:
                    if each_input.startswith("selectbulk_"):
                        delete_bulk_mod_log_ids.append(each_input.split("_")[1])

                if not delete_bulk_mod_log_ids:
                    status_msg['status_title'] = "Error"
                    status_msg['status_message'].append("Must select at least one entry to delete")

                if not status_msg['status_message']:
                    try:
                        for each_id in delete_bulk_mod_log_ids:
                            mod_log_entry = ModLog.query.filter(ModLog.id == each_id).first()
                            if mod_log_entry:
                                log_description = ""
                                if form_modlog.bulk_restore_thread_mod_log.data and mod_log_entry.thread_hash:
                                    # Restore thread
                                    thread = Threads.query.filter(
                                        Threads.thread_hash == mod_log_entry.thread_hash).first()
                                    if thread:
                                        log_description = 'Restore thread "{}"'.format(thread.subject)
                                        restore_thread(mod_log_entry.thread_hash)
                                elif form_modlog.bulk_restore_post_mod_log.data and mod_log_entry.message_id:
                                    # Restore post
                                    message = Messages.query.filter(
                                        Messages.message_id == mod_log_entry.message_id).first()
                                    if message:
                                        log_description = 'Restore post'
                                        restore_post(mod_log_entry.message_id)

                                user_from_tmp = get_logged_in_user_name()
                                user_from = user_from_tmp if user_from_tmp else None

                                if log_description:
                                    add_mod_log_entry(
                                        log_description,
                                        message_id=mod_log_entry.message_id,
                                        user_from=user_from,
                                        board_address=mod_log_entry.board_address,
                                        thread_hash=mod_log_entry.thread_hash)

                        status_msg['status_message'].append(
                            "Restored post/thread from Mod Log")
                        status_msg['status_title'] = "Success"
                    except Exception as err:
                        logger.error("Exception while restoring Mod Log entries: {}".format(err))
            except:
                logger.exception("restoring Mod Log entries")

    mod_log_msgs = ModLog.query

    if address != "0":
        mod_log_msgs = mod_log_msgs.filter(
            ModLog.board_address == address)

    arg_filter_remote_moderate = request.args.get('frm', default=False, type=bool)
    arg_filter_failed_attempts = request.args.get('ffa', default=False, type=bool)

    filter_remote_moderate = False
    filter_failed_attempts = False

    if (global_admin and
            (
                (form_modlog.filter.data and form_modlog.filter_remote_moderate.data) or
                arg_filter_remote_moderate
            )):
        filter_remote_moderate = True
        mod_log_msgs = mod_log_msgs.filter(ModLog.hidden.is_(True))
    else:
        mod_log_msgs = mod_log_msgs.filter(or_(
            ModLog.hidden.is_(True), ModLog.hidden.is_(False)))

    if (global_admin and
            (
                (form_modlog.filter.data and form_modlog.filter_failed_attempts.data) or
                arg_filter_failed_attempts
            )):
        filter_failed_attempts = True
        mod_log_msgs = mod_log_msgs.filter(ModLog.success.is_(False))
    else:
        mod_log_msgs = mod_log_msgs.filter(or_(
            ModLog.success.is_(True), ModLog.success.is_(False)))

    mod_log_msgs = mod_log_msgs.order_by(ModLog.timestamp.desc())

    mod_log_count = mod_log_msgs.count()

    post_start = (current_page - 1) * settings.results_per_page_mod_log
    post_end = (current_page * settings.results_per_page_mod_log) - 1
    mod_log_results = []
    for i, result in enumerate(mod_log_msgs.all()):
        if i > post_end:
            break
        if post_start <= i:
            mod_log_results.append(result)

    return render_template("pages/mod_log.html",
                           address=address,
                           filter_remote_moderate=filter_remote_moderate,
                           filter_failed_attempts=filter_failed_attempts,
                           now=time.time(),
                           mod_log_page=current_page,
                           mod_log_count=mod_log_count,
                           mod_log=mod_log_results,
                           status_msg=status_msg)


@blueprint.route('/help')
@count_views
@rate_limit
def help_docs():
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    return render_template("pages/help.html")


@blueprint.route('/configure', methods=('GET', 'POST'))
@count_views
def configure():
    global_admin, allow_msg = allowed_access("is_global_admin")
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
                        12, with_spaces=False, with_punctuation=False), flag_extension)

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
            timestamp_change = False
            successes = []

            settings = GlobalSettings.query.first()
            if form_settings.theme.data:
                settings.theme = form_settings.theme.data

            if settings.maintenance_mode is False and form_settings.maintenance_mode.data is True:
                logger.info("Enabling maintenance mode. Stopping Bitmessage")
                if config.DOCKER:
                    subprocess.Popen('docker stop -t 15 bitchan_bitmessage 2>&1', shell=True)
                else:
                    subprocess.Popen('service bitchan_bitmessage stop', shell=True)

            if settings.maintenance_mode is True and form_settings.maintenance_mode.data is False:
                logger.info("Disabling maintenance mode. Starting Bitmessage")
                if config.DOCKER:
                    subprocess.Popen('docker start bitchan_bitmessage 2>&1', shell=True)
                else:
                    subprocess.Popen('service bitchan_bitmessage start', shell=True)
                time.sleep(3)  # Allow bitmessage to start

            settings.maintenance_mode = form_settings.maintenance_mode.data
            settings.max_download_size = form_settings.max_download_size.data
            settings.max_extract_size = form_settings.max_extract_size.data
            settings.always_allow_my_i2p_bittorrent_attachments = form_settings.always_allow_my_i2p_bittorrent_attachments.data
            settings.allow_net_file_size_check = form_settings.allow_net_file_size_check.data
            settings.allow_net_book_quote = form_settings.allow_net_book_quote.data
            settings.never_auto_download_unencrypted = form_settings.never_auto_download_unencrypted.data
            settings.allow_unencrypted_encryption_option = form_settings.allow_unencrypted_encryption_option.data
            settings.auto_dl_from_unknown_upload_sites = form_settings.auto_dl_from_unknown_upload_sites.data
            settings.delete_sent_identity_msgs = form_settings.delete_sent_identity_msgs.data
            settings.debug_posts = form_settings.debug_posts.data
            settings.post_timestamp = form_settings.post_timestamp.data
            if settings.post_timestamp_timezone != form_settings.post_timestamp_timezone.data:
                timestamp_change = True
                settings.post_timestamp_timezone = form_settings.post_timestamp_timezone.data
            if settings.post_timestamp_hour != form_settings.post_timestamp_hour.data:
                timestamp_change = True
                settings.post_timestamp_hour = form_settings.post_timestamp_hour.data
            settings.title_text = form_settings.title_text.data
            settings.home_page_msg = form_settings.home_page_msg.data
            settings.html_head = form_settings.html_head.data
            settings.html_body = form_settings.html_body.data
            settings.results_per_page_board = form_settings.results_per_page_board.data
            settings.results_per_page_recent = form_settings.results_per_page_recent.data
            settings.results_per_page_search = form_settings.results_per_page_search.data
            settings.results_per_page_overboard = form_settings.results_per_page_overboard.data
            settings.results_per_page_catalog = form_settings.results_per_page_catalog.data
            settings.results_per_page_mod_log = form_settings.results_per_page_mod_log.data

            # Bitmessage
            update_bm_settings = False
            update_bm_onion = False
            if settings.bm_connections_in_out != form_settings.bm_connections_in_out.data:
                settings.bm_connections_in_out = form_settings.bm_connections_in_out.data
                update_bm_settings = True
            if bool(settings.bitmessage_onion_services_only) != bool(form_settings.bitmessage_onion_services_only.data):
                settings.bitmessage_onion_services_only = form_settings.bitmessage_onion_services_only.data
                update_bm_onion = True

            # Security
            settings.enable_captcha = form_settings.enable_captcha.data
            settings.enable_verification = form_settings.enable_verification.data
            settings.hide_version = form_settings.hide_version.data
            settings.enable_page_rate_limit = form_settings.enable_page_rate_limit.data
            settings.max_requests_per_period = form_settings.max_requests_per_period.data
            settings.rate_limit_period_seconds = form_settings.rate_limit_period_seconds.data
            settings.remote_delete_action = form_settings.remote_delete_action.data
            settings.disable_downloading_upload_site = form_settings.disable_downloading_upload_site.data
            settings.disable_downloading_i2p_torrent = form_settings.disable_downloading_i2p_torrent.data
            if (form_settings.ttl_seed_i2p_torrent_op_days.data <= 0 or
                    form_settings.ttl_seed_i2p_torrent_reply_days.data <= 0):
                status_msg['status_message'].append("I2P seeding time cannot be less than 0 days.")
            settings.ttl_seed_i2p_torrent_op_days = form_settings.ttl_seed_i2p_torrent_op_days.data
            settings.ttl_seed_i2p_torrent_reply_days = form_settings.ttl_seed_i2p_torrent_reply_days.data

            # RSS
            settings.rss_enable = form_settings.rss_enable.data
            settings.rss_enable_i2p = form_settings.rss_enable_i2p.data
            settings.rss_url = form_settings.rss_url.data
            settings.rss_url_i2p = form_settings.rss_url_i2p.data
            settings.rss_number_posts = form_settings.rss_number_posts.data
            settings.rss_char_length = form_settings.rss_char_length.data
            settings.rss_use_html_posts = form_settings.rss_use_html_posts.data
            settings.rss_rate_limit_number_requests = form_settings.rss_rate_limit_number_requests.data
            settings.rss_rate_limit_period_sec = form_settings.rss_rate_limit_period_sec.data

            # Kiosk mode
            if not settings.enable_kiosk_mode and form_settings.enable_kiosk_mode.data:
                # Enabling kiosk mode
                # Check if an admin user exists
                count_admins = Auth.query.filter(Auth.global_admin.is_(True)).count()
                if not count_admins:
                    status_msg['status_message'].append(
                        f"Cannot enable Kiosk Mode when no Kiosk Global Admins exist. "
                        f"If you do this, you will not be able to log in to the Kiosk. "
                        f"Go to the Kiosk User Management page and add a Global Admin user.")
            settings.enable_kiosk_mode = form_settings.enable_kiosk_mode.data
            settings.kiosk_login_to_view = form_settings.kiosk_login_to_view.data
            settings.kiosk_allow_posting = form_settings.kiosk_allow_posting.data
            settings.kiosk_allow_gpg = form_settings.kiosk_allow_gpg.data
            settings.kiosk_allow_pow = form_settings.kiosk_allow_pow.data
            settings.kiosk_disable_i2p_torrent_attach = form_settings.kiosk_disable_i2p_torrent_attach.data
            settings.kiosk_disable_torrent_file_download = form_settings.kiosk_disable_torrent_file_download.data
            settings.kiosk_disable_bm_attach = form_settings.kiosk_disable_bm_attach.data
            settings.kiosk_allow_download = form_settings.kiosk_allow_download.data
            settings.kiosk_post_rate_limit = form_settings.kiosk_post_rate_limit.data
            settings.kiosk_attempts_login = form_settings.kiosk_attempts_login.data
            settings.kiosk_ban_login_sec = form_settings.kiosk_ban_login_sec.data
            settings.kiosk_only_admin_access_mod_log = form_settings.kiosk_only_admin_access_mod_log.data
            settings.kiosk_only_admin_access_search = form_settings.kiosk_only_admin_access_search.data

            try:
                list_i2p_trackers = form_settings.i2p_trackers.data.replace(" ", "").split("\n")

                # Ensure all trackers have i2p TLD
                non_i2p_urls = check_tld_i2p(list_i2p_trackers)
                if non_i2p_urls:
                    status_msg['status_message'].append(
                        "Improper I2P Tracker format. Must be I2P URLs separated by commas.")
                else:
                    settings.i2p_trackers = json.dumps(list_i2p_trackers)
            except:
                status_msg['status_message'].append("Improper I2P Tracker format. Must be I2P URLs, each on a new line.")

            if (form_settings.kiosk_max_post_size_bytes.data < 0 or
                    form_settings.kiosk_max_post_size_bytes.data > config.BM_PAYLOAD_MAX_SIZE):
                status_msg['status_message'].append(
                    f"Max post size (bytes) must be >= 0 and <= {config.BM_PAYLOAD_MAX_SIZE}.")
            else:
                settings.kiosk_max_post_size_bytes = form_settings.kiosk_max_post_size_bytes.data

            settings.kiosk_ttl_option = form_settings.kiosk_ttl_option.data
            if form_settings.kiosk_ttl_seconds.data < 3600 or form_settings.kiosk_ttl_seconds.data > 2419200:
                status_msg['status_message'].append(
                    "TTL must be >= 3600 seconds (1 hour) and <= 2419200 seconds (28 days).")
            else:
                settings.kiosk_ttl_seconds = form_settings.kiosk_ttl_seconds.data

            if (form_settings.chan_update_display_number.data and
                    form_settings.chan_update_display_number.data >= 0):
                settings.chan_update_display_number = form_settings.chan_update_display_number.data

            if not status_msg['status_message']:
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Settings saved without errors.")
            else:
                status_msg['status_title'] = "Error"

            if status_msg['status_title'] == "Success":
                settings.save()
                if update_bm_settings:
                    change_bm_settings = Thread(
                        target=daemon_com.bm_change_connection_settings)
                    change_bm_settings.start()
                    successes.append(
                        f"Applying changed bitmessage connection settings. Give at least 60 seconds for the changes to take effect.")

                if update_bm_onion:
                    change_onion = Thread(
                        target=daemon_com.enable_onion_services_only,
                        args=(form_settings.bitmessage_onion_services_only.data,))
                    change_onion.start()
                    successes.append(
                        f"Applying changed bitmessage onion settings. Give at least 60 seconds for the changes to take effect.")

                for each_success in successes:
                    status_msg['status_message'].append(each_success)

            if timestamp_change:
                # Instructed to use different timestamp format, regenerate all HTML
                for board in Chan.query.all():
                    regenerate_card_popup_post_html(
                        all_posts_of_board_address=board.address)

            refresh_settings = Thread(target=daemon_com.refresh_settings)
            refresh_settings.start()

        elif form_settings.export_chans.data:
            def export_boards_lists(chans_):
                data = StringIO()
                w = csv.writer(data)

                w.writerow(('type', 'label', 'description', 'access', 'address', 'passphrase'))
                yield data.getvalue()
                data.seek(0)
                data.truncate(0)

                for each_chan_ in chans_:
                    w.writerow((
                        each_chan_.type,
                        each_chan_.label,
                        each_chan_.description,
                        each_chan_.access,
                        each_chan_.address,
                        each_chan_.passphrase
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
            def export_address_book(add_book):
                data = StringIO()
                w = csv.writer(data)

                w.writerow(('label', 'address'))
                yield data.getvalue()
                data.seek(0)
                data.truncate(0)

                for each_ab in add_book:
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
                        save_path = f"{config.TOR_HS_CUS}/{zip_filename}"
                        form_settings.tor_file.data.save(save_path)

                        logger.info("Extracting zip")
                        with zipfile.ZipFile(save_path, 'r') as zipObj:
                            zipObj.extractall(f"{config.TOR_HS_CUS}/")

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

        elif form_settings.get_new_bm_tor.data:
            daemon_com.regenerate_bitmessage_onion_address()
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(
                "Generating a new bitmessage onion address.")

        elif form_settings.save_chan_options.data:
            # Get submitted unlisted and restricted addresses
            chans_unlisted = []
            chans_restricted = []
            chans_hide_passphrase = []
            chans_read_only = []
            for each_input in request.form:
                if each_input.startswith("option_unlisted_"):
                    chans_unlisted.append(each_input.split("_")[2])
                if each_input.startswith("option_restricted_"):
                    chans_restricted.append(each_input.split("_")[2])
                if each_input.startswith("option_hide_passphrase_"):
                    chans_hide_passphrase.append(each_input.split("_")[3])
                if each_input.startswith("option_read_only_"):
                    chans_read_only.append(each_input.split("_")[3])

            chans = Chan.query.all()
            for each_chan in chans:
                # Change unlisted status
                unlisted_changed = False
                if each_chan.address in chans_unlisted:
                    if not each_chan.unlisted:
                        unlisted_changed = True
                    each_chan.unlisted = True
                else:
                    if each_chan.unlisted:
                        unlisted_changed = True
                    each_chan.unlisted = False
                if unlisted_changed:
                    each_chan.save()

                # Change restricted status
                restricted_changed = False
                if each_chan.address in chans_restricted:
                    if not each_chan.restricted:
                        restricted_changed = True
                    each_chan.restricted = True
                else:
                    if each_chan.restricted:
                        restricted_changed = True
                    each_chan.restricted = False
                if restricted_changed:
                    each_chan.save()

                # Change hide_passphrase status
                hide_passphrase_changed = False
                if each_chan.address in chans_hide_passphrase:
                    if not each_chan.hide_passphrase:
                        hide_passphrase_changed = True
                    each_chan.hide_passphrase = True
                else:
                    if each_chan.hide_passphrase:
                        hide_passphrase_changed = True
                    each_chan.hide_passphrase = False
                if hide_passphrase_changed:
                    each_chan.save()

                # Change read_only status
                read_only_changed = False
                if each_chan.address in chans_read_only:
                    if not each_chan.read_only:
                        read_only_changed = True
                    each_chan.read_only = True
                else:
                    if each_chan.read_only:
                        read_only_changed = True
                    each_chan.read_only = False
                if read_only_changed:
                    each_chan.save()

            status_msg['status_title'] = "Success"
            status_msg['status_message'].append("Set chan options.")

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_main.configure"))

    (tor_enabled_bm, tor_address_bm,
     tor_enabled_rand, tor_address_rand,
     tor_enabled_cus, tor_address_cus) = get_onion_info()

    settings = GlobalSettings.query.first()
    try:
        i2p_trackers = "\n".join(json.loads(settings.i2p_trackers))
    except:
        i2p_trackers = ""

    return render_template("pages/configure.html",
                           form_settings=form_settings,
                           i2p_trackers=i2p_trackers,
                           status_msg=status_msg,
                           tor_address_bm=tor_address_bm,
                           tor_enabled_bm=tor_enabled_bm,
                           tor_address_cus=tor_address_cus,
                           tor_enabled_cus=tor_enabled_cus,
                           tor_address_rand=tor_address_rand,
                           tor_enabled_rand=tor_enabled_rand,
                           upload_sites=UploadSites.query.all())


@blueprint.route('/upload_site/<action>/<upload_site_id>', methods=('GET', 'POST'))
def upload_site(action, upload_site_id):
    global_admin, allow_msg = allowed_access("is_global_admin")
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
                    upload_site.enabled = True
                    upload_site.domain = site_options["domain"]
                    upload_site.type = site_options["type"]
                    upload_site.subtype = site_options["subtype"]
                    upload_site.uri = site_options["uri"]
                    upload_site.download_prefix = site_options["download_prefix"]
                    upload_site.response = site_options["response"]
                    upload_site.json_key = site_options["json_key"]
                    upload_site.direct_dl_url = site_options["direct_dl_url"]
                    upload_site.extra_curl_options = site_options["extra_curl_options"]
                    upload_site.upload_word = site_options["upload_word"]
                    upload_site.form_name = site_options["form_name"]
                    upload_site.http_headers = site_options["http_headers"]
                    upload_site.proxy_type = site_options["proxy_type"]
                    upload_site.replace_download_domain = site_options["replace_download_domain"]
                    upload_site.save()
                else:
                    status_msg['status_msg'].append("Message not found")
            elif action == "add":
                new_site = UploadSites()
                new_site.enabled = form_upload_site.enabled.data
                new_site.domain = form_upload_site.domain.data
                new_site.type = form_upload_site.type.data
                new_site.subtype = form_upload_site.subtype.data
                new_site.uri = form_upload_site.uri.data
                new_site.download_prefix = form_upload_site.download_prefix.data
                new_site.response = form_upload_site.response.data
                new_site.json_key = form_upload_site.json_key.data
                new_site.direct_dl_url = form_upload_site.direct_dl_url.data
                new_site.extra_curl_options = form_upload_site.extra_curl_options.data
                new_site.upload_word = form_upload_site.upload_word.data
                new_site.form_name = form_upload_site.form_name.data
                new_site.http_headers = form_upload_site.http_headers.data
                new_site.proxy_type = form_upload_site.proxy_type.data
                new_site.replace_download_domain = form_upload_site.replace_download_domain.data
                new_site.save()

            status_msg['status_message'].append("Upload site added")
            status_msg['status_title'] = "Success"

        elif form_upload_site.save.data:
            upload_site = UploadSites.query.filter(UploadSites.id == int(upload_site_id)).first()
            if upload_site:
                if form_upload_site.enabled.data:
                    upload_site.enabled = form_upload_site.enabled.data
                else:
                    upload_site.enabled = None
                if form_upload_site.domain.data:
                    upload_site.domain = form_upload_site.domain.data
                else:
                    upload_site.domain = None
                if form_upload_site.type.data:
                    upload_site.type = form_upload_site.type.data
                else:
                    upload_site.type = None
                if form_upload_site.subtype.data:
                    upload_site.subtype = form_upload_site.subtype.data
                else:
                    upload_site.subtype = None
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
                if form_upload_site.json_key.data:
                    upload_site.json_key = form_upload_site.json_key.data
                else:
                    upload_site.json_key = None
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
                if form_upload_site.http_headers.data:
                    upload_site.http_headers = form_upload_site.http_headers.data
                else:
                    upload_site.http_headers = None
                if form_upload_site.proxy_type.data:
                    upload_site.proxy_type = form_upload_site.proxy_type.data
                else:
                    upload_site.proxy_type = None
                if form_upload_site.replace_download_domain.data:
                    upload_site.replace_download_domain = form_upload_site.replace_download_domain.data
                else:
                    upload_site.replace_download_domain = None
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


def generate_charts(past_minutes=(60 * 24)):
    boards = {}
    threads = {}
    verify_data = {}
    x_axis_ts = []
    y_wait = []
    y_test = []
    y_success = []
    ts_day_last = None
    last_epoch = None
    charts = {}
    data = OrderedDict()
    time_end = datetime.datetime.now()
    time_start = time_end - datetime.timedelta(minutes=past_minutes)

    if past_minutes > 1440:
        time_start = (time_start - datetime.timedelta(
            hours=time_start.hour, minutes=time_start.minute,
            seconds=time_start.second, microseconds=time_start.microsecond))
        epoch_round = int(time_start.strftime('%s'))
        endpoint_data = EndpointCount.query.filter(
            EndpointCount.timestamp_epoch > epoch_round).order_by(
            EndpointCount.timestamp_epoch.asc()).all()
    else:
        endpoint_data = EndpointCount.query.filter(
            EndpointCount.timestamp_epoch > time.time() - past_minutes * 60).order_by(
            EndpointCount.timestamp_epoch.asc()).all()

    for entry in endpoint_data:
        if entry.timestamp_epoch not in data:
            data[entry.timestamp_epoch] = {"thread": {}, "chan": {}, "endpoint": {}}
        if entry.thread_hash:
            if entry.thread_hash not in data[entry.timestamp_epoch]["thread"]:
                data[entry.timestamp_epoch]["thread"][entry.thread_hash] = {}
            if entry.new_posts:
                data[entry.timestamp_epoch]["thread"][entry.thread_hash]["new_posts"] = entry.new_posts
            if entry.rss:
                data[entry.timestamp_epoch]["thread"][entry.thread_hash]["rss"] = entry.rss
            if entry.requests:
                data[entry.timestamp_epoch]["thread"][entry.thread_hash]["requests"] = entry.requests
        if entry.chan_address:
            if entry.chan_address not in data[entry.timestamp_epoch]["chan"]:
                data[entry.timestamp_epoch]["chan"][entry.chan_address] = {}
            if entry.rss:
                data[entry.timestamp_epoch]["chan"][entry.chan_address]["rss"] = entry.rss
            if entry.requests:
                data[entry.timestamp_epoch]["chan"][entry.chan_address]["requests"] = entry.requests
        if entry.endpoint and not entry.thread_hash and not entry.chan_address:
            data[entry.timestamp_epoch]["endpoint"][entry.endpoint] = entry.requests

    #
    # Chart: Verifications
    #

    # Get first timestamp
    for ts in data:
        if last_epoch:
            break
        if "endpoint" in data[ts] and data[ts]["endpoint"]:
            for endpoint in data[ts]["endpoint"]:
                if endpoint == "verify_wait":
                    dt_start_last = datetime.date.fromtimestamp(ts)
                    ts_day_last = dt_start_last.timetuple().tm_yday
                    last_epoch = int(dt_start_last.strftime('%s'))
                    break

    for ts in data:
        if not last_epoch:
            break

        if "endpoint" in data[ts] and data[ts]["endpoint"]:
            for endpoint in data[ts]["endpoint"]:
                dt_last = datetime.date.fromtimestamp(ts)
                ts_day = dt_last.timetuple().tm_yday
                ts_epoch = int(dt_last.strftime('%s'))

                if endpoint == "verify_wait":
                    if past_minutes <= 1440:
                        if ts not in verify_data:
                            verify_data[ts] = {}
                        verify_data[ts]["verify_wait"] = data[ts]["endpoint"][endpoint]
                    else:
                        if last_epoch not in verify_data:
                            verify_data[last_epoch] = {}
                        if "verify_wait" not in verify_data[last_epoch]:
                            verify_data[last_epoch]["verify_wait"] = data[ts]["endpoint"][endpoint]
                        else:
                            verify_data[last_epoch]["verify_wait"] += data[ts]["endpoint"][endpoint]

                if endpoint == "verify_test":
                    if past_minutes <= 1440:
                        if ts not in verify_data:
                            verify_data[ts] = {}
                        verify_data[ts]["verify_test"] = data[ts]["endpoint"][endpoint]
                    else:
                        if last_epoch not in verify_data:
                            verify_data[last_epoch] = {}
                        if "verify_test" not in verify_data[last_epoch]:
                            verify_data[last_epoch]["verify_test"] = data[ts]["endpoint"][endpoint]
                        else:
                            verify_data[last_epoch]["verify_test"] += data[ts]["endpoint"][endpoint]

                if endpoint == "verify_success":
                    if past_minutes <= 1440:
                        if ts not in verify_data:
                            verify_data[ts] = {}
                        verify_data[ts]["verify_success"] = data[ts]["endpoint"][endpoint]
                    else:
                        if last_epoch not in verify_data:
                            verify_data[last_epoch] = {}
                        if "verify_success" not in verify_data[last_epoch]:
                            verify_data[last_epoch]["verify_success"] = data[ts]["endpoint"][endpoint]
                        else:
                            verify_data[last_epoch]["verify_success"] += data[ts]["endpoint"][endpoint]

                if ts_day != ts_day_last:
                    ts_day_last = ts_day
                    last_epoch = ts_epoch

    for ts in verify_data:
        if "verify_wait" in verify_data[ts] or "verify_test" in verify_data[ts] or "verify_success" in verify_data[ts]:
            if past_minutes <= 1440:
                x_axis_ts.append(datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M'))
            else:
                x_axis_ts.append(datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d'))
            if "verify_wait" in verify_data[ts]:
                y_wait.append(verify_data[ts]["verify_wait"])
            else:
                y_wait.append(0)
            if "verify_test" in verify_data[ts]:
                y_test.append(verify_data[ts]["verify_test"])
            else:
                y_test.append(0)
            if "verify_success" in verify_data[ts]:
                y_success.append(verify_data[ts]["verify_success"])
            else:
                y_success.append(0)

    if x_axis_ts:
        x_axis = np.arange(len(x_axis_ts))

        plt.clf()
        figure = plt.gcf()
        figure.set_size_inches(7, 5)
        plt.rc('xtick', labelsize=6)
        plt.title('Verification\n{} - {}'.format(
            time_start.strftime('%Y-%m-%d %H:%M'),
            time_end.strftime('%Y-%m-%d %H:%M')))
        plt.ylabel('Requests')
        plt.bar(x_axis - 0.25, y_wait, 0.25, label='Wait')
        plt.bar(x_axis, y_test, 0.25, label='Test')
        plt.bar(x_axis + 0.25, y_success, 0.25, label='Success')
        plt.xticks(x_axis, x_axis_ts, rotation=90)
        plt.tight_layout()
        plt.legend()
        figfile = BytesIO()
        plt.savefig(figfile, dpi=125, format='png')
        figfile.seek(0)

        charts["verify"] = base64.b64encode(figfile.getvalue()).decode()

    for ts in data:
        if "chan" in data[ts] and data[ts]["chan"]:
            for address, categories in data[ts]["chan"].items():
                for category, value in categories.items():
                    if address not in boards:
                        boards[address] = {'requests': 0, 'rss': 0, 'total': 0}

                    if category == "rss":
                        boards[address]['rss'] += value
                    elif category == "requests":
                        boards[address]['requests'] += value
                    boards[address]['total'] += value


    # Combine thread hashes and sum counts
    for ts in data:
        if "thread" in data[ts] and data[ts]["thread"]:
            for thread_hash, categories in data[ts]["thread"].items():
                for category, value in categories.items():
                    # Ensure short and non-short thread hash are condensed to the short hash
                    thread = Threads.query.filter(
                        or_(Threads.thread_hash == thread_hash,
                            Threads.thread_hash_short == thread_hash)).first()
                    if thread:
                        save_hash = thread.thread_hash_short
                    else:
                        save_hash = thread_hash

                    if save_hash not in threads:
                        threads[save_hash] = {'requests': 0, 'requests_update': 0, 'rss': 0, 'total': 0}

                    if category == "rss":
                        threads[save_hash]['rss'] += value
                    elif category == "new_posts":
                        threads[save_hash]['requests_update'] += value
                    elif category == "requests":
                        threads[save_hash]['requests'] += value
                    threads[save_hash]['total'] += value

    threads_sorted_keys = sorted(threads, key=lambda x: (threads[x]['total']), reverse=True)
    threads_sorted = {}
    for each_key in threads_sorted_keys:
        threads_sorted[each_key] = threads[each_key]

    boards_sorted_keys = sorted(boards, key=lambda x: (boards[x]['total']), reverse=True)
    boards_sorted = {}
    for each_key in boards_sorted_keys:
        boards_sorted[each_key] = boards[each_key]

    dict_stats = {
        'boards': boards_sorted,
        'threads': threads_sorted,
    }

    return charts, dict_stats


@blueprint.route('/stats', methods=('GET', 'POST'))
@count_views
def stats():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    status_msg = session.get('status_msg', {"status_message": []})

    count_posts = Messages.query.count()
    count_threads = Threads.query.count()
    attachment_size = human_readable_size(get_directory_size(config.FILE_DIRECTORY))

    try:
        past_min = request.args.get('past_min', default=(60 * 24), type=int)
        if past_min < 0:
            past_min = (60 * 24)
    except:
        past_min = (60 * 24)

    try:
        view_counter = daemon_com.get_view_counter()
    except:
        view_counter = {}

    charts, dict_stats = generate_charts(past_min)

    return render_template("pages/stats.html",
                           attachment_size=attachment_size,
                           count_posts=count_posts,
                           count_threads=count_threads,
                           generated_charts=charts,
                           dict_stats=dict_stats,
                           past_min=past_min,
                           status_msg=status_msg,
                           table_endpoint_count=EndpointCount,
                           view_counter=view_counter)


@blueprint.route('/upload_progress/<upload_id>', methods=('GET', 'POST'))
@count_views
def upload_progress(upload_id):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    upload_entry = UploadProgress.query.filter(
        UploadProgress.upload_id == upload_id).first()

    status_msg = session.get('status_msg', {"status_message": []})

    return render_template("pages/upload_progress.html",
                           status_msg=status_msg,
                           upload_entry=upload_entry,
                           upload_id=upload_id)


@blueprint.route('/status', methods=('GET', 'POST'))
@count_views
def status():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    status_msg = session.get('status_msg', {"status_message": []})
    bm_status = {}
    bm_connections = {}
    tor_status = {"Circuit Established": False}
    form_status = forms_settings.Status()
    logging.getLogger("stem").setLevel(logging.WARNING)

    (tor_enabled_bm, tor_address_bm,
     tor_enabled_rand, tor_address_rand,
     tor_enabled_cus, tor_address_cus) = get_onion_info()

    try:
        bm_messages_size = human_readable_size(os.path.getsize(config.BM_MESSAGES_DAT))
    except:
        bm_messages_size = "ERROR"

    try:
        bm_knownnodes_size = human_readable_size(os.path.getsize(config.BM_KNOWNNODES_DAT))
    except:
        bm_knownnodes_size = "ERROR"

    try:
        bm_keys_size = human_readable_size(os.path.getsize(config.BM_KEYS_DAT))
    except:
        bm_keys_size = "ERROR"

    try:
        df = subprocess.check_output(
            "/bin/df -h", shell=True, text=True).replace("\n", "<br/>")
    except:
        df = None

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
            logger.exception("Error: {}".format(err))
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API)

    try:
        bm_sync_complete = daemon_com.bm_sync_complete()
    except Exception as err:
        bm_sync_complete = f"Error: {err}"

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
        try:
            bm_connections = api.listConnections()
        except Exception as err:
            logger.exception("Error: {}".format(err))
        finally:
            time.sleep(config.API_PAUSE)
            lf.lock_release(config.LOCKFILE_API)

    try:
        if config.DOCKER:
            tor_version = subprocess.check_output(
                'docker exec -i bitchan_tor tor --version --quiet', shell=True, text=True)
            tor_modules = subprocess.check_output(
                'docker exec -i bitchan_tor tor --list-modules', shell=True, text=True)
        else:
            tor_version = subprocess.check_output(
                'tor --version --quiet', shell=True, text=True)
            tor_modules = subprocess.check_output(
                'tor --list-modules', shell=True, text=True)
    except:
        logger.exception("getting tor version")
        tor_version = "Error getting tor version"
        tor_modules = "Error getting tor modules"

    try:
        if config.DOCKER:
            i2pd_version = subprocess.check_output(
                'docker exec -i bitchan_i2p i2pd --version', shell=True, text=True)
        else:
            i2pd_version = subprocess.check_output(
                'i2pd --version', shell=True, text=True)
    except:
        logger.exception("getting i2pd version")
        i2pd_version = "Error getting i2pd version"

    try:
        if config.DOCKER:
            qbittorrent_version = subprocess.check_output(
                'docker exec -i bitchan_qbittorrent qbittorrent-nox --version', shell=True, text=True)
        else:
            qbittorrent_version = subprocess.check_output(
                'i2pd --version', shell=True, text=True)
    except:
        logger.exception("getting qbittorrent version")
        qbittorrent_version = "Error getting qbittorrent version"

    attachment_size = None
    try:
        if config.DOCKER:
            attachment_size = subprocess.check_output(
                f'docker exec -i bitchan_flask du {config.FILE_DIRECTORY} --max-depth=0', shell=True, text=True)
        else:
            attachment_size = subprocess.check_output(
                f'du {config.FILE_DIRECTORY} --max-depth=0', shell=True, text=True)
        attachment_size = int(attachment_size.split("\t")[0]) * 1000
    except:
        logger.exception(f"Getting size of attachments: {attachment_size}")
        attachment_size = "Error getting size of attachments"

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

    bc_env = {}
    try:
        import re
        bc_env['version_python'] = sys.version
    except:
        logger.exception("BitChan environment information")

    db_version = Alembic.query.first().version_num

    return render_template("pages/status.html",
                           attachment_size=attachment_size,
                           bc_env=bc_env,
                           bm_connections=bm_connections,
                           bm_knownnodes_size=bm_knownnodes_size,
                           bm_messages_size=bm_messages_size,
                           bm_status=bm_status,
                           bm_sync_complete=bm_sync_complete,
                           db_version=db_version,
                           df=df,
                           form_status=form_status,
                           i2pd_version=i2pd_version,
                           bm_keys_size=bm_keys_size,
                           qbittorrent_version=qbittorrent_version,
                           status_msg=status_msg,
                           tor_circuit_dict=tor_circuit_dict,
                           tor_address_bm=tor_address_bm,
                           tor_enabled_bm=tor_enabled_bm,
                           tor_address_cus=tor_address_cus,
                           tor_enabled_cus=tor_enabled_cus,
                           tor_address_rand=tor_address_rand,
                           tor_enabled_rand=tor_enabled_rand,
                           tor_modules=tor_modules,
                           tor_status=tor_status,
                           tor_version=tor_version,
                           upload_progress=UploadProgress.query.all())


@blueprint.route('/log', methods=('GET', 'POST'))
@count_views
def log_view():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    form_log = forms_board.Log()

    log_cmd = ""
    log_output = ""

    lines = 30
    if form_log.lines.data:
        lines = form_log.lines.data

    log = "daemon"
    if form_log.log.data:
        log = form_log.log.data

    if log == "daemon":
        log_cmd = f'cat {config.LOG_BACKEND_FILE} | tail -n {lines}'
    elif log == "flask":
        log_cmd = f'cat {config.LOG_FRONTEND_FILE} | tail -n {lines}'
    elif log == "tor":
        if config.DOCKER:
            log_cmd = f'docker logs -n {lines} bitchan_tor'
        else:
            log_cmd = f'cat /var/log/syslog | grep tor -i | tail -n {lines}'
    elif log == "i2p":
        if config.DOCKER:
            log_cmd = f'docker logs -n {lines} bitchan_i2p'
        else:
            log_cmd = f'cat /var/log/i2pd/i2pd.log | grep tor -i | tail -n {lines}'

    if log_cmd:
        log_ = subprocess.Popen(log_cmd, stdout=subprocess.PIPE, shell=True)
        (log_output, _) = log_.communicate()
        log_.wait()
        log_output = html.escape(str(log_output, 'latin-1')).replace("\n", "<br/>")

    return render_template("pages/log.html",
                           lines=lines,
                           log=log,
                           log_output=log_output)
