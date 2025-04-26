import json
import logging
import time

from flask import abort
from flask import request
from flask.blueprints import Blueprint
from sqlalchemy import and_

from bitchan_client import DaemonCom
from database.models import GlobalSettings
from database.models import Messages
from database.models import Threads
from flask_routes.utils import count_views
from flask_routes.utils import get_posts_from_thread
from flask_routes.utils import is_verified
from flask_routes.utils import rate_limit
from utils.generate_post import generate_post_html
from utils.routes import allowed_access
from utils.routes import get_post_id_string
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_no_verification')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_no_verification',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.before_request
def before_view():
    if not is_verified():
        abort(401)  # 401 Unauthorized


@blueprint.route('/new_posts/<thread_hash_short>/<post_ids>', methods=('GET', 'POST'))
@count_views
@rate_limit
def new_posts(thread_hash_short, post_ids):
    can_view, allow_msg = allowed_access("can_view")
    if not can_view:
        return allow_msg

    list_new_posts = []
    list_new_post_ids = []
    list_ref_posts = []
    list_ref_post_message_ids = []
    last_post_id = None
    list_post_ids_only = []
    post_new_count = 0
    post_ref_count = 0
    list_posts = []
    download_statuses = {}
    found_first_post = False

    settings = GlobalSettings.query.first()

    pow_filter_value = 0
    try:
        arg_filter_pow = request.args.get('filter_pow', default=None, type=str)
        if arg_filter_pow:
            pow_filter_value = (2 ** int(arg_filter_pow.split("x")[0])) * int(arg_filter_pow.split("x")[1])
    except:
        logger.exception("/new_posts/ POW Filter")

    try:
        last = int(request.args.get('last'))
        if last < 0:
            last = None
    except:
        last = None

    thread = Threads.query.filter(Threads.thread_hash_short == thread_hash_short).first()
    if not thread:
        return json.dumps([])

    post_order, message_op, message_replies, message_reply_all_count = get_posts_from_thread(
        thread, settings, pow_filter_value, last, False)

    if message_op:
        post_op_post_id = message_op.post_id
        list_posts.append(post_op_post_id)  # Add OP ID to list to it's not removed from thread
        last_post_id = post_op_post_id
        found_first_post = True
    else:
        post_op_post_id = None

    message_replies = message_replies.all()

    try:
        list_post_ids = post_ids.split("_")
        for each_post_id in list_post_ids:
            if "-" in each_post_id:
                list_post_ids_only.append(each_post_id.split("-")[0])
            else:
                list_post_ids_only.append(each_post_id)
    except:
        return json.dumps([])

    # Find Posts removed
    for each_post in message_replies:
        list_posts.append(each_post.post_id)

    # logger.info(f"Received: {list_post_ids_only}")
    # logger.info(f"Available: {list_posts}")

    list_del_posts = list(set(list_post_ids_only) - set(list_posts))

    # Find posts added
    for each_post in message_replies:
        # Need to ensure we find at least the first post_id before starting to add new posts
        # This allows ?last=x page to work
        if each_post.post_id.upper() in list_post_ids_only:
            found_first_post = True
        if not found_first_post:
            continue

        # Find posts that have had attachments successfully downloaded to refresh
        download_statuses[each_post.post_id] = get_post_id_string(post_id=each_post.post_id)
        for each_post_attach in list_post_ids:
            if (("-" in each_post_attach and
                    each_post_attach.split("-")[0] == each_post.post_id.upper()) or
                        each_post.post_id.upper() == each_post_attach):
                if each_post_attach != download_statuses[each_post.post_id]:
                    # Post ID string is not the same as on the user's page, indicate to refresh post content
                    list_ref_post_message_ids.append(
                        [each_post.post_id, each_post.message_id])
                break

        if each_post.post_id.upper() not in list_post_ids_only:
            if each_post.post_id in download_statuses:
                download_status = download_statuses[each_post.post_id]
            else:
                download_status = None

            list_new_posts.append([
                last_post_id,
                each_post.post_id.upper(),
                generate_post_html(each_post.message_id),
                download_status
            ])
            list_new_post_ids.append(each_post.post_id.upper())
            list_post_ids_only.append(each_post.post_id.upper())
            post_new_count += 1

            # Find posts that the new post references, check if it's in this thread, and update it.
            # Allow refreshing of OP post, since OP post isn't included in the list to check for
            # new posts if there are replies.
            try:
                replies = json.loads(each_post.post_ids_replied_to)
                for each_post_id in replies:
                    if each_post_id in list_post_ids_only or (post_op_post_id and each_post_id == post_op_post_id):
                        reply_post = Messages.query.join(Threads).filter(and_(
                            Threads.thread_hash_short == thread_hash_short,
                            Messages.post_id == each_post_id)).first()
                        if reply_post and each_post_id not in list_ref_post_message_ids:
                            list_ref_post_message_ids.append(
                                [each_post_id, reply_post.message_id])
                    else:
                        continue  # Skip refreshing posts that aren't on the page
            except:
                pass

        if each_post.post_id.upper() in list_post_ids_only:
            last_post_id = each_post.post_id.upper()

        # Only allow returning up to 10 new posts at a time
        if post_new_count >= 10:
            break

    # logger.info(f"ADD: {list_new_post_ids}")
    # logger.info(f"DEL: {list_del_posts}")
    # logger.info(f"REF: {list_ref_posts}")

    # Send posts in this thread that should be refreshed to update header of post replies
    for post_id, message_id in list_ref_post_message_ids:
        # Don't include posts that are already being added via the add post list
        if post_id in list_new_post_ids:
            continue
        # Only allow returning up to 10 refreshed posts at a time
        if post_ref_count >= 10:
            break

        if post_id in download_statuses:
            download_status = download_statuses[post_id]
        else:
            download_status = None

        list_ref_posts.append([post_id, generate_post_html(message_id), download_status])
        post_ref_count += 1

    ret_json = json.dumps({
        "add": list_new_posts,
        "del": list_del_posts,
        "ref": list_ref_posts
    })

    return ret_json


@blueprint.route('/post-timer')
def post_timer():
    settings = GlobalSettings.query.first()
    if not settings.enable_kiosk_mode or not settings.kiosk_post_rate_limit:
        return ""
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return "ERR"
    now = time.time()
    last_post_ts = daemon_com.get_last_post_ts()
    if now < last_post_ts + settings.kiosk_post_rate_limit:
        seconds_left = (last_post_ts + settings.kiosk_post_rate_limit) - now
        return str(int(seconds_left))
    return "0"
