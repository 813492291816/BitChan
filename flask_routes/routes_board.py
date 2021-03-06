import base64
import json
import logging
import os
import time
from io import BytesIO

from flask import redirect
from flask import render_template
from flask import request
from flask import send_file
from flask import session
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_

import config
from bitchan_flask import nexus
from database.models import Chan
from database.models import Command
from database.models import Flags
from database.models import GlobalSettings
from database.models import Messages
from database.models import Threads
from database.models import UploadSites
from forms import forms_board
from utils.files import LF
from utils.files import delete_message_files
from utils.identicon import generate_icon
from utils.message_post import post_message
from utils.routes import attachment_info
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_board')

blueprint = Blueprint('routes_board',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.route('/board/<current_chan>/<current_page>', methods=('GET', 'POST'))
def board(current_chan, current_page):
    form_post = forms_board.Post()
    form_steg = forms_board.Steg()
    form_set = forms_board.SetChan()

    chan = Chan.query.filter(Chan.address == current_chan).first()
    if not chan:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    board = {
        "current_page": int(current_page),
        "current_chan": chan,
        "current_thread": None,
        "messages": Messages,
        "threads": Threads.query
            .filter(Threads.chan_id == chan.id)
            .order_by(Threads.timestamp_sent.desc())
    }

    form_populate = session.get('form_populate', {})
    status_msg = session.get('status_msg', {"status_message": []})

    def get_threads_from_page(address, page):
        thread_start = int((int(page) - 1) * config.THREADS_PER_PAGE)
        thread_end = int(int(page) * config.THREADS_PER_PAGE) - 1
        chan_ = Chan.query.filter(Chan.address == address).first()
        threads_all = Threads.query.filter(
            Threads.chan_id == chan_.id).order_by(Threads.timestamp_sent.desc()).all()
        threads = []
        for i, thread in enumerate(threads_all):
            if thread_start <= i <= thread_end:
                threads.append(thread)
        return threads

    if request.method == 'GET':
        if 'form_populate' in session:
            session.pop('form_populate')
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_set.set_pgp_passphrase_msg.data:
            if not form_set.pgp_passphrase_msg.data:
                status_msg['status_message'].append("Message PGP passphrase required")
            elif len(form_set.pgp_passphrase_msg.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append("Message PGP passphrase longer than {}: {}".format(
                    config.PGP_PASSPHRASE_LENGTH, len(form_set.pgp_passphrase_msg.data)))
            else:
                chan.pgp_passphrase_msg = form_set.pgp_passphrase_msg.data
                chan.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Changed Message PGP Passphrase.")

        if form_set.set_pgp_passphrase_attach.data:
            if not form_set.pgp_passphrase_attach.data:
                status_msg['status_message'].append("Attachment PGP passphrase required")
            elif len(form_set.pgp_passphrase_attach.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append("Attachment PGP passphrase longer than {}: {}".format(
                    config.PGP_PASSPHRASE_LENGTH, len(form_set.pgp_passphrase_attach.data)))
            else:
                chan.pgp_passphrase_attach = form_set.pgp_passphrase_attach.data
                chan.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Changed Attachment PGP Passphrase.")

        elif form_set.set_pgp_passphrase_steg.data:
            if not form_set.pgp_passphrase_steg.data:
                status_msg['status_message'].append("Steg PGP passphrase required")
            elif len(form_set.pgp_passphrase_steg.data) > config.PGP_PASSPHRASE_LENGTH:
                status_msg['status_message'].append("Steg PGP passphrase longer than {}: {}".format(
                    config.PGP_PASSPHRASE_LENGTH, len(form_set.pgp_passphrase_steg.data)))
            else:
                chan.pgp_passphrase_steg = form_set.pgp_passphrase_steg.data
                chan.save()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Changed Steg PGP Passphrase.")

        elif form_post.start_download.data:
            nexus.set_start_download(form_post.message_id.data)
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(
                "File download initialized in the background. Give it time to download.")

        elif form_post.submit.data:
            if form_post.default_from_address.data:
                chan.default_from_address = form_post.from_address.data
            else:
                chan.default_from_address = None
            chan.save()
            status_msg, result, form_populate = post_message(form_post, form_steg)

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_board.board",
                                current_chan=current_chan,
                                current_page=current_page))

    try:
        from_list = nexus.get_from_list(current_chan)
    except:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    chan = Chan.query.filter(Chan.address == current_chan).first()
    dict_join = {
        "passphrase": chan.passphrase
    }
    passphrase_base64 = base64.b64encode(
        json.dumps(dict_join).encode()).decode().replace("/", "&")
    if chan.pgp_passphrase_msg != config.PGP_PASSPHRASE_MSG:
        dict_join["pgp_msg"] = chan.pgp_passphrase_msg
    if chan.pgp_passphrase_attach != config.PGP_PASSPHRASE_ATTACH:
        dict_join["pgp_attach"] = chan.pgp_passphrase_attach
    if chan.pgp_passphrase_steg != config.PGP_PASSPHRASE_STEG:
        dict_join["pgp_steg"] = chan.pgp_passphrase_steg
    passphrase_base64_with_pgp = base64.b64encode(
        json.dumps(dict_join).encode()).decode().replace("/", "&")

    return render_template("pages/board.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           from_list=from_list,
                           get_threads_from_page=get_threads_from_page,
                           passphrase_base64=passphrase_base64,
                           passphrase_base64_with_pgp=passphrase_base64_with_pgp,
                           status_msg=status_msg,
                           upload_sites=UploadSites)


@blueprint.route('/thread/<current_chan>/<thread_id>', methods=('GET', 'POST'))
def thread(current_chan, thread_id):
    form_post = forms_board.Post()
    form_steg = forms_board.Steg()

    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    if not chan:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    if not thread:
        return render_template("pages/404-thread.html",
                               board_address=current_chan,
                               thread_id=thread_id)
    board = {
        "current_chan": chan,
        "current_thread": thread,
        "nexus_thread": nexus.get_chan_thread(current_chan, thread_id),
        "messages": Messages
    }

    form_populate = session.get('form_populate', {})
    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'form_populate' in session:
            session.pop('form_populate')
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_post.start_download.data:
            nexus.set_start_download(form_post.message_id.data)
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(
                "File download initialized in the background. Give it time to download.")

        elif form_post.submit.data:
            if form_post.default_from_address.data:
                thread.default_from_address = form_post.from_address.data
            else:
                thread.default_from_address = None
            thread.save()
            status_msg, result, form_populate = post_message(form_post, form_steg)

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        return redirect(url_for("routes_board.thread",
                                current_chan=current_chan,
                                thread_id=thread_id))

    try:
        from_list = nexus.get_from_list(current_chan)
    except:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    return render_template("pages/thread.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           from_list=from_list,
                           status_msg=status_msg,
                           upload_sites=UploadSites)


@blueprint.route('/thread_steg/<current_chan>/<thread_id>', methods=('GET', 'POST'))
def thread_steg(current_chan, thread_id):
    form_post = forms_board.Post()
    form_steg = forms_board.Steg()

    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    if not chan:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    if not thread:
        return render_template("pages/404-thread.html",
                               board_address=current_chan,
                               thread_id=thread_id)

    board = {
        "current_chan": chan,
        "current_thread": thread,
        "nexus_thread": nexus.get_chan_thread(current_chan, thread_id),
        "messages": Messages
    }
    form_populate = session.get('form_populate', {})
    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'form_populate' in session:
            session.pop('form_populate')
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_post.start_download.data:
            nexus.set_start_download(form_post.message_id.data)
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(
                "File download initialized in the background. Give it time to download.")

        elif form_post.submit.data:
            if form_post.default_from_address.data:
                thread.default_from_address = form_post.from_address.data
            else:
                thread.default_from_address = None
            thread.save()
            status_msg, result, form_populate = post_message(form_post, form_steg)

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        return redirect(url_for("routes_board.thread_steg",
                                current_chan=current_chan,
                                thread_id=thread_id))

    try:
        from_list = nexus.get_from_list(current_chan)
    except:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    return render_template("pages/thread_steg.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           form_steg=form_steg,
                           from_list=from_list,
                           status_msg=status_msg,
                           upload_sites=UploadSites)


@blueprint.route('/icon/<address>')
def icon_image(address):
    path_icon = os.path.join(config.FILE_DIRECTORY, "{}_icon.png".format(address))
    if not os.path.exists(path_icon):
        generate_icon(address)
    return send_file(path_icon, mimetype='image/png', cache_timeout=1440)


@blueprint.route('/custom_flag_by_flag_id/<flag_id>')
def custom_flag_by_flag_id(flag_id):
    """Returns a flag image based on the flag ID"""
    flag = Flags.query.filter(Flags.id == int(flag_id)).first()

    if flag:
        return send_file(
            BytesIO(base64.b64decode(flag.flag_base64)),
            mimetype='image/{}'.format(flag.flag_extension),
            cache_timeout=1440)


@blueprint.route('/custom_flag_by_post_id/<post_id>')
def custom_flag_by_post_id(post_id):
    """Returns a flag image based on the post ID"""
    message = Messages.query.filter(Messages.message_id == post_id).first()

    if message:
        return send_file(
            BytesIO(base64.b64decode(message.nation_base64)),
            mimetype='image/jpg',
            cache_timeout=1440)


@blueprint.route('/banner/<chan_address>')
def banner_image(chan_address):
    """Returns a banner image based on whether a custom banner is available"""
    file_path = None
    chan = Chan.query.filter(Chan.address == chan_address).first()
    settings = GlobalSettings.query.first()

    if chan:
        admin_cmd = Command.query.filter(and_(
            Command.chan_address == chan.address,
            Command.action == "set",
            Command.action_type == "options")).first()
        if admin_cmd:
            try:
                options = json.loads(admin_cmd.options)
            except:
                options = {}
            if "banner_base64" in options and options["banner_base64"]:
                return send_file(
                    BytesIO(base64.b64decode(options["banner_base64"])),
                    mimetype='image/png',
                    cache_timeout=1440)

    if settings.theme in config.THEMES_DARK:
        file_path = "/home/bitchan/static/banner_dark.png"
    elif settings.theme in config.THEMES_LIGHT:
        file_path = "/home/bitchan/static/banner_light.png"

    if file_path:
        return send_file(file_path, mimetype='image/png', cache_timeout=1440)
    return "Error determining the banner image to use"


@blueprint.route('/spoiler/<chan_address>')
def spoiler_image(chan_address):
    """Returns a spoiler image based on whether a custom banner is available"""
    chan = Chan.query.filter(Chan.address == chan_address).first()

    if chan:
        admin_cmd = Command.query.filter(and_(
            Command.chan_address == chan.address,
            Command.action == "set",
            Command.action_type == "options")).first()
        if admin_cmd:
            try:
                options = json.loads(admin_cmd.options)
            except:
                options = {}
            if "spoiler_base64" in options and options["spoiler_base64"]:
                return send_file(
                    BytesIO(base64.b64decode(options["spoiler_base64"])),
                    mimetype='image/png',
                    cache_timeout=1440)

    file_path = "/home/bitchan/static/spoiler.png"
    return send_file(file_path, mimetype='image/png', cache_timeout=1440)


def get_image_attach(message_id, file_path, file_filename, extension, mime_type="image/jpg"):
    post = Messages.query.filter(Messages.message_id == message_id).first()
    if extension in config.FILE_EXTENSIONS_IMAGE:
        mime_type = "image/jpg"
    elif extension in config.FILE_EXTENSIONS_VIDEO:
        mime_type = "video/mp4"

    if file_path and file_filename:
        file_path = os.path.join(file_path, file_filename)
        if os.path.exists(file_path):
            if extension in config.FILE_EXTENSIONS_IMAGE:
                return send_file(file_path, mimetype=mime_type)
        else:
            logger.error("File doesn't exist on disk")
            message = Messages.query.filter(Messages.message_id == message_id).first()
            message.file_download_successful = False
            message.file_sha256_hashes_match = False
            message.save()
            return ""
    else:
        return send_file(BytesIO(post.file_decoded), mimetype=mime_type)


@blueprint.route('/files/<file_type>/<message_id>/<filename>')
def images(message_id, file_type, filename):
    post = Messages.query.filter(Messages.message_id == message_id).first()
    if not post:
        if file_type == "god_song":
            pass  # God songs can be in the long description
        else:
            return "Message ID not found"

    if file_type == "thumb":
        # Return image thumbnail
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}_thumb".format(config.FILE_DIRECTORY, message_id)
        if filename in media_info:
            return get_image_attach(
                message_id, path, filename, media_info[filename]["extension"])
    if file_type == "thumb_first":
        # Return image thumbnail
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}_thumb".format(config.FILE_DIRECTORY, message_id)
        for filename in media_info:
            if media_info[filename]["extension"] in config.FILE_EXTENSIONS_IMAGE:
                if media_info[filename]['spoiler']:
                    return send_file("/home/bitchan/static/spoiler.png", mimetype="image/png")
                else:
                    return get_image_attach(
                        message_id, path, filename, media_info[filename]["extension"])
    elif file_type == "image":
        # Return image file
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}".format(config.FILE_DIRECTORY, message_id)
        if filename in media_info:
            return get_image_attach(
                message_id, path, filename, media_info[filename]["extension"])
    elif file_type == "god_song":
        file_path = "{}/{}_god_song.mp3".format(config.FILE_DIRECTORY, message_id)
        if os.path.exists(file_path):
            return send_file(file_path, mimetype="audio/mp3")
        else:
            return "Could not find God Song file at {}".format(file_path)
    elif file_type == "file":
        # Return potentially non-image file
        file_order, media_info, _ = attachment_info(message_id)
        path = "{}/{}".format(config.FILE_DIRECTORY, message_id)
        file_path = "{}/{}".format(path, filename)
        if os.path.exists(file_path):
            if (filename in media_info and
                    media_info[filename]["extension"] in config.FILE_EXTENSIONS_IMAGE):
                return get_image_attach(
                    message_id, path, filename, media_info[filename]["extension"])
            else:
                return send_file(file_path, attachment_filename=filename)
    else:
        logger.error("File '{}' not found for message {}".format(filename, message_id))
        return ""


@blueprint.route('/dl/<message_id>/<filename>')
def download(message_id, filename):
    post = Messages.query.filter(Messages.message_id == message_id).first()
    file_path = "{}/{}/{}".format(config.FILE_DIRECTORY, message_id, filename)
    if post and os.path.exists(file_path):
        return send_file(file_path,
                         attachment_filename=filename,
                         as_attachment=True)


@blueprint.route('/block_address/<chan_address>/<block_address>/<block_type>', methods=('GET', 'POST'))
def block_address(chan_address, block_address, block_type):
    """Block address locally, on single board or across all boards"""
    form_confirm = forms_board.Confirm()

    chan = Chan.query.filter(Chan.address == chan_address).first()

    if request.method != 'POST' or not form_confirm.confirm.data:
        return render_template("pages/confirm.html",
                               action="block_address",
                               block_type=block_type,
                               chan=chan,
                               chan_address=chan_address,
                               block_address=block_address)

    messages = Messages.query.filter(Messages.address_from == block_address).all()

    board = {
        "current_chan": chan,
        "current_thread": None,
    }
    status_msg = {"status_message": []}
    list_delete_message_ids = []

    for message in messages:
        if block_type == "single_board" and message.thread.chan.address == chan_address:
            list_delete_message_ids.append(message.message_id)
        elif block_type == "global":
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
        except Exception as err:
            logger.error("Exception while deleting messages: {}".format(err))
        finally:
            lf.lock_release(config.LOCKFILE_MSG_PROC)

    new_cmd = Command()
    new_cmd.do_not_send = True
    new_cmd.action = "block"
    new_cmd.action_type = "block_address"
    new_cmd.options = json.dumps({"block_address": block_address})
    if block_type == "single_board":
        new_cmd.chan_address = chan_address
    elif block_type == "global":
        new_cmd.chan_address = "all"  # global block
    new_cmd.save()

    status_msg['status_title'] = "Success"
    status_msg['status_message'].append("Blocked address {}".format(block_address))

    return render_template("pages/alert.html",
                           board=board,
                           status_msg=status_msg)
