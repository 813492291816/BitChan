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
from database.models import Messages
from database.models import Threads
from forms import forms_board
from utils.files import LF
from utils.files import delete_message_files
from utils.identicon import generate_icon
from utils.messages import post_message
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
        thread_end = int(int(page) * config.THREADS_PER_PAGE)
        chan = Chan.query.filter(
            Chan.address == address).first()
        threads_all = Threads.query.filter(
            Threads.chan_id == chan.id).order_by(Threads.timestamp_sent.desc()).all()
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
        if form_post.start_download.data:
            nexus.set_start_download(form_post.message_id.data)
            status_msg['status_title'] = "Success"
            status_msg['status_message'].append(
                "File download initialized in the background. Give it time to download.")

        elif form_post.submit.data:
            status_msg, result, form_populate = post_message(form_post, form_steg)

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        return redirect(url_for("routes_board.board",
                                current_chan=current_chan,
                                current_page=current_page))

    return render_template("pages/board.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           get_threads_from_page=get_threads_from_page,
                           status_msg=status_msg)


@blueprint.route('/thread/<current_chan>/<thread_id>', methods=('GET', 'POST'))
def thread(current_chan, thread_id):
    form_post = forms_board.Post()
    form_steg = forms_board.Steg()

    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    if not chan or not thread:
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
            status_msg, result, form_populate = post_message(form_post, form_steg)

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        return redirect(url_for("routes_board.thread",
                                current_chan=current_chan,
                                thread_id=thread_id))

    return render_template("pages/thread.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           status_msg=status_msg)


@blueprint.route('/thread_steg/<current_chan>/<thread_id>', methods=('GET', 'POST'))
def thread_steg(current_chan, thread_id):
    form_post = forms_board.Post()
    form_steg = forms_board.Steg()

    chan = Chan.query.filter(Chan.address == current_chan).first()
    thread = Threads.query.filter(Threads.thread_hash == thread_id).first()

    if not chan or not thread:
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
            status_msg, result, form_populate = post_message(form_post, form_steg)

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        return redirect(url_for("routes_board.thread_steg",
                                current_chan=current_chan,
                                thread_id=thread_id))

    return render_template("pages/thread_steg.html",
                           board=board,
                           form_populate=form_populate,
                           form_post=form_post,
                           form_steg=form_steg,
                           status_msg=status_msg)


@blueprint.route('/icon/<address>')
def icon_image(address):
    path_icon = os.path.join(config.FILE_DIRECTORY, "{}_icon.png".format(address))
    if not os.path.exists(path_icon):
        generate_icon(address)
    return send_file(path_icon, mimetype='image/png', cache_timeout=1440)


@blueprint.route('/banner/<chan_address>')
def banner_image(chan_address):
    """Returns a banner image based on whether a custom banner is available"""
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
            if "banner_base64" in options and options["banner_base64"]:
                return send_file(
                    BytesIO(base64.b64decode(options["banner_base64"])),
                    mimetype='image/jpg',
                    cache_timeout=1440)

    file_path = "/home/bitchan/static/banner.png"
    return send_file(file_path, mimetype='image/jpg', cache_timeout=1440)


def get_image(message_id, file_filename, mime_type="image/jpg"):
    post = Messages.query.filter(Messages.message_id == message_id).first()
    if post.file_extension in config.FILE_EXTENSIONS_IMAGE:
        mime_type = "image/jpg"
    elif post.file_extension in config.FILE_EXTENSIONS_VIDEO:
        mime_type = "video/mp4"

    if file_filename:
        file_path = os.path.join(config.FILE_DIRECTORY, file_filename)
        if os.path.exists(file_path):
            if post.file_extension in config.FILE_EXTENSIONS_IMAGE:
                return send_file(file_path, mimetype=mime_type)
        else:
            logger.error("File doesn't exist on disk")
            message = Messages.query.filter(Messages.message_id == message_id).first()
            message.file_download_successful = False
            message.file_md5_hashes_match = False
            message.save()
            return ""
    else:
        return send_file(BytesIO(post.file_decoded), mimetype=mime_type)


@blueprint.route('/files/<file_type>/<message_id>/<filename>')
def images(message_id, file_type, filename):
    post = Messages.query.filter(Messages.message_id == message_id).first()
    if post:
        if file_type == "thumb":
            # Return image thumbnail
            return get_image(message_id, post.saved_image_thumb_filename)
        elif file_type == "image":
            # Return image file
            return get_image(message_id, post.saved_file_filename)
        elif file_type == "god_song":
            file_path = "{}/{}_god_song.mp3".format(config.FILE_DIRECTORY, message_id)
            if os.path.exists(file_path):
                return send_file(file_path, mimetype="audio/mp3")
        elif file_type == "file":
            # Return potentially non-image file
            file_path = "{}/{}".format(config.FILE_DIRECTORY, post.saved_file_filename)
            if os.path.exists(file_path):
                if post.file_extension in config.FILE_EXTENSIONS_IMAGE:
                    return get_image(message_id, post.saved_file_filename)
                else:
                    file_path = "{}/{}".format(config.FILE_DIRECTORY, post.saved_file_filename)
                    return send_file(file_path, attachment_filename=post.file_filename)
            elif post.file_decoded is not None:
                # Return file from dictionary entry data
                if post.file_extension in config.FILE_EXTENSIONS_IMAGE:
                    # File data is an image
                    return send_file(BytesIO(post.file_decoded), mimetype='image/jpg')
                else:
                    # File data is not an image
                    return send_file(BytesIO(post.file_decoded), attachment_filename=post.file_filename)
        else:
            logger.error("File '{}' not found for message {}".format(filename, message_id))
            return ""
    return "Unexpected error while serving file"


@blueprint.route('/dl/<message_id>/<filename>')
def download(message_id, filename):
    post = Messages.query.filter(Messages.message_id == message_id).first()
    if post:
        # Return potentially non-image file
        file_path = "{}/{}".format(config.FILE_DIRECTORY, post.saved_file_filename)
        if os.path.exists(file_path):
            file_path = "{}/{}".format(config.FILE_DIRECTORY, post.saved_file_filename)
            return send_file(file_path,
                             attachment_filename=post.file_filename,
                             as_attachment=True)
        elif post.file_decoded:
            # Return file from dictionary entry data
            return send_file(BytesIO(post.file_decoded),
                             attachment_filename=post.file_filename,
                             as_attachment=True)


@blueprint.route('/block_address/<chan_address>/<block_address>/<block_type>', methods=('GET', 'POST'))
def block_address(chan_address, block_address, block_type):
    """Block address locally, on single board or across all boards"""
    chan = Chan.query.filter(Chan.address == chan_address).first()
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
