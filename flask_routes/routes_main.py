import base64
import csv
import datetime
import html
import json
import logging
import os
import re
import subprocess
import time
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
from stem import CircStatus
from stem import Signal
from stem.connection import PasswordAuthFailed
from stem.control import Controller
from werkzeug.wrappers import Response

import config
from bitchan_flask import nexus
from database.models import AddressBook
from database.models import Alembic
from database.models import Chan
from database.models import Flags
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from database.models import Threads
from database.models import UploadProgress
from database.models import UploadSites
from forms import forms_board
from forms import forms_settings
from utils.files import LF
from utils.files import delete_file
from utils.general import get_random_alphanumeric_string
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_main')

blueprint = Blueprint('routes_main',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.route('/log', methods=('GET', 'POST'))
def log():
    form_log = forms_board.Log()

    log_file = "/usr/local/bitchan/log/bitchan.log"

    lines = 40
    if form_log.lines.data:
        lines = form_log.lines.data

    command = 'cat {log} | tail -n {lines}'.format(
        log=log_file, lines=lines)

    if command:
        log = subprocess.Popen(
            command, stdout=subprocess.PIPE, shell=True)
        (log_output, _) = log.communicate()
        log.wait()
        log_output = html.escape(str(log_output, 'latin-1')).replace("\n", "<br/>")
    else:
        log_output = 404

    return render_template("pages/log.html",
                           lines=lines,
                           log_output=log_output)


@blueprint.route('/', methods=('GET', 'POST'))
def index():
    status = nexus.get_api_status()
    status_msg = {"status_message": []}

    if not status == True:
        status_msg['status_title'] = "Error"
        if status == "ConnectionRefusedError(111, 'Connection refused')":
            status_msg['status_message'].append("Is Bitmessage running?")

    # Get OP and up to 3 replies for up to 3 threads from each board
    new_posts = OrderedDict()
    boards = Chan.query.filter(Chan.type == "board").all()
    for each_board in boards:
        threads = Threads.query.filter(
            Threads.chan_id == each_board.id).order_by(
            Threads.timestamp_sent.desc()).limit(3).all()
        for each_thread in threads:
            if each_board not in new_posts:
                new_posts[each_board] = {
                    "type": "board",
                    "threads": OrderedDict(),
                    "latest_timestamp": each_thread.timestamp_sent
                }
            new_posts[each_board]["threads"][each_thread] = []
            # OP
            new_posts[each_board]["threads"][each_thread].append(
                Messages.query.filter(
                    and_(
                        Messages.thread_id == each_thread.id,
                        Messages.is_op == True)).first())

            msg_count = Messages.query.filter(
                and_(
                    Messages.thread_id == each_thread.id,
                    Messages.is_op == False)).count()
            if msg_count:
                if msg_count > 3:
                    limit = 3
                else:
                    limit = msg_count
                messages = Messages.query.filter(
                    and_(
                        Messages.thread_id == each_thread.id,
                        Messages.is_op == False)).order_by(
                    Messages.timestamp_sent.desc()).limit(limit)
                messages = messages.from_self().order_by(
                    Messages.timestamp_sent.asc()).all()
                for each_msg in messages:
                    # Replies
                    new_posts[each_board]["threads"][each_thread].append(each_msg)

    lists = Chan.query.filter(Chan.type == "list").all()
    for each_list in lists:
        if each_list.list_timestamp_changed:
            new_posts[each_list] = {
                "type": "list",
                "latest_timestamp": each_list.list_timestamp_changed
            }

    # Sort boards by latest post
    newest_posts = OrderedDict(
        sorted(new_posts.items(), key=lambda x: x[1]['latest_timestamp'], reverse=True))

    def clean_html(raw_html):
        try:
            cleanr = re.compile('<.*?>')
            clean_text = re.sub(cleanr, '', raw_html)
            return clean_text
        except:
            return ""

    return render_template("pages/index.html",
                           clean_html=clean_html,
                           newest_posts=newest_posts,
                           status_msg=status_msg)


@blueprint.route('/help')
def help_docs():
    return render_template("pages/help.html")


@blueprint.route('/configure', methods=('GET', 'POST'))
def configure():
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
            settings.allow_net_file_size_check = form_settings.allow_net_file_size_check.data
            settings.allow_net_book_quote = form_settings.allow_net_book_quote.data
            settings.allow_net_ntp = form_settings.allow_net_ntp.data
            settings.never_auto_download_unencrypted = form_settings.never_auto_download_unencrypted.data
            if (form_settings.chan_update_display_number.data and
                    form_settings.chan_update_display_number.data >= 0):
                settings.chan_update_display_number = form_settings.chan_update_display_number.data
            settings.save()
            nexus.refresh_settings()
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

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_main.configure"))

    return render_template("pages/configure.html",
                           form_settings=form_settings,
                           status_msg=status_msg,
                           upload_sites=UploadSites.query.all())


@blueprint.route('/upload_site/<action>/<upload_site_id>', methods=('GET', 'POST'))
def upload_site(action, upload_site_id):
    form_upload_site = forms_settings.UploadSite()

    status_msg = session.get('status_msg', {"status_message": []})
    site_options = None
    current_upload_site = None

    if action in ["edit", "delete"]:
        current_upload_site = UploadSites.query.filter(UploadSites.id == int(upload_site_id)).first()
    elif action == "add_msg_id":
        try:
            site_options = json.loads(Messages.query.filter(Messages.message_id == upload_site_id).first().file_upload_settings)
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
                upload_site.domain = current_upload_site.domain.data
                upload_site.type = current_upload_site.type.data
                upload_site.uri = current_upload_site.uri.data
                upload_site.download_prefix = current_upload_site.download_prefix.data
                upload_site.response = current_upload_site.response.data
                upload_site.direct_dl_url = current_upload_site.direct_dl_url.data
                upload_site.extra_curl_options = current_upload_site.extra_curl_options.data
                upload_site.upload_word = current_upload_site.upload_word.data
                upload_site.form_name = current_upload_site.form_name.data
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
    from bitchan_flask import nexus
    status_msg = session.get('status_msg', {"status_message": []})
    bm_status = {}
    tor_status = {"Circuit Established": False}
    form_status = forms_settings.Status()
    logging.getLogger("stem").setLevel(logging.WARNING)

    if request.method == 'POST':
        if form_status.tor_newnym.data:
            try:
                with Controller.from_port(address="172.28.1.2", port=9061) as controller:
                    controller.authenticate(password=config.TOR_PASS)
                    controller.signal(Signal.NEWNYM)
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("New tor identity requested")
            except Exception as err:
                status_msg['status_message'].append("Error getting new tor identity: {}".format(err))

    lf = LF()
    if lf.lock_acquire(config.LOCKFILE_API, to=60):
        try:
            bm_status_raw = nexus._api.clientStatus()
            bm_status = OrderedDict(sorted(bm_status_raw.items()))
        except Exception as err:
            logger.error("Error: {}".format(err))
        finally:
            lf.lock_release(config.LOCKFILE_API)

    try:
        tor_version = subprocess.check_output(
            'docker exec -i tor tor --version --quiet', shell=True, text=True)
    except:
        tor_version = "Error getting tor version"

    tor_circuit_dict = {}
    try:
        with Controller.from_port(address="172.28.1.2", port=9061) as controller:
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


@blueprint.route('/diag', methods=('GET', 'POST'))
def diag():
    from bitchan_flask import nexus
    status_msg = session.get('status_msg', {"status_message": []})
    form_diag = forms_settings.Diag()

    if request.method == 'POST':
        if form_diag.del_inventory.data:
            try:
                nexus.clear_bm_inventory()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Deleted Bitmessage inventory and restarting Bitmessage. Give it time to resync.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete Bitmessage inventory: {}".format(err))
                logger.exception("Couldn't delete BM inventory")
        elif form_diag.del_trash.data:
            try:
                nexus.delete_and_vacuum()
                status_msg['status_title'] = "Success"
                status_msg['status_message'].append("Deleted Bitmessage Trash items.")
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't delete Bitmessage Trash items: {}".format(err))
                logger.exception("Couldn't delete BM Trash Items")

    return render_template("pages/diag.html",
                           form_diag=form_diag,
                           status_msg=status_msg)


@blueprint.route('/bug_report', methods=('GET', 'POST'))
def bug_report():
    from bitchan_flask import nexus
    status_msg = session.get('status_msg', {"status_message": []})
    form_bug = forms_board.BugReport()

    if request.method == 'POST':
        if form_bug.send.data and form_bug.bug_report.data:
            try:
                # Only send from a board or list
                # Do not send from an identity
                if config.DEFAULT_CHANS[0]["address"] in nexus.get_all_chans():
                    address_from = config.DEFAULT_CHANS[0]["address"]
                elif nexus.get_all_chans():
                    address_from = list(nexus.get_all_chans().keys())[0]
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
                    nexus.get_utc()).strftime('%Y-%m-%d %H:%M:%S')
                subject = "Bug Report {} ({})".format(config.VERSION_BITCHAN, ts)
                subject_b64 = base64.b64encode(subject.encode()).decode()

                if not status_msg['status_message']:
                    if address_from:
                        lf = LF()
                        if lf.lock_acquire(config.LOCKFILE_API, to=60):
                            try:
                                return_str = nexus._api.sendMessage(
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
                                time.sleep(0.1)
                            finally:
                                lf.lock_release(config.LOCKFILE_API)
            except Exception as err:
                status_msg['status_message'].append("Could not send: {}".format(err))
                logger.exception("Could not send bug report: {}".format(err))

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/bug_report.html",
                           form_bug=form_bug,
                           status_msg=status_msg)
