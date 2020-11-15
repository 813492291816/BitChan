import json
import logging
import time

from flask import render_template
from flask import request
from flask.blueprints import Blueprint

import config
from bitchan_flask import nexus
from config import RESTRICTED_WORDS
from database.models import Chan
from forms import forms_board
from utils.files import LF
from utils.files import delete_message_files
from utils.general import generate_passphrase
from utils.general import process_passphrase
from utils.general import set_clear_time_to_future
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_management')

blueprint = Blueprint('routes_management',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.route('/join', methods=('GET', 'POST'))
def join():
    form_join = forms_board.Join()

    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    if not form_join.stage.data:
        stage = "start"
    else:
        stage = form_join.stage.data

    if request.method == 'POST':
        if stage == "start":
            if form_join.join_type.data == "join":
                stage = "join"
            elif form_join.join_type.data == "public_board":
                stage = "public_board"
            elif form_join.join_type.data == "private_board":
                stage = "private_board"
            elif form_join.join_type.data == "public_list":
                stage = "public_list"
            elif form_join.join_type.data == "private_list":
                stage = "private_list"

        # Join board or list
        elif stage == "join" and form_join.join.data:
            passphrase = form_join.passphrase.data
            if not passphrase:
                status_msg['status_message'].append("Passphrase required")

            errors, dict_chan_info = process_passphrase(passphrase)
            if not dict_chan_info:
                status_msg['status_message'].append("Error parsing passphrase")
                for error in errors:
                    status_msg['status_message'].append(error)

            if not status_msg['status_message']:
                for each_word in RESTRICTED_WORDS:
                    if each_word in dict_chan_info["label"].lower():
                        status_msg['status_message'].append(
                            "bitchan is a restricted word for labels")

            if not status_msg['status_message']:
                status_msg['status_title'] = "Success"
                result = nexus.join_chan(passphrase)

                if dict_chan_info["rules"]:
                    dict_chan_info["rules"] = set_clear_time_to_future(dict_chan_info["rules"])

                new_chan = Chan()
                new_chan.passphrase = passphrase
                new_chan.access = dict_chan_info["access"]
                new_chan.type = dict_chan_info["type"]
                new_chan.primary_addresses = json.dumps(dict_chan_info["primary_addresses"])
                new_chan.secondary_addresses = json.dumps(dict_chan_info["secondary_addresses"])
                new_chan.tertiary_addresses = json.dumps(dict_chan_info["tertiary_addresses"])
                new_chan.restricted_addresses = json.dumps(dict_chan_info["restricted_addresses"])
                new_chan.rules = json.dumps(dict_chan_info["rules"])
                new_chan.description = dict_chan_info["description"]

                if result.startswith("BM-"):
                    new_chan.address = result
                    new_chan.label = dict_chan_info["label"]
                    new_chan.is_setup = True
                    if new_chan.type == "board":
                        status_msg['status_message'].append("Joined board")
                        url = "/board/{}/1".format(result)
                        url_text = "/{}/ - {}".format(new_chan.label, new_chan.description)
                    elif new_chan.type == "list":
                        status_msg['status_message'].append("Joined list")
                        url = "/list/{}".format(result)
                        url_text = "{} - {}".format(new_chan.label, new_chan.description)
                else:
                    status_msg['status_message'].append(
                        "Chan creation queued. Label set temporarily to passphrase.")
                    new_chan.address = None
                    new_chan.label = "[chan] {}".format(passphrase)
                    new_chan.is_setup = False
                new_chan.save()
                stage = "end"

        # Create public/private board/list
        elif (stage in ["public_board",
                        "private_board",
                        "public_list",
                        "private_list"] and
                form_join.join.data):
            label = form_join.label.data
            if not label:
                status_msg['status_message'].append("Label required")

            for each_word in RESTRICTED_WORDS:
                if each_word in label.lower():
                    status_msg['status_message'].append(
                        "bitchan is a restricted word for labels")

            description = form_join.description.data
            if not description:
                status_msg['status_message'].append("Description required")

            def process_additional_addresses(form_list, status_msg):
                add_list_failed = []
                add_list_passed = []
                try:
                    list_additional = form_list.split(",")
                    for each_ident in list_additional:
                        ident_strip = each_ident.replace(" ", "")
                        if (ident_strip and (
                                not ident_strip.startswith("BM-") or
                                len(ident_strip) > 38 or
                                len(ident_strip) < 34)):
                            add_list_failed.append(ident_strip)
                        elif ident_strip.startswith("BM-"):
                            add_list_passed.append(ident_strip)
                except:
                    logger.exception(1)
                    status_msg['status_message'].append(
                        "Error parsing additional addresses. "
                        "Must only be comma-separated addresses without spaces.")
                return status_msg, add_list_failed, add_list_passed

            status_msg, add_list_prim_fail, add_list_prim_pass = process_additional_addresses(
                form_join.primary_additional.data, status_msg)
            if add_list_prim_fail:
                status_msg['status_message'].append(
                    "Error parsing primary additional identities. "
                    "Must only be comma-separated addresses without spaces.")

            list_primary_identities = []
            for key in request.form.keys():
                if 'primary_identity_' in key and key[17:]:
                    list_primary_identities.append(key[17:])
            list_primary_address_book = []
            for key in request.form.keys():
                if 'primary_address_book_' in key and key[21:]:
                    list_primary_address_book.append(key[21:])
            list_primary_chans = []
            for key in request.form.keys():
                if 'primary_chans_' in key and key[14:]:
                    list_primary_chans.append(key[14:])
            list_primary_addresses = (
                list_primary_identities +
                list_primary_address_book +
                list_primary_chans +
                add_list_prim_pass)

            status_msg, add_list_sec_fail, add_list_sec_pass = process_additional_addresses(
                form_join.secondary_additional.data, status_msg)
            if add_list_prim_fail:
                status_msg['status_message'].append(
                    "Error parsing secondary additional identities. "
                    "Must only be comma-separated addresses without spaces.")

            list_secondary_identities = []
            for key in request.form.keys():
                if 'secondary_identity_' in key and key[19:]:
                    list_secondary_identities.append(key[19:])
            list_secondary_address_book = []
            for key in request.form.keys():
                if 'secondary_address_book_' in key and key[23:]:
                    list_secondary_address_book.append(key[23:])
            list_secondary_chans = []
            for key in request.form.keys():
                if 'secondary_chans_' in key and key[16:]:
                    list_secondary_chans.append(key[16:])
            list_secondary_addresses = (
                list_secondary_identities +
                list_secondary_address_book +
                list_secondary_chans +
                add_list_sec_pass)

            status_msg, add_list_ter_fail, add_list_ter_pass = process_additional_addresses(
                form_join.tertiary_additional.data, status_msg)
            if add_list_prim_fail:
                status_msg['status_message'].append(
                    "Error parsing tertiary additional identities. "
                    "Must only be comma-separated addresses without spaces.")

            list_tertiary_identities = []
            for key in request.form.keys():
                if 'tertiary_identity_' in key and key[18:]:
                    list_tertiary_identities.append(key[18:])
            list_tertiary_address_book = []
            for key in request.form.keys():
                if 'tertiary_address_book_' in key and key[22:]:
                    list_tertiary_address_book.append(key[22:])
            list_tertiary_chans = []
            for key in request.form.keys():
                if 'tertiary_chans_' in key and key[15:]:
                    list_tertiary_chans.append(key[15:])
            list_tertiary_addresses = (
                    list_tertiary_identities +
                    list_tertiary_address_book +
                    list_tertiary_chans +
                    add_list_ter_pass)

            status_msg, add_list_restricted_fail, add_list_restricted_pass = process_additional_addresses(
                form_join.restricted_additional.data, status_msg)
            if add_list_restricted_fail:
                status_msg['status_message'].append(
                    "Error parsing restricted additional identities. "
                    "Must only be comma-separated addresses without spaces.")

            list_restricted_address_book = []
            for key in request.form.keys():
                if 'restricted_address_book_' in key and key[24:]:
                    list_restricted_address_book.append(key[24:])
            list_restricted_chans = []
            for key in request.form.keys():
                if 'restricted_chans_' in key and key[17:]:
                    list_restricted_chans.append(key[17:])
            list_restricted_addresses = (
                    list_restricted_address_book +
                    list_restricted_chans +
                    add_list_restricted_pass)

            if (stage in ["private_board", "private_list"] and
                    not list_primary_addresses):
                status_msg['status_message'].append(
                    "Must provide at least one primary address as the owner")

            rules = {}

            if form_join.require_identity_to_post.data:
                rules["require_identity_to_post"] = form_join.require_identity_to_post.data
            if form_join.automatic_wipe.data:
                try:
                    rules["automatic_wipe"] = {
                        "wipe_epoch": form_join.wipe_epoch.data,
                        "interval_seconds": form_join.interval_seconds.data
                    }
                except:
                    status_msg['status_message'].append(
                        "Could not process Rule options to Automatic Wipe")

            extra_string = form_join.extra_string.data

            if not status_msg['status_message']:
                status_msg['status_title'] = "Success"

                access = stage.split("_")[0]
                chan_type = stage.split("_")[1]

                passphrase = generate_passphrase(
                    access,
                    chan_type,
                    label,
                    description,
                    list_restricted_addresses,
                    list_primary_addresses,
                    list_secondary_addresses,
                    list_tertiary_addresses,
                    rules,
                    extra_string)

                result = nexus.join_chan(passphrase)

                if rules:
                    rules = set_clear_time_to_future(rules)

                new_chan = Chan()
                new_chan.access = access
                new_chan.type = chan_type
                new_chan.restricted_addresses = json.dumps(list_restricted_addresses)
                new_chan.primary_addresses = json.dumps(list_primary_addresses)
                new_chan.secondary_addresses = json.dumps(list_secondary_addresses)
                new_chan.tertiary_addresses = json.dumps(list_tertiary_addresses)
                new_chan.rules = json.dumps(rules)

                if result.startswith("BM-"):
                    if stage == "public_board":
                        status_msg['status_message'].append("Created public board")
                    elif stage == "private_board":
                        status_msg['status_message'].append("Created private board")
                    elif stage == "public_list":
                        status_msg['status_message'].append("Created public list")
                    elif stage == "private_list":
                        status_msg['status_message'].append("Created private list")
                    new_chan.address = result
                    new_chan.label = label
                    new_chan.description = description
                    new_chan.is_setup = True
                    if stage in ["public_board", "private_board"]:
                        url = "/board/{}/1".format(result)
                        url_text = "/{}/ - {}".format(label, description)
                    elif stage in ["public_list", "private_list"]:
                        url = "/list/{}".format(result)
                        url_text = "{} - {}".format(label, description)
                else:
                    status_msg['status_message'].append(
                        "Creation queued. Label set to passphrase.")
                    new_chan.address = None
                    new_chan.label = "[chan] {}".format(passphrase)
                    new_chan.is_setup = False
                new_chan.passphrase = passphrase
                new_chan.save()
                stage = "end"

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/join.html",
                           stage=stage,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/leave/<address>', methods=('GET', 'POST'))
def leave(address):
    status_msg = {"status_message": []}

    chan = Chan.query.filter(Chan.address == address).first()
    if chan:
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_MSG_PROC, to=60):
            try:
                for each_thread in chan.threads:
                    # Delete messages
                    for each_message in each_thread.messages:
                        delete_message_files(each_message.message_id)
                        each_message.delete()

                    # Delete threads
                    nexus.delete_thread(chan.address, each_thread.thread_hash)
                    each_thread.delete()

                # Delete chan
                nexus.leave_chan(chan.address)
                chan.delete()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(
                    "Deleted board {}".format(address))
                time.sleep(0.1)
            finally:
                lf.lock_release(config.LOCKFILE_MSG_PROC)

    if 'status_title' not in status_msg and status_msg['status_message']:
        status_msg['status_title'] = "Error"

    return render_template("pages/index.html",
                           status_msg=status_msg)
