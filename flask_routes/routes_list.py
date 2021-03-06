import base64
import json
import logging
import time

from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint
from sqlalchemy import and_

import config
from bitchan_flask import nexus
from database.models import Chan
from forms import forms_board
from utils.general import process_passphrase
from utils.general import set_clear_time_to_future
from utils.routes import get_access
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_list')

blueprint = Blueprint('routes_list',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.route('/list/<list_address>', methods=('GET', 'POST'))
def list_chans(list_address):
    form_join = forms_board.Join()
    form_list = forms_board.List()
    form_set = forms_board.SetChan()

    chan = Chan.query.filter(Chan.address == list_address).first()
    if not chan:
        return render_template("pages/404-board.html",
                               board_address=list_address)

    try:
        from_list = nexus.get_from_list(list_address)
    except:
        return render_template("pages/404-board.html",
                               board_address=list_address)

    board = {"current_chan": chan}
    status_msg = {"status_message": []}
    url = ""
    url_text = ""
    form_list_add = []

    identities = nexus.get_identities()
    subscriptions = nexus.get_subscriptions()
    identities_subscriptions = {}
    for each_address, each_data in identities.items():
        if each_address in subscriptions:
            identities_subscriptions[each_address] = each_data

    try:
        this_chan_list = json.loads(chan.list)
    except:
        this_chan_list = {}

    chans = Chan.query.filter(and_(
        Chan.address != list_address,
        Chan.address.notin_(this_chan_list))).order_by(
            Chan.type.asc(),
            Chan.label.asc()).all()
    for each_chan in chans:
        str_select = ""
        if each_chan.type == "board":
            str_select += "Board: "
        elif each_chan.type == "list":
            str_select += "List: "
        str_select += each_chan.label
        if each_chan.access == "public":
            str_select += " [Public] "
        elif each_chan.access == "private":
            str_select += " [Private] "
        str_select += "({}...{})".format(
            each_chan.address[:9], each_chan.address[-6:])
        form_list_add.append((each_chan.address, str_select))

    if request.method == 'GET':
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
                status_msg['status_message'].append("Changed PGP Passphrase.")

        # set default/preferred address to update list
        elif form_list.save_from.data:
            chan = Chan.query.filter(
                Chan.address == list_address).first()
            if chan:
                if form_list.from_address.data:
                    chan.default_from_address = form_list.from_address.data
                else:
                    chan.default_from_address = None
                chan.save()

        # Add/delete a board or list to/from a list
        elif form_list.add.data or form_list.delete.data:
            chan_add = Chan.query.filter(
                Chan.address == form_list.address.data).first()
            if form_list.add.data and not chan_add:
                status_msg["status_message"].append("Invalid list to modify")
            else:
                mod_list = Chan.query.filter(and_(
                    Chan.type == "list",
                    Chan.address == list_address)).first()

                try:
                    dict_list_addresses = json.loads(mod_list.list)
                except:
                    dict_list_addresses = {}

                try:
                    rules = json.loads(mod_list.rules)
                except:
                    rules = {}

                if form_list.add.data and form_list.address.data in dict_list_addresses:
                    status_msg["status_message"].append("Can't add address that's already on the list")

                if form_list.delete.data and form_list.address.data not in dict_list_addresses:
                    status_msg["status_message"].append("Can't delete address that's not on the list")

                if form_list.address.data == list_address:
                    status_msg["status_message"].append("Cannot modify an address that's the same address as the list")

                def sender_has_access(address, address_type):
                    access = get_access(address)
                    for each_address in nexus.get_identities():
                        if each_address in access[address_type]:
                            return True
                    for each_address in nexus.get_all_chans():
                        if each_address in access[address_type]:
                            return True

                if mod_list.access == "private":
                    if (sender_has_access(list_address, "primary_addresses") or
                            sender_has_access(list_address, "secondary_addresses")):
                        # Primary and secondary access can add or delete from lists
                        modify_access = True
                    elif (form_list.add.data and
                            sender_has_access(list_address, "tertiary_addresses")):
                        # Only allow tertiary access to add to private lists
                        modify_access = True
                    else:
                        # Everyone else is prohibited from adding/deleting from private lists
                        modify_access = False

                    if not modify_access:
                        status_msg["status_message"].append(
                            "Cannot modify this list if you are not the owner.")

                # Check if passphrase is valid
                if form_list.add.data:
                    errors, dict_chan_info = process_passphrase(chan_add.passphrase)
                    if not dict_chan_info:
                        status_msg['status_message'].append("Error parsing passphrase")

                    if "allow_list_pgp_metadata" in rules and rules["allow_list_pgp_metadata"]:
                        if dict_chan_info["type"] in ["board", "list"]:
                            if len(chan_add.pgp_passphrase_msg) > config.PGP_PASSPHRASE_LENGTH:
                                status_msg['status_message'].append(
                                    "Message PGP Passphrase longer than {}: {}".format(
                                        config.PGP_PASSPHRASE_LENGTH, len(chan_add.pgp_passphrase_msg)))
                            elif not chan_add.pgp_passphrase_msg:
                                status_msg['status_message'].append(
                                    "Message PGP Passphrase of the entry you tried to add cannot be empty")
                        if dict_chan_info["type"] == "board":
                            if len(chan_add.pgp_passphrase_attach) > config.PGP_PASSPHRASE_LENGTH:
                                status_msg['status_message'].append(
                                    "Attachment PGP Passphrase longer than {}: {}".format(
                                        config.PGP_PASSPHRASE_LENGTH, len(chan_add.pgp_passphrase_attach)))
                            elif not chan_add.pgp_passphrase_attach:
                                status_msg['status_message'].append(
                                    "Attachment PGP Passphrase of the entry you tried to add cannot be empty")
                            if len(chan_add.pgp_passphrase_steg) > config.PGP_PASSPHRASE_LENGTH:
                                status_msg['status_message'].append(
                                    "Steg PGP Passphrase longer than {}: {}".format(
                                        config.PGP_PASSPHRASE_LENGTH, len(chan_add.pgp_passphrase_steg)))
                            elif not chan_add.pgp_passphrase_steg:
                                status_msg['status_message'].append(
                                    "Steg PGP Passphrase of the entry you tried to add cannot be empty")

                if not status_msg['status_message']:
                    status_msg['status_title'] = "Success"

                    if form_list.add.data:
                        dict_list_addresses[chan_add.address] = {
                            "passphrase": chan_add.passphrase
                        }
                        if "allow_list_pgp_metadata" in rules and rules["allow_list_pgp_metadata"]:
                            if dict_chan_info["type"] in ["board", "list"]:
                                dict_list_addresses[chan_add.address]["pgp_passphrase_msg"] = chan_add.pgp_passphrase_msg
                            if dict_chan_info["type"] == "board":
                                dict_list_addresses[chan_add.address]["pgp_passphrase_attach"] = chan_add.pgp_passphrase_attach
                                dict_list_addresses[chan_add.address]["pgp_passphrase_steg"] = chan_add.pgp_passphrase_steg
                        status_msg["status_message"].append(
                            "Added {} to the List".format(form_list.address.data))

                    elif form_list.delete.data:
                        dict_list_addresses.pop(form_list.address.data, None)
                        status_msg["status_message"].append(
                            "Deleted {} from the List".format(form_list.address.data))

                    # Set the time the list changed
                    if mod_list.list != json.dumps(dict_list_addresses):
                        mod_list.list_timestamp_changed = time.time()

                    mod_list.list = json.dumps(dict_list_addresses)
                    mod_list.list_send = True
                    mod_list.save()

                    time_to_send = 60 * 1
                    logger.info("Instructing send_lists() to run in {} minutes".format(time_to_send / 60))
                    nexus.timer_send_lists = time.time() + time_to_send

        elif form_join.join.data:
            # Join from list
            return redirect(url_for("routes_list.join_from_list",
                                    list_address=list_address,
                                    join_address=form_join.address.data))

        time.sleep(3)

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    chan_posts = Chan.query.filter(Chan.type == "board").all()

    chan_lists = {}
    for each_chan in Chan.query.filter(Chan.type == "list").all():
        chan_lists[each_chan.address] = {
            "passphrase": each_chan.passphrase,
            "list": json.loads(each_chan.list)
        }
        if len(each_chan.label) > config.LABEL_LENGTH:
            chan_lists[each_chan.address]["label_short"] = each_chan.label[:config.LABEL_LENGTH]
        else:
            chan_lists[each_chan.address]["label_short"] = each_chan.label

    chan = Chan.query.filter(Chan.address == list_address).first()
    dict_join = {
        "passphrase": chan.passphrase
    }
    passphrase_base64 = base64.b64encode(
        json.dumps(dict_join).encode()).decode().replace("/", "&")
    if chan.pgp_passphrase_msg != config.PGP_PASSPHRASE_MSG:
        dict_join["pgp_msg"] = chan.pgp_passphrase_msg
    passphrase_base64_with_pgp = base64.b64encode(
        json.dumps(dict_join).encode()).decode().replace("/", "&")

    return render_template("pages/list.html",
                           board=board,
                           chan_lists=chan_lists,
                           chan_posts=chan_posts,
                           form_list=form_list,
                           form_list_add=form_list_add,
                           from_list=from_list,
                           identities_subscriptions=identities_subscriptions,
                           passphrase_base64=passphrase_base64,
                           passphrase_base64_with_pgp=passphrase_base64_with_pgp,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/list/join/<list_address>/<join_address>', methods=('GET', 'POST'))
def join_from_list(list_address, join_address):
    form_join = forms_board.Join()

    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    chan_list = Chan.query.filter(and_(
        Chan.type == "list",
        Chan.address == list_address)).first()
    try:
        dict_list_addresses = json.loads(chan_list.list)
    except:
        dict_list_addresses = {}
    try:
        rules = json.loads(chan_list.rules)
    except:
        rules = {}

    if join_address not in dict_list_addresses:
        status_msg['status_message'].append("Address to join not in list")

    dict_chan_info = {}
    passphrase = ""
    if "passphrase" in dict_list_addresses[join_address]:
        passphrase = dict_list_addresses[join_address]["passphrase"]

        if Chan.query.filter(Chan.passphrase == passphrase).count():
            status_msg['status_message'].append("Chan already in database")

        errors, dict_chan_info = process_passphrase(passphrase)
        if not dict_chan_info:
            status_msg['status_message'].append("Error parsing passphrase")
            for error in errors:
                status_msg['status_message'].append(error)

    identities = nexus.get_identities()
    subscriptions = nexus.get_subscriptions()
    identities_subscriptions = {}
    for each_address, each_data in identities.items():
        if each_address in subscriptions:
            identities_subscriptions[each_address] = each_data

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_join.join.data:
            # Join from list
            if dict_chan_info and passphrase and not status_msg['status_message']:
                if dict_chan_info["rules"]:
                    dict_chan_info["rules"] = set_clear_time_to_future(dict_chan_info["rules"])

                new_chan = Chan()
                new_chan.passphrase = passphrase
                new_chan.access = dict_chan_info["access"]
                new_chan.type = dict_chan_info["type"]
                new_chan.primary_addresses = json.dumps(dict_chan_info["primary_addresses"])
                new_chan.secondary_addresses = json.dumps(dict_chan_info["secondary_addresses"])
                new_chan.tertiary_addresses = json.dumps(dict_chan_info["tertiary_addresses"])
                new_chan.rules = json.dumps(dict_chan_info["rules"])
                new_chan.label = dict_chan_info["label"]
                new_chan.description = dict_chan_info["description"]

                if form_join.pgp_passphrase_msg.data:
                    new_chan.pgp_passphrase_msg = form_join.pgp_passphrase_msg.data
                else:
                    new_chan.pgp_passphrase_msg = config.PGP_PASSPHRASE_MSG
                if new_chan.type == "board":
                    if form_join.pgp_passphrase_steg.data:
                        new_chan.pgp_passphrase_steg = form_join.pgp_passphrase_steg.data
                    else:
                        new_chan.pgp_passphrase_steg = config.PGP_PASSPHRASE_STEG
                    if form_join.pgp_passphrase_attach.data:
                        new_chan.pgp_passphrase_attach = form_join.pgp_passphrase_attach.data
                    else:
                        new_chan.pgp_passphrase_attach = config.PGP_PASSPHRASE_ATTACH

                result = nexus.join_chan(passphrase, clear_inventory=form_join.resync.data)
                if result.startswith("BM-"):
                    new_chan.address = result
                    new_chan.is_setup = True
                    if new_chan.type == "board":
                        status_msg['status_message'].append("Joined board")
                        url = "/board/{}/1".format(result)
                        url_text = "{} - {}".format(new_chan.label, result)
                    elif new_chan.type == "list":
                        status_msg['status_message'].append("Joined list")
                        url = "/list/{}".format(result)
                        url_text = "{} - {}".format(new_chan.label, result)
                else:
                    status_msg['status_message'].append("Could not join at this time: {}".format(result))
                    new_chan.address = None
                    new_chan.is_setup = False

                if 'status_title' not in status_msg:
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append(result)
                    new_chan.save()

                return render_template("pages/alert.html",
                                       board=list_address,
                                       status_msg=status_msg,
                                       url=url,
                                       url_text=url_text)

        time.sleep(3)

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

    return render_template("pages/list_join.html",
                           dict_chan_info=dict_chan_info,
                           dict_list_addresses=dict_list_addresses,
                           form_join=form_join,
                           identities_subscriptions=identities_subscriptions,
                           join_address=join_address,
                           rules=rules,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)
