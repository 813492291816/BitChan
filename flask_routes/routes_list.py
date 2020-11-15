import json
import logging
import time

from flask import render_template
from flask import request
from flask import session
from flask.blueprints import Blueprint
from sqlalchemy import and_

import config
from bitchan_flask import nexus
from database.models import Chan
from flask_extensions import db
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

    identities = nexus.get_identities()
    subscriptions = nexus.get_subscriptions()
    identities_subscriptions = {}
    for each_address, each_data in identities.items():
        if each_address in subscriptions:
            identities_subscriptions[each_address] = each_data

    chan = Chan.query.filter(Chan.address == list_address).first()
    board = {"current_chan": chan}
    status_msg = {"status_message": []}
    url = ""
    url_text = ""

    form_list_add = []

    try:
        this_chan_list = json.loads(chan.list)
    except:
        this_chan_list = {}

    chans = Chan.query.filter(and_(
        Chan.address != list_address,
        Chan.address not in this_chan_list)).order_by(
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
        str_select += "({})".format(each_chan.address)
        form_list_add.append((each_chan.address, str_select))

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        # Add/delete a board or list to/from a list
        if form_list.add.data or form_list.delete.data:
            chan_add = Chan.query.filter(
                Chan.address == form_list.address.data).first()
            if not chan_add:
                status_msg["status_message"].append("Invalid list to modify")
            else:
                mod_list = Chan.query.filter(and_(
                    Chan.type == "list",
                    Chan.address == list_address)).first()
                try:
                    dict_list_addresses = json.loads(mod_list.list)
                except:
                    dict_list_addresses = {}

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

                if not status_msg['status_message']:
                    status_msg['status_title'] = "Success"

                    if form_list.add.data:
                        chan_mod = Chan.query.filter(
                            Chan.address == form_list.address.data).first()
                        dict_list_addresses[chan_mod.address] = {
                            "passphrase": chan_mod.passphrase
                        }
                        status_msg["status_message"].append(
                            "Added {} to the List".format(form_list.address.data))
                    elif form_list.delete.data:
                        dict_list_addresses.pop(form_list.address.data, None)
                        status_msg["status_message"].append(
                            "Deleted {} from the List".format(form_list.address.data))

                    mod_list.list = json.dumps(dict_list_addresses)
                    mod_list.list_send = True
                    db.session.commit()

                    time_to_send = 60 * 10
                    logger.info("Instructing send_lists() to run in {} minutes".format(time_to_send / 60))
                    nexus.timer_send_lists = time.time() + time_to_send

        elif form_join.join.data:
            # Join from list
            chan_list = Chan.query.filter(and_(
                Chan.type == "list",
                Chan.address == list_address)).first()
            try:
                dict_list_addresses = json.loads(chan_list.list)
            except:
                dict_list_addresses = {}

            if form_join.address.data not in dict_list_addresses:
                logger.error("Address to join not in list")
                return

            dict_chan_info = {}
            passphrase = ""
            if "passphrase" in dict_list_addresses[form_join.address.data]:
                passphrase = dict_list_addresses[form_join.address.data]["passphrase"]

                if Chan.query.filter(Chan.passphrase == passphrase).count():
                    status_msg['status_message'].append("Chan already in database")

                errors, dict_chan_info = process_passphrase(passphrase)
                if not dict_chan_info:
                    status_msg['status_message'].append("Error parsing passphrase")
                    for error in errors:
                        status_msg['status_message'].append(error)

                for each_word in config.RESTRICTED_WORDS:
                    if each_word in dict_chan_info["label"].lower():
                        status_msg['status_message'].append(
                            "bitchan is a restricted word for labels")

            if dict_chan_info and passphrase and not status_msg['status_message']:
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
                new_chan.rules = json.dumps(dict_chan_info["rules"])
                new_chan.description = dict_chan_info["description"]

                if result.startswith("BM-"):
                    new_chan.address = result
                    new_chan.label = dict_chan_info["label"]
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
                    status_msg['status_message'].append(
                        "Chan creation queued. Label set temporarily to passphrase.")
                    new_chan.address = None
                    new_chan.label = "[chan] {}".format(passphrase)
                    new_chan.is_setup = False
                new_chan.save()

                status_msg['status_title'] = "Success"
                status_msg['status_message'].append(result)

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

    return render_template("pages/list.html",
                           board=board,
                           chan_lists=chan_lists,
                           chan_posts=chan_posts,
                           form_list=form_list,
                           form_list_add=form_list_add,
                           identities_subscriptions=identities_subscriptions,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)
