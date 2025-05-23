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
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import GlobalSettings
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from flask_routes.utils import rate_limit
from forms import forms_board
from utils.general import process_passphrase
from utils.general import set_clear_time_to_future
from utils.routes import allowed_access
from utils.routes import get_chan_passphrase
from utils.routes import get_logged_in_user_name
from utils.routes import has_permission
from utils.routes import page_dict
from utils.shared import add_mod_log_entry
from utils.shared import get_access

logger = logging.getLogger('bitchan.routes_list')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_list',
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


@blueprint.route('/lists')
@count_views
@rate_limit
def lists():
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    status_msg = {"status_message": []}

    return render_template("pages/lists.html",
                           status_msg=status_msg)


@blueprint.route('/list/<current_chan>', methods=('GET', 'POST'))
@count_views
@rate_limit
def list_chans(current_chan):
    allowed, allow_msg = allowed_access("can_view")
    if not allowed:
        return allow_msg

    chan = Chan.query.filter(Chan.address == current_chan).first()
    board_list_admin, _ = allowed_access("is_board_list_admin", board_address=current_chan)
    global_admin, _ = allowed_access("is_global_admin")

    if not chan or (not global_admin and not board_list_admin and chan.restricted):
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    try:
        from_list = daemon_com.get_from_list(current_chan)
    except:
        return render_template("pages/404-board.html",
                               board_address=current_chan)

    form_list = forms_board.List()
    form_set = forms_board.SetChan()

    board = {"current_chan": chan}
    status_msg = {"status_message": []}
    url = ""
    url_text = ""
    form_list_add = []

    try:
        this_chan_list = json.loads(chan.list)
    except:
        this_chan_list = {}

    if global_admin:
        chans = Chan.query.filter(and_(
            Chan.address != current_chan,
            Chan.address.notin_(this_chan_list))).order_by(
            Chan.type.asc(),
            Chan.label.asc()).all()
    else:
        chans = Chan.query.filter(and_(
            Chan.unlisted.is_(False),
            Chan.restricted.is_(False),
            Chan.address != current_chan,
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
        global_admin, allow_msg = allowed_access("is_global_admin")
        if not global_admin:
            return allow_msg

        join_bulk = None
        join = None
        delete = None

        for each_input in request.form:
            if each_input.startswith("join_"):
                join = each_input.split("_")[1]
                break
            elif each_input.startswith("delete_"):
                delete = each_input.split("_")[1]
                break
            elif each_input == "joinbulk":
                join_bulk = True
                break

        if form_set.set_pgp_passphrase_msg.data:
            global_admin, allow_msg = allowed_access("is_global_admin")
            if not global_admin:
                return allow_msg

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
            global_admin, allow_msg = allowed_access("is_global_admin")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not global_admin and not board_list_admin:
                return allow_msg

            chan = Chan.query.filter(
                Chan.address == current_chan).first()
            settings = GlobalSettings.query.first()
            if chan and ((settings.enable_kiosk_mode and (global_admin or board_list_admin)) or not settings.enable_kiosk_mode):
                if form_list.from_address.data:
                    chan.default_from_address = form_list.from_address.data
                else:
                    chan.default_from_address = None
                chan.save()

        # Modify list by adding/deleting a board or list
        elif form_list.add.data or delete:
            global_admin, allow_msg = allowed_access("is_global_admin")
            board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=current_chan)
            if not global_admin and not board_list_admin:
                return allow_msg

            address = None
            if form_list.add.data:
                address = form_list.address.data
            elif delete:
                address = delete

            chan_add = Chan.query.filter(and_(Chan.address == address)).first()

            list_mod = Chan.query.filter(and_(
                Chan.type == "list",
                Chan.address == current_chan)).first()
            if not list_mod:
                status_msg["status_message"].append("Invalid list to modify")
            elif form_list.add.data and not chan_add:
                status_msg["status_message"].append("Invalid board/list to add")
            else:
                try:
                    dict_list_addresses = json.loads(list_mod.list)
                except:
                    dict_list_addresses = {}

                try:
                    rules = json.loads(list_mod.rules)
                except:
                    rules = {}

                if form_list.add.data and address in dict_list_addresses:
                    status_msg["status_message"].append("Can't add address that's already on the list")

                if delete and address not in dict_list_addresses:
                    status_msg["status_message"].append("Can't delete address that's not on the list")

                if address == current_chan:
                    status_msg["status_message"].append("Cannot modify an address that's the same address as the list")

                if list_mod.access == "private":
                    if (sender_has_access(current_chan, "primary_addresses") or
                            sender_has_access(current_chan, "secondary_addresses")):
                        # Primary and secondary access can add or delete from lists
                        modify_access = True
                    elif (form_list.add.data and
                            sender_has_access(current_chan, "tertiary_addresses")):
                        # Tertiary access can add to private lists but not delete
                        modify_access = True
                    else:
                        # Everyone else is prohibited from adding/deleting from private lists
                        modify_access = False

                    if not modify_access:
                        status_msg["status_message"].append(
                            "Insufficient credentials to modify this list.")

                # If adding, check if the passphrase is valid
                if form_list.add.data:
                    errors, dict_chan_info = process_passphrase(chan_add.passphrase)
                    if not dict_chan_info:
                        status_msg['status_message'].append("Error parsing passphrase")
                        for error in errors:
                            status_msg['status_message'].append(error)

                    settings = GlobalSettings.query.first()
                    if (settings.enable_kiosk_mode and
                            chan.read_only and
                            not has_permission("is_global_admin") and
                            not has_permission("is_board_list_admin")):
                        status_msg['status_message'].append("Only Admins can add to a read-only list.")

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

                    user_name = get_logged_in_user_name()
                    admin_name = user_name if user_name else "LOCAL ADMIN"

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
                            "Added {} to the List".format(address))

                        add_mod_log_entry(
                            f"Locally Added to List: {address}",
                            board_address=current_chan, user_from=admin_name)

                    elif delete:
                        dict_list_addresses.pop(address)
                        status_msg["status_message"].append(
                            "Deleted {} from the List".format(address))

                        add_mod_log_entry(
                            f"Locally Deleted from List: {address}",
                            board_address=current_chan, user_from=admin_name)

                    # Set the time the list changed
                    if list_mod.list != json.dumps(dict_list_addresses):
                        list_mod.list_timestamp_changed = time.time()

                    list_mod.list = json.dumps(dict_list_addresses)
                    list_mod.list_send = True
                    list_mod.save()

                    logger.info("Instructing send_lists() to run in {} minutes".format(
                        config.LIST_ADD_WAIT_TO_SEND_SEC / 60))
                    daemon_com.update_timer_send_lists(config.LIST_ADD_WAIT_TO_SEND_SEC)

        elif join:
            # Join from list
            global_admin, allow_msg = allowed_access("is_global_admin")
            if not global_admin:
                return allow_msg

            return redirect(url_for("routes_list.join_from_list",
                                    list_address=current_chan,
                                    join_address=join))

        elif join_bulk:
            # Bulk join from list
            global_admin, allow_msg = allowed_access("is_global_admin")
            if not global_admin:
                return allow_msg

            join_bulk_list = []

            for each_input in request.form:
                if each_input.startswith("joinbulk_"):
                    join_bulk_list.append(each_input.split("_")[1])

            if not join_bulk_list:
                status_msg['status_title'] = "Error"
                status_msg["status_message"].append("You must check at least one list entry to join")
            else:
                daemon_com.bulk_join(current_chan, join_bulk_list)

            status_msg['status_title'] = "Success"
            status_msg["status_message"].append(
                "Addresses being joined in the background. "
                "Give the process time to complete.")

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

    passphrase_base64, passphrase_base64_with_pgp = get_chan_passphrase(current_chan, is_board=False)

    return render_template("pages/list.html",
                           board=board,
                           chan_lists=chan_lists,
                           chan_posts=chan_posts,
                           form_list=form_list,
                           form_list_add=form_list_add,
                           from_list=from_list,
                           passphrase_base64=passphrase_base64,
                           passphrase_base64_with_pgp=passphrase_base64_with_pgp,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/list/join/<list_address>/<join_address>', methods=('GET', 'POST'))
@count_views
def join_from_list(list_address, join_address):
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

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

        if "%" in passphrase:  # TODO: Remove check when Bitmessage fixes this issue
            status_msg['status_message'].append('Chan passphrase cannot contain: "%"')

        errors, dict_chan_info = process_passphrase(passphrase)
        if not dict_chan_info:
            status_msg['status_message'].append("Error parsing passphrase")
            for error in errors:
                status_msg['status_message'].append(error)

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_join.join.data:
            # Join from list
            if dict_chan_info and passphrase and not status_msg['status_message']:
                url = None
                url_text = None

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

                result = daemon_com.join_chan(passphrase, clear_inventory=form_join.resync.data)
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
                           join_address=join_address,
                           rules=rules,
                           status_msg=status_msg,
                           url=url,
                           url_text=url_text)


@blueprint.route('/list_bulk_add/<list_address>', methods=('GET', 'POST'))
@count_views
def list_bulk_add(list_address):
    global_admin, allow_msg = allowed_access("is_global_admin")
    board_list_admin, allow_msg = allowed_access("is_board_list_admin", board_address=list_address)
    if not global_admin and not board_list_admin:
        return allow_msg

    chan = Chan.query.filter(Chan.address == list_address).first()
    global_admin, _ = allowed_access("is_global_admin")

    if not chan or (not global_admin and chan.restricted):
        return render_template("pages/404-board.html",
                               board_address=list_address)

    form_list = forms_board.List()

    try:
        from_list = daemon_com.get_from_list(list_address)
    except:
        return render_template("pages/404-board.html",
                               board_address=list_address)

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
        add_bulk_list = []

        for each_input in request.form:
            if each_input == "add_bulk":
                for each_input_ in request.form:
                    if each_input_.startswith("add_bulk_"):
                        add_bulk_list.append(each_input_.split("_")[2])
                break

        # Add boards or lists to a list in bulk
        if form_list.add_bulk.data and add_bulk_list:
            if not global_admin and not board_list_admin:
                return allow_msg

            mod_list = Chan.query.filter(and_(
                Chan.type == "list",
                Chan.address == list_address)).first()

            dict_list_addresses = {}
            rules = {}

            if not mod_list:
                status_msg["status_message"].append("Invalid list to modify")
            else:
                list_unlisted = []
                list_restricted = []

                if form_list.from_address.data:
                    mod_list.default_from_address = form_list.from_address.data

                try:
                    dict_list_addresses = json.loads(mod_list.list)
                except:
                    pass

                try:
                    rules = json.loads(mod_list.rules)
                except:
                    pass

                for each_address in add_bulk_list:
                    chan_add = Chan.query.filter(Chan.address == each_address).first()
                    if chan_add.unlisted and not form_list.add_unlisted.data:
                        list_unlisted.append(chan_add)
                        continue

                    if chan_add.restricted and not form_list.add_restricted.data:
                        list_restricted.append(chan_add)
                        continue

                    if not chan_add:
                        status_msg["status_message"].append(
                            "Can't find board/list to add: {}".format(each_address))
                        continue

                    if form_list.add.data and each_address in dict_list_addresses:
                        status_msg["status_message"].append(
                            "Can't add address that's already on the list: {}".format(each_address))

                    if each_address == list_address:
                        status_msg["status_message"].append(
                            "Cannot modify an address that's the same address as the list: {}".format(each_address))

                    def sender_has_access(address, address_type):
                        access = get_access(address)
                        for address in daemon_com.get_identities():
                            if address in access[address_type]:
                                return True
                        for address in daemon_com.get_all_chans():
                            if address in access[address_type]:
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

                    errors, dict_chan_info = process_passphrase(chan_add.passphrase)
                    if not dict_chan_info:
                        status_msg['status_message'].append(
                            "Error parsing passphrase for address {}".format(each_address))

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

                    dict_list_addresses[chan_add.address] = {
                        "passphrase": chan_add.passphrase
                    }
                    if "allow_list_pgp_metadata" in rules and rules["allow_list_pgp_metadata"]:
                        if dict_chan_info["type"] in ["board", "list"]:
                            dict_list_addresses[chan_add.address]["pgp_passphrase_msg"] = chan_add.pgp_passphrase_msg
                        if dict_chan_info["type"] == "board":
                            dict_list_addresses[chan_add.address]["pgp_passphrase_attach"] = chan_add.pgp_passphrase_attach
                            dict_list_addresses[chan_add.address]["pgp_passphrase_steg"] = chan_add.pgp_passphrase_steg

                if list_unlisted:
                    status_msg["status_message"].append(
                        f'Unlisted board/list detected. Cannot add unless "Add Unlisted" is selected.')
                    for each_unlisted in list_unlisted:
                        status_msg["status_message"].append(
                            f'Unlisted: /{each_unlisted.label}/ {each_unlisted.address}')

                if list_restricted:
                    status_msg["status_message"].append(
                        f'Restricted board/list detected. Cannot add unless "Add Restricted" is selected.')
                    for each_restricted in list_restricted:
                        status_msg["status_message"].append(
                            f'Restricted: /{each_restricted.label}/ {each_restricted.address}')

            if not status_msg['status_message']:
                status_msg["status_message"].append(
                    "Added to the List: {}".format(", ".join(add_bulk_list)))
                status_msg['status_title'] = "Success"
                url = "/list/{}".format(list_address)
                url_text = "Return to List"

                # Set the time the list changed
                if mod_list.list != json.dumps(dict_list_addresses):
                    mod_list.list_timestamp_changed = time.time()

                mod_list.list = json.dumps(dict_list_addresses)
                mod_list.list_send = True

                mod_list.save()

                add_mod_log_entry(
                    f'Locally Added to List: {", ".join(add_bulk_list)}',
                    board_address=list_address)

                logger.info("Instructing send_lists() to run in {} minutes".format(
                    config.LIST_ADD_WAIT_TO_SEND_SEC / 60))
                daemon_com.update_timer_send_lists(config.LIST_ADD_WAIT_TO_SEND_SEC)

            if 'status_title' not in status_msg and status_msg['status_message']:
                status_msg['status_title'] = "Error"

            return render_template("pages/alert.html",
                                   board=list_address,
                                   status_msg=status_msg,
                                   url=url,
                                   url_text=url_text)

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
        json.dumps(dict_join).encode()).decode()
    if chan.pgp_passphrase_msg != config.PGP_PASSPHRASE_MSG:
        dict_join["pgp_msg"] = chan.pgp_passphrase_msg
    passphrase_base64_with_pgp = base64.b64encode(
        json.dumps(dict_join).encode()).decode()

    return render_template("pages/list_bulk_add.html",
                           board=board,
                           chan_lists=chan_lists,
                           chan_posts=chan_posts,
                           form_list=form_list,
                           form_list_add=form_list_add,
                           from_list=from_list,
                           passphrase_base64=passphrase_base64,
                           passphrase_base64_with_pgp=passphrase_base64_with_pgp,
                           status_msg=status_msg,
                           table_chan=Chan,
                           url=url,
                           url_text=url_text)


def sender_has_access(address_, address_type):
    access = get_access(address_)
    for each_address in daemon_com.get_identities():
        if each_address in access[address_type]:
            return True
    for each_address in daemon_com.get_all_chans():
        if each_address in access[address_type]:
            return True
