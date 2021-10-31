import base64
import logging
import time

from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

import config
from bitchan_client import DaemonCom
from database.models import GlobalSettings
from database.models import Identity
from forms import forms_board
from forms import forms_settings
from utils.files import LF
from utils.gateway import api
from utils.general import process_passphrase
from utils.routes import allowed_access
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_identities')
daemon_com = DaemonCom()

blueprint = Blueprint('routes_identities',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.before_request
def before_view():
    if (GlobalSettings.query.first().enable_verification and
            ("verified" not in session or not session["verified"])):
        session["verified_msg"] = "You are not verified"
        return redirect(url_for('routes_verify.verify_wait'))
    session["verified_msg"] = "You are verified"


@blueprint.route('/identities', methods=('GET', 'POST'))
def identities():
    global_admin, allow_msg = allowed_access(
        check_is_global_admin=True)
    if not global_admin:
        return allow_msg

    form_identity = forms_settings.Identity()
    form_confirm = forms_board.Confirm()

    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_identity.create_identity.data:
            if not form_identity.label.data or not form_identity.passphrase.data:
                status_msg['status_message'].append("Label and passphrase required")

            errors, dict_chan_info = process_passphrase(form_identity.passphrase.data)
            if dict_chan_info:
                status_msg['status_message'].append("Cannot create an Identity with board/list passphrase")

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                    try:
                        b64_passphrase = base64.b64encode(form_identity.passphrase.data.encode())
                        return_str = api.createDeterministicAddresses(b64_passphrase.decode())
                        if return_str:
                            if ("addresses" in return_str and
                                    len(return_str["addresses"]) == 1 and
                                    return_str["addresses"][0]):

                                ident = Identity.query.filter(
                                    Identity.address == return_str["addresses"][0]).first()
                                if ident:
                                    logger.info(
                                        "Creating identity that already exists in the database. "
                                        "Skipping adding entry")
                                else:
                                    new_ident = Identity()
                                    new_ident.address = return_str["addresses"][0]
                                    new_ident.label = form_identity.label.data
                                    new_ident.passphrase_base64 = b64_passphrase
                                    new_ident.save()

                                daemon_com.refresh_identities()

                                if form_identity.resync.data:
                                    daemon_com.signal_clear_inventory()

                                status_msg['status_title'] = "Success"
                                status_msg['status_message'].append(
                                    "Created identity {} with address {}.".format(
                                        form_identity.label.data, return_str["addresses"][0]))
                                status_msg['status_message'].append(
                                    "Give the system a few seconds for the change to take effect.")
                            else:
                                status_msg['status_message'].append(
                                    "Error creating Identity: {}".format(return_str))
                        else:
                            status_msg['status_message'].append("Error creating Identity")
                    finally:
                        time.sleep(config.API_PAUSE)
                        lf.lock_release(config.LOCKFILE_API)

        elif form_identity.rename.data:
            if not form_identity.ident_label.data or not form_identity.address.data:
                status_msg['status_message'].append("Label and address required")

            if not status_msg['status_message']:
                ident = Identity.query.filter(
                    Identity.address == form_identity.address.data).first()
                if ident:
                    ident.label = form_identity.ident_label.data
                    ident.save()
                    daemon_com.refresh_identities()
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("Identity renamed.")
                    status_msg['status_message'].append(
                        "Give the system a few seconds for the change to take effect.")

        elif form_identity.delete.data:
            ident = None
            if not form_identity.address.data:
                status_msg['status_message'].append("Address required")
            else:
                ident = Identity.query.filter(
                    Identity.address == form_identity.address.data).first()

            if not form_confirm.confirm.data:
                return render_template("pages/confirm.html",
                                       action="delete_identity",
                                       ident=ident)

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=config.API_LOCK_TIMEOUT):
                    try:
                        return_str = api.deleteAddress(form_identity.address.data)
                        if return_str == "success":
                            if ident:
                                ident.delete()
                            daemon_com.refresh_identities()
                            status_msg['status_title'] = "Success"
                            status_msg['status_message'].append("Identity deleted.")
                            status_msg['status_message'].append(
                                "Give the system a few seconds for the change to take effect.")
                        else:
                            status_msg['status_message'].append(
                                "Error deleting Identity: {}".format(return_str))
                    finally:
                        time.sleep(config.API_PAUSE)
                        lf.lock_release(config.LOCKFILE_API)

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_identities.identities"))

    return render_template("pages/identities.html",
                           form_identity=form_identity,
                           status_msg=status_msg)
