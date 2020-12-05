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
from bitchan_flask import nexus
from database.models import Identity
from forms import forms_settings
from utils.files import LF
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_identities')

blueprint = Blueprint('routes_identities',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.route('/identities', methods=('GET', 'POST'))
def identities():
    form_identity = forms_settings.Identity()

    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_identity.create_identity.data:
            if not form_identity.label.data or not form_identity.passphrase.data:
                status_msg['status_message'].append("Label and passphrase required")

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        b64_passphrase = base64.b64encode(form_identity.passphrase.data.encode())
                        return_str = nexus._api.createDeterministicAddresses(b64_passphrase.decode())
                        if return_str:
                            if ("addresses" in return_str and
                                    len(return_str["addresses"]) == 1 and
                                    return_str["addresses"][0]):
                                new_ident = Identity()
                                new_ident.address = return_str["addresses"][0]
                                new_ident.label = form_identity.label.data
                                new_ident.passphrase_base64 = b64_passphrase
                                new_ident.save()

                                nexus._refresh_identities = True
                                nexus.signal_clear_inventory()

                                status_msg['status_title'] = "Success"
                                status_msg['status_message'].append(
                                    "Created identity {} with address {}.".format(
                                        form_identity.label.data,
                                        return_str["addresses"][0]))
                                status_msg['status_message'].append(
                                    "Give the system a few seconds for the change to take effect.")
                            else:
                                status_msg['status_message'].append(
                                    "Error creating Identity: {}".format(return_str))
                        else:
                            status_msg['status_message'].append("Error creating Identity")
                        time.sleep(0.1)
                    finally:
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
                    nexus._refresh_identities = True
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("Identity renamed.")
                    status_msg['status_message'].append(
                        "Give the system a few seconds for the change to take effect.")

        elif form_identity.delete.data:
            if not form_identity.address.data:
                status_msg['status_message'].append("Address required")

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        return_str = nexus._api.deleteAddress(form_identity.address.data)
                        if return_str == "success":
                            ident = Identity.query.filter(
                                Identity.address == form_identity.address.data).first()
                            if ident:
                                ident.delete()
                            nexus._refresh_identities = True
                            status_msg['status_title'] = "Success"
                            status_msg['status_message'].append("Identity deleted.")
                            status_msg['status_message'].append(
                                "Give the system a few seconds for the change to take effect.")
                        else:
                            status_msg['status_message'].append(
                                "Error deleting Identity: {}".format(return_str))
                        time.sleep(0.1)
                    finally:
                        lf.lock_release(config.LOCKFILE_API)

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_identities.identities"))

    return render_template("pages/identities.html",
                           form_identity=form_identity,
                           status_msg=status_msg)
