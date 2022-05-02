import base64
import logging
import os
import shutil

import gnupg
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_settings
from utils.routes import allowed_access
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_pgp')

blueprint = Blueprint('routes_pgp',
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


@blueprint.route('/pgp', methods=('GET', 'POST'))
@count_views
def pgp():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    form_pgp = forms_settings.PGP()

    status_msg = session.get("status_msg", {"status_message": []})

    gnupg_home = "/usr/local/bitchan/gnupg"

    if not os.path.exists(gnupg_home):
        os.mkdir(gnupg_home)

    gpg = gnupg.GPG(gnupghome=gnupg_home)

    private_keys = gpg.list_keys(True)
    public_keys = gpg.list_keys()

    private_key_ids = []
    for each_key in private_keys:
        private_key_ids.append(each_key["keyid"])

    public_key_ids = []
    for each_key in public_keys:
        if each_key["keyid"] not in private_key_ids:
            public_key_ids.append(each_key["keyid"])

    exported_public_keys = {}
    for each_pub_key in public_keys:
        exported_public_keys[each_pub_key["keyid"]] = gpg.export_keys(each_pub_key["keyid"])

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_pgp.create_master_key.data:
            key_type = form_pgp.key_type_length.data.split(",")[0]
            key_length = int(form_pgp.key_type_length.data.split(",")[1])

            input_data = gpg.gen_key_input(
                key_type=key_type,
                key_length=key_length,
                key_usage='encrypt, sign',
                name_comment=form_pgp.comment.data,
                expire_date=0,
                name_real=form_pgp.name.data,
                name_email=form_pgp.email.data,
                passphrase=form_pgp.passphrase.data)
            key = gpg.gen_key(input_data)

            status_msg['status_message'].append("PGP key pair created: {}".format(key.fingerprint))
            status_msg['status_title'] = "Success"

        elif form_pgp.delete_all.data:
            shutil.rmtree(gnupg_home)
            # for each_key in gpg.list_keys(True):
            #     status_msg['status_message'].append("Delete Private Key {}: {}".format(
            #         each_key["fingerprint"],
            #         gpg.delete_keys(fingerprints=each_key["fingerprint"],
            #                         secret=True,
            #                         passphrase="PASS").status))
            # for each_key in gpg.list_keys():
            #     status_msg['status_message'].append("Delete Public Key {}: {}".format(
            #         each_key["fingerprint"],
            #         gpg.delete_keys(fingerprints=each_key["fingerprint"]).status))
            status_msg['status_message'].append("Deleted all keys")
            status_msg['status_title'] = "Success"

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_pgp.pgp"))

    return render_template("pages/pgp.html",
                           exported_public_keys=exported_public_keys,
                           private_keys=private_keys,
                           public_key_ids=public_key_ids,
                           public_keys=public_keys,
                           status_msg=status_msg)
