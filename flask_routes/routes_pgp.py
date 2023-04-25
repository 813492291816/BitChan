import base64
import datetime
import logging
import subprocess
import time
from threading import Thread

import gnupg
from flask import redirect
from flask import render_template
from flask import request
from flask import send_file
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

from config import GPG_DIR
from database.models import PGP
from flask_routes.utils import count_views
from flask_routes.utils import is_verified
from forms import forms_pgp
from utils.files import delete_file
from utils.files import delete_files_recursive
from utils.general import get_random_alphanumeric_string
from utils.gpg import delete_public_key
from utils.gpg import ensure_gpg_dir_exists
from utils.gpg import get_all_key_information
from utils.gpg import get_all_keyrings
from utils.gpg import get_key_id
from utils.gpg import import_key
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


@blueprint.route('/gpg', methods=('GET', 'POST'))
@count_views
def gpg_page():
    global_admin, allow_msg = allowed_access("is_global_admin")
    if not global_admin:
        return allow_msg

    private_key = {}

    form_pgp = forms_pgp.PGP()
    form_pgp_add = forms_pgp.PGPAddKey()
    form_pgp_mod = forms_pgp.PGPMod()
    form_pgp_ie = forms_pgp.PGPImportExport()

    status_msg = session.get("status_msg", {"status_message": []})

    ensure_gpg_dir_exists()

    (public_keys,
     private_keys,
     private_key_ids,
     public_key_ids,
     exported_public_keys) = get_all_key_information()

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    # Show private key block upon request
    elif request.method == 'POST' and form_pgp_mod.show_private_key_block.data:
        key = PGP.query.filter(PGP.fingerprint == form_pgp_mod.fingerprint.data).first()
        if key:
            gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=key.keyring_name)
            private_key[form_pgp_mod.fingerprint.data] = gpg.export_keys(
                form_pgp_mod.fingerprint.data, secret=True, passphrase=key.passphrase)
            status_msg['status_message'].append(f"Private Key shown. Open the accordion to view it.")
            status_msg['status_title'] = "Success"

    elif request.method == 'POST':
        if form_pgp_ie.export_keyring.data:
            date_now = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            filename = 'bitchan_gpg_keyring_export_{}.tar'.format(date_now)
            save_path = '/tmp/{}'.format(filename)

            def delete_backup_file(f_name):
                time.sleep(120)
                delete_file(f_name)

            try:
                cmd = f'tar -cvf {save_path} -C {GPG_DIR} .'
                output = subprocess.check_output(cmd, shell=True, text=True)
                logger.debug("Command: {}, Output: {}".format(cmd, output))

                thread_download = Thread(target=delete_backup_file, args=(filename,))
                thread_download.start()

                return send_file(save_path, mimetype='application/x-tar')
            except Exception as err:
                status_msg['status_message'].append(
                    "Couldn't generate keyring export archive: {}".format(err))
                logger.exception("Couldn't generate keyring export archive")

        elif form_pgp_ie.import_keyring.data:
            if not form_pgp_ie.keyring_archive.data:
                status_msg['status_message'].append(
                    f"A passphrase needs ot be provided to delete a private key")
            else:
                try:
                    delete_files_recursive(GPG_DIR)
                    ensure_gpg_dir_exists()
                    for each_pgp in PGP.query.all():
                        each_pgp.delete()
                    save_file_path = "/tmp/{}".format(
                        get_random_alphanumeric_string(15, with_punctuation=False, with_spaces=False))
                    form_pgp_ie.keyring_archive.data.save(save_file_path)
                    cmd = f'tar -xvf {save_file_path} -C {GPG_DIR} .'
                    output = subprocess.check_output(cmd, shell=True, text=True)
                    logger.debug("Command: {}, Output: {}".format(cmd, output))
                    status_msg['status_message'].append(f"Import Keyring")
                    status_msg['status_title'] = "Success"
                except Exception as err:
                    status_msg['status_message'].append(
                        "Couldn't import keyring: {}".format(err))
                    logger.exception("Couldn't import keyring")

        elif form_pgp_add.add_key.data:
            keyring_name, key = import_key(form_pgp_add.text_key.data)

            if keyring_name != "public.kr" and key:
                new_key = PGP()
                new_key.key_id = get_key_id(keyring_name, key.fingerprints[0])
                new_key.fingerprint = key.fingerprints[0]
                new_key.keyring_name = keyring_name
                new_key.passphrase = form_pgp_add.passphrase.data
                new_key.save()

                status_msg['status_message'].append(f"Add Key: {key}")
                status_msg['status_title'] = "Success"
            elif keyring_name == "public.kr" and key:
                status_msg['status_message'].append(f"Add Key: {key}")
                status_msg['status_title'] = "Success"
            else:
                status_msg['status_message'].append("Could not add PGP key")

        elif form_pgp_mod.save_passphrase.data:
            if not form_pgp_mod.passphrase_save.data:
                status_msg['status_message'].append(
                    f"A passphrase needs ot be provided to delete a private key")
            else:
                # Find key database entry
                key_test = PGP.query.filter(PGP.fingerprint == form_pgp_mod.fingerprint.data).first()
                if key_test:
                    key_test.passphrase = form_pgp_mod.passphrase_save.data
                    key_test.save()
                    status_msg['status_message'].append(f"Key passphrase saved")
                    status_msg['status_title'] = "Success"
                else:
                    # Find keyring and key
                    keyring = None
                    key = None
                    for each_keyring in get_all_keyrings():
                        if each_keyring == 'public.kr':
                            continue
                        gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=each_keyring)
                        private_keys = gpg.list_keys(secret=True)
                        for each_key in private_keys:
                            if each_key["fingerprint"] == form_pgp_mod.fingerprint.data:
                                key = each_key
                                keyring = each_keyring
                                break

                            if keyring and key:
                                break

                    if keyring and key:
                        new_key = PGP()
                        new_key.key_id = get_key_id(keyring, key['fingerprint'])
                        new_key.fingerprint = key['fingerprint']
                        new_key.keyring_name = keyring
                        new_key.passphrase = form_pgp_mod.passphrase_save.data
                        new_key.save()

                        status_msg['status_message'].append(f"Key passphrase saved")
                        status_msg['status_title'] = "Success"

                if status_msg['status_title'] != "Success":
                    status_msg['status_message'].append(f"Could not save key passphrase")

        elif form_pgp_mod.delete_public_key.data:
            list_return = delete_public_key(form_pgp_mod.fingerprint.data)
            status_msg['status_message'].append(
                f"Delete public key with fingerprint {form_pgp_mod.fingerprint.data}: {', '.join(list_return)}")
            status_msg['status_title'] = "Success"

        elif form_pgp_mod.delete_private_key.data:
            if not form_pgp_mod.passphrase.data:
                status_msg['status_message'].append(
                    f"A passphrase needs ot be provided to delete a private key")
            else:
                key = PGP.query.filter(PGP.fingerprint == form_pgp_mod.fingerprint.data).first()
                if key:
                    gpg = gnupg.GPG(gnupghome=GPG_DIR, keyring=key.keyring_name)
                    del_return = gpg.delete_keys(
                        form_pgp_mod.fingerprint.data,
                        secret=True,
                        passphrase=form_pgp_mod.passphrase.data)
                    key.delete()
                    status_msg['status_message'].append(
                        f"Delete private key with fingerprint {form_pgp_mod.fingerprint.data}: {del_return}")
                    status_msg['status_title'] = "Success"
                else:
                    status_msg['status_message'].append(f"Could not find key in database to delete")

        elif form_pgp.create_master_key.data:
            key_type = form_pgp.key_type_length.data.split(",")[0]
            key_length = int(form_pgp.key_type_length.data.split(",")[1])

            keyring_name = f'{get_random_alphanumeric_string(30, with_punctuation=False, with_spaces=False)}.kr'
            gpg = gnupg.GPG(
                gnupghome=GPG_DIR,
                keyring=keyring_name)

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

            if key:
                new_key = PGP()
                new_key.key_id = get_key_id(keyring_name, key.fingerprint)
                new_key.fingerprint = key.fingerprint
                new_key.keyring_name = keyring_name
                new_key.passphrase = form_pgp.passphrase.data
                new_key.save()

                status_msg['status_message'].append(f"PGP key pair created: {key.fingerprint}")
                status_msg['status_title'] = "Success"
            else:
                status_msg['status_message'].append("Could not create PGP key")

        elif form_pgp.delete_all.data:
            delete_files_recursive(GPG_DIR)
            ensure_gpg_dir_exists()
            for each_pgp in PGP.query.all():
                each_pgp.delete()
            status_msg['status_message'].append("Deleted all keys")
            status_msg['status_title'] = "Success"

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_pgp.gpg_page"))

    return render_template("pages/gpg.html",
                           exported_public_keys=exported_public_keys,
                           pgp=PGP,
                           private_key=private_key,
                           private_keys=private_keys,
                           public_key_ids=public_key_ids,
                           public_keys=public_keys,
                           status_msg=status_msg)
