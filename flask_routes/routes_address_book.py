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
from database.models import AddressBook
from forms import forms_board
from forms import forms_settings
from utils.files import LF
from utils.routes import page_dict

logger = logging.getLogger('bitchan.routes_address_book')

blueprint = Blueprint('routes_address_book',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


@blueprint.route('/address_book', methods=('GET', 'POST'))
def address_book():
    form_addres_book = forms_settings.AddressBook()
    form_confirm = forms_board.Confirm()

    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_addres_book.add.data:
            if not form_addres_book.label.data or not form_addres_book.address.data:
                status_msg['status_message'].append("Label and address required")

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        label = base64.b64encode(form_addres_book.label.data.encode()).decode()
                        try:
                            return_str = nexus._api.addAddressBookEntry(
                                form_addres_book.address.data, label)
                        except Exception as e:
                            if e:
                                return_str = "Could not add to Address Book: {}".format(e)
                            else:
                                return_str = "Not a valid address?"

                        if return_str:
                            if "Added address" in return_str:
                                new_add_book = AddressBook()
                                new_add_book.address = form_addres_book.address.data
                                new_add_book.label = form_addres_book.label.data
                                new_add_book.save()

                                nexus._refresh_address_book = True
                                status_msg['status_title'] = "Success"
                                status_msg['status_message'].append(
                                    "Added Address Book entry {}".format(
                                        form_addres_book.label.data))
                                status_msg['status_message'].append(
                                    "Give the system a few seconds for the change to take effect.")
                            else:
                                status_msg['status_message'].append(return_str)
                        else:
                            status_msg['status_message'].append(
                                "Error creating Address Book entry")
                        time.sleep(0.1)
                    finally:
                        lf.lock_release(config.LOCKFILE_API)

        elif form_addres_book.rename.data:
            if not form_addres_book.add_label.data or not form_addres_book.address.data:
                status_msg['status_message'].append("Label and address required")

            if not status_msg['status_message']:
                add_book = AddressBook.query.filter(
                    AddressBook.address == form_addres_book.address.data).first()
                if add_book:
                    add_book.label = form_addres_book.add_label.data
                    add_book.save()
                    nexus._refresh_address_book = True
                    status_msg['status_title'] = "Success"
                    status_msg['status_message'].append("Address Book entry renamed.")
                    status_msg['status_message'].append(
                        "Give the system a few seconds for the change to take effect.")

        elif form_addres_book.delete.data:
            add_book = None
            if not form_addres_book.address.data:
                status_msg['status_message'].append("Address required")
            else:
                add_book = AddressBook.query.filter(
                    AddressBook.address == form_addres_book.address.data).first()

            if not form_confirm.confirm.data:
                return render_template("pages/confirm.html",
                                       action="delete_address_book",
                                       add_book=add_book)

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        return_str = nexus._api.deleteAddressBookEntry(form_addres_book.address.data)
                        if "Deleted address book entry" in return_str:
                            if add_book:
                                add_book.delete()
                            nexus._refresh_address_book = True
                            status_msg['status_title'] = "Success"
                            status_msg['status_message'].append("Address Book entry deleted.")
                            status_msg['status_message'].append(
                                "Give the system a few seconds for the change to take effect.")
                        else:
                            status_msg['status_message'].append(
                                "Error deleting Address Book entry: {}".format(return_str))
                        time.sleep(0.1)
                    finally:
                        lf.lock_release(config.LOCKFILE_API)

        session['status_msg'] = status_msg

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

        return redirect(url_for("routes_address_book.address_book"))

    return render_template("pages/address_book.html",
                           form_addres_book=form_addres_book,
                           status_msg=status_msg)


@blueprint.route('/address_book_add/<address>', methods=('GET', 'POST'))
def address_book_add(address):
    form_addres_book = forms_settings.AddressBook()

    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'status_msg' in session:
            session.pop('status_msg')

    elif request.method == 'POST':
        if form_addres_book.add.data:
            if not form_addres_book.label.data or not form_addres_book.address.data:
                status_msg['status_message'].append("Label and address required")

            if not status_msg['status_message']:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        label = base64.b64encode(form_addres_book.label.data.encode()).decode()
                        try:
                            return_str = nexus._api.addAddressBookEntry(
                                form_addres_book.address.data, label)
                        except Exception as e:
                            if e:
                                return_str = "Could not add to Address Book: {}".format(e)
                            else:
                                return_str = "Not a valid address?"

                        if return_str:
                            if "Added address" in return_str:
                                new_add_book = AddressBook()
                                new_add_book.address = form_addres_book.address.data
                                new_add_book.label = form_addres_book.label.data
                                new_add_book.save()

                                nexus._refresh_address_book = True
                                status_msg['status_title'] = "Success"
                                status_msg['status_message'].append(
                                    "Added Address Book entry {}".format(
                                        form_addres_book.label.data))
                                status_msg['status_message'].append(
                                    "Give the system a few seconds for the change to take effect.")
                            else:
                                status_msg['status_message'].append(return_str)
                        else:
                            status_msg['status_message'].append(
                                "Error creating Address Book entry")
                        time.sleep(0.1)
                    finally:
                        lf.lock_release(config.LOCKFILE_API)

            session['status_msg'] = status_msg

            if 'status_title' not in status_msg and status_msg['status_message']:
                status_msg['status_title'] = "Error"

            return redirect(url_for("routes_address_book.address_book"))

    return render_template("pages/address_book_add.html",
                           address=address,
                           form_addres_book=form_addres_book,
                           status_msg=status_msg)
