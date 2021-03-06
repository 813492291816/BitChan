import base64
import datetime
import logging
import time
from collections import OrderedDict
from operator import itemgetter

from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask.blueprints import Blueprint

import config
from database.models import Chan
from database.models import GlobalSettings
from database.models import Identity
from forms import forms_mailbox
from utils.files import LF
from utils.routes import page_dict
from utils.shared import get_msg_expires_time

logger = logging.getLogger('bitchan.routes_mail')

blueprint = Blueprint('routes_mail',
                      __name__,
                      static_folder='../static',
                      template_folder='../templates')


@blueprint.context_processor
def global_var():
    return page_dict()


def timestamp_format(ts):
    if ts:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')


def base64_decode(b64str):
    if b64str:
        return base64.b64decode(b64str).decode()
    return ""


def get_messages_from_page(mailbox, page, address):
    from bitchan_flask import nexus
    messages_sorted = []
    messages_page = []

    settings = GlobalSettings.query.first()

    if mailbox == "inbox":
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                messages = nexus._api.getInboxMessagesByReceiver(address)
                # Sort messages
                if "inboxMessages" in messages:
                    messages_sorted = sorted(
                        messages["inboxMessages"],
                        key=itemgetter('receivedTime'),
                        reverse=True)
            except Exception as err:
                logger.error("Error: {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_API)
    elif mailbox == "sent":
        lf = LF()
        if lf.lock_acquire(config.LOCKFILE_API, to=60):
            try:
                messages = nexus._api.getSentMessagesBySender(address)
                # Sort messages
                if "sentMessages" in messages:
                    messages_sorted = sorted(
                        messages["sentMessages"],
                        key=itemgetter('lastActionTime'),
                        reverse=True)
            except Exception as err:
                logger.error("Error: {}".format(err))
            finally:
                lf.lock_release(config.LOCKFILE_API)

    msg_start = int((int(page) - 1) * settings.messages_per_mailbox_page)
    msg_end = int(int(page) * settings.messages_per_mailbox_page) - 1
    for i, msg in enumerate(messages_sorted):
        if msg_start <= i <= msg_end:
            messages_page.append(msg)

    return messages_page, messages_sorted


@blueprint.route('/mailbox/<ident_address>/<mailbox>/<page>/<msg_id>', methods=('GET', 'POST'))
def mailbox(ident_address, mailbox, page, msg_id):
    from bitchan_flask import nexus
    status_msg = {"status_message": []}
    messages = []
    msg_selected = []
    identities = nexus.get_identities()
    page = int(page)

    form_mail = forms_mailbox.Mailbox()

    if msg_id != "0":
        if mailbox == "inbox":
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=60):
                try:
                    msg_selected = nexus._api.getInboxMessageById(msg_id, True)
                    if "inboxMessage" in msg_selected:
                        msg_selected = msg_selected["inboxMessage"][0]
                        expires = get_msg_expires_time(msg_id)
                        if expires:
                            msg_selected["expires_time"] = expires
                except Exception as err:
                    logger.error("Error: {}".format(err))
                finally:
                    lf.lock_release(config.LOCKFILE_API)

        elif mailbox == "sent":
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=60):
                try:
                    msg_selected = nexus._api.getSentMessageById(msg_id)
                    if "sentMessage" in msg_selected:
                        msg_selected = msg_selected["sentMessage"][0]
                        expires = get_msg_expires_time(msg_id)
                        if expires:
                            msg_selected["expires_time"] = expires
                except Exception as err:
                    logger.error("Error: {}".format(err))
                finally:
                    lf.lock_release(config.LOCKFILE_API)

    if request.method == 'POST':
        settings = GlobalSettings.query.first()

        if ((form_mail.messages_per_mailbox_page.data or
                (form_mail.messages_per_mailbox_page.data and
                 form_mail.set_per_page.data))
                and
                form_mail.messages_per_mailbox_page.data != settings.messages_per_mailbox_page
                ):
            settings.messages_per_mailbox_page = form_mail.messages_per_mailbox_page.data
            settings.save()

        elif form_mail.execute_bulk_action.data and form_mail.bulk_action.data:
            msg_ids = request.form.getlist("selected_msg")

            if form_mail.bulk_action.data == "delete":
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        for each_id in msg_ids:
                            if mailbox == "inbox":
                                nexus._api.trashInboxMessage(each_id)
                            elif mailbox == "sent":
                                nexus._api.trashSentMessage(each_id)
                            time.sleep(0.1)
                    except Exception as err:
                        logger.error("Error: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_API)

                return redirect(url_for("routes_mail.mailbox",
                                        ident_address=ident_address,
                                        mailbox=mailbox,
                                        page="1",
                                        msg_id="0"))

            if form_mail.bulk_action.data in ["mark_read", "mark_unread"]:
                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:
                        for each_id in msg_ids:
                            nexus._api.getInboxMessageById(
                                each_id,
                                form_mail.bulk_action.data == "mark_read")
                            time.sleep(0.1)
                    except Exception as err:
                        logger.error("Error: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_API)

                nexus.set_unread_mail_count(ident_address)

                return redirect(url_for("routes_mail.mailbox",
                                        ident_address=ident_address,
                                        mailbox=mailbox,
                                        page=page,
                                        msg_id=msg_id))

        elif form_mail.reply.data and form_mail.message_id.data:
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=60):
                try:
                    msg_selected = nexus._api.getInboxMessageById(form_mail.message_id.data, True)
                    if "inboxMessage" in msg_selected:
                        msg_selected = msg_selected["inboxMessage"][0]
                        form_populate = {
                            "to_address": msg_selected["fromAddress"],
                            "body": "\n\n\n------------------------------------------------------\n{}".format(
                                base64_decode(msg_selected["message"]))
                        }
                        if base64_decode(msg_selected["subject"]).startswith("Re:"):
                            form_populate["subject"] = base64_decode(msg_selected["subject"])
                        else:
                            form_populate["subject"] = "Re: {}".format(base64_decode(msg_selected["subject"]))
                        session['form_populate'] = form_populate
                        session['status_msg'] = status_msg
                except Exception as err:
                    logger.error("Error: {}".format(err))
                finally:
                    lf.lock_release(config.LOCKFILE_API)

            return redirect(url_for("routes_mail.compose",
                                    address_to="0"))

        elif form_mail.forward.data and form_mail.message_id.data:
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=60):
                try:
                    msg_selected = nexus._api.getInboxMessageById(form_mail.message_id.data, True)
                    if "inboxMessage" in msg_selected:
                        msg_selected = msg_selected["inboxMessage"][0]
                        form_populate = {
                            "body": "\n\n\n------------------------------------------------------\n{}".format(
                                base64_decode(msg_selected["message"]))
                        }
                        if base64_decode(msg_selected["subject"]).startswith("Fwd:"):
                            form_populate["subject"] = base64_decode(msg_selected["subject"])
                        else:
                            form_populate["subject"] = "Fwd: {}".format(base64_decode(msg_selected["subject"]))
                        session['form_populate'] = form_populate
                        session['status_msg'] = status_msg
                except Exception as err:
                    logger.error("Error: {}".format(err))
                finally:
                    lf.lock_release(config.LOCKFILE_API)

            return redirect(url_for("routes_mail.compose",
                                    address_to="0"))

        elif form_mail.delete.data and form_mail.message_id.data:
            lf = LF()
            if lf.lock_acquire(config.LOCKFILE_API, to=60):
                try:
                    nexus._api.trashMessage(form_mail.message_id.data)
                except Exception as err:
                    logger.error("Error: {}".format(err))
                finally:
                    lf.lock_release(config.LOCKFILE_API)

            return redirect(url_for("routes_mail.mailbox",
                                    ident_address=ident_address,
                                    mailbox=mailbox,
                                    page=page,
                                    msg_id="0"))

    if ident_address != '0' and mailbox == "inbox":
        nexus.set_unread_mail_count(ident_address)

    unread_mail_counts = {}
    for each_identity in Identity.query.all():
        unread_mail_counts[each_identity.address] = each_identity.unread_messages

    return render_template("mailbox/mailbox.html",
                           base64_decode=base64_decode,
                           get_messages_from_page=get_messages_from_page,
                           ident_address=ident_address,
                           identities=identities,
                           mailbox=mailbox,
                           msg_id=msg_id,
                           msg_selected=msg_selected,
                           messages=messages,
                           page=page,
                           status_msg=status_msg,
                           timestamp_format=timestamp_format,
                           unread_mail_counts=unread_mail_counts)


def get_from_list_all():
    from bitchan_flask import nexus
    from_addresses = {}
    address_labels = nexus.get_address_labels()
    all_chans = nexus.get_all_chans()
    identities = nexus.get_identities()

    for each_address in identities:
        from_addresses[each_address] = "Identity: "
        if each_address in address_labels:
            from_addresses[each_address] += "{} ".format(address_labels[each_address])
        from_addresses[each_address] += "({})".format(each_address)

    for each_address in all_chans:
        if Chan.query.filter(Chan.address == each_address).first():
            if Chan.query.filter(Chan.address == each_address).first().type == "board":
                from_addresses[each_address] = "Board: "
            elif Chan.query.filter(Chan.address == each_address).first().type == "list":
                from_addresses[each_address] = "List: "

        if each_address in from_addresses:
            if each_address in address_labels:
                from_addresses[each_address] += "{} ".format(address_labels[each_address])
            from_addresses[each_address] += "({})".format(each_address)

    # sort
    from_dict = {"board": {}, "list": {}, "ident": {}}

    for each_address in from_addresses:
        if from_addresses[each_address].startswith("Board:"):
            from_dict["board"][each_address] = from_addresses[each_address]
        elif from_addresses[each_address].startswith("List:"):
            from_dict["list"][each_address] = from_addresses[each_address]
        elif from_addresses[each_address].startswith("Identity:"):
            from_dict["ident"][each_address] = from_addresses[each_address]

    from_dict["ident"] = OrderedDict(sorted(from_dict["ident"].items(), key=lambda x: x[1].lower()))
    from_dict["board"] = OrderedDict(sorted(from_dict["board"].items(), key=lambda x: x[1].lower()))
    from_dict["list"] = OrderedDict(sorted(from_dict["list"].items(), key=lambda x: x[1].lower()))

    combined_dict = OrderedDict()
    combined_dict.update(from_dict["ident"])
    combined_dict.update(from_dict["board"])
    combined_dict.update(from_dict["list"])

    return combined_dict


@blueprint.route('/compose/<address_from>/<address_to>', methods=('GET', 'POST'))
def compose(address_from, address_to):
    from bitchan_flask import nexus
    from_all = []

    form_msg = forms_mailbox.Compose()

    if address_from == "0":
        address_from = ""

    if address_to == "0":
        address_to = ""

    from_all.extend(nexus.get_identities().keys())
    from_all.extend(nexus.get_all_chans().keys())

    form_populate = session.get('form_populate', {})
    status_msg = session.get('status_msg', {"status_message": []})

    if request.method == 'GET':
        if 'form_populate' in session:
            session.pop('form_populate')
        if 'status_msg' in session:
            session.pop('status_msg')

    if request.method == 'POST':
        if form_msg.send.data:
            if not form_msg.to_address.data:
                status_msg['status_message'].append("Must provide a To Address")
            if not form_msg.from_address.data:
                status_msg['status_message'].append("Must provide a From Address")
            if not (3600 <= form_msg.ttl.data <= 2419200):
                status_msg['status_message'].append("TTL must be between 3600 and 2419200")

            if not status_msg['status_message']:
                if form_msg.subject.data:
                    subject = base64.b64encode(form_msg.subject.data.encode()).decode()
                else:
                    subject = ""
                if form_msg.body.data:
                    message = base64.b64encode(form_msg.body.data.encode()).decode()
                else:
                    message = ""

                lf = LF()
                if lf.lock_acquire(config.LOCKFILE_API, to=60):
                    try:  # TODO: message sends but results in error. Diagnose.
                        status_msg['status_title'] = "Success"
                        status_msg['status_message'].append("Message sent to queue")
                        try:
                            return_str = nexus._api.sendMessage(
                                form_msg.to_address.data,
                                form_msg.from_address.data,
                                subject,
                                message,
                                2,
                                form_msg.ttl.data)
                        except Exception as err:
                            if err.__str__() == "<Fault 21: 'Unexpected API Failure - too many values to unpack'>":
                                return_str = "Error: API Failure (despite this error, the message probably still sent)"
                            else:
                                return_str = "Error: {}".format(err)
                        if return_str:
                            logger.info("Send message from {} to {}. Returned: {}".format(
                                form_msg.from_address.data,
                                form_msg.to_address.data,
                                return_str))
                            status_msg['status_message'].append(
                                "Bitmessage returned: {}".format(return_str))
                        time.sleep(0.1)
                    except Exception as err:
                        logger.exception("Error: {}".format(err))
                    finally:
                        lf.lock_release(config.LOCKFILE_API)

        if 'status_title' not in status_msg and status_msg['status_message']:
            status_msg['status_title'] = "Error"

            form_populate = {
                "to_address": form_msg.to_address.data,
                "from_address": form_msg.from_address.data,
                "ttl": form_msg.ttl.data,
                "subject": form_msg.subject.data,
                "body": form_msg.body.data,
            }

        session['form_populate'] = form_populate
        session['status_msg'] = status_msg

        return redirect(url_for("routes_mail.compose",
                                address_from="0",
                                address_to="0"))

    return render_template("mailbox/compose.html",
                           address_from=address_from,
                           address_to=address_to,
                           form_populate=form_populate,
                           from_all=from_all,
                           get_from_list_all=get_from_list_all,
                           status_msg=status_msg)
