# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import IntegerField
from wtforms import StringField
from wtforms import SubmitField

logger = logging.getLogger("bitchan.forms_mailbox")


class Mailbox(FlaskForm):
    bulk_action = StringField("Bulk Action")
    messages_per_mailbox_page = IntegerField("Messages Per Mailbox Page")
    set_per_page = IntegerField("Set Messages Per Mailbox Page")
    mailbox = StringField("mailbox")
    message_id = StringField("message_id")
    reply = SubmitField("Reply")
    delete = SubmitField("Delete")
    forward = SubmitField("Forward")
    execute_bulk_action = SubmitField("Execute Bulk Action")


class Compose(FlaskForm):
    from_address = StringField("From Address")
    to_address = StringField("To Address")
    ttl = IntegerField("TTL (seconds)")
    subject = StringField("Subject")
    body = StringField("Body")
    send = SubmitField("Send")
