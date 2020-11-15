# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import BooleanField
from wtforms import IntegerField
from wtforms import FileField
from wtforms import PasswordField
from wtforms import SelectField
from wtforms import StringField
from wtforms import SubmitField

from config import UPLOAD_SERVERS_NAMES
from forms.nations import nations

logger = logging.getLogger("bitchan.forms_board")


class Post(FlaskForm):
    board_id = StringField("Board ID")
    thread_id = StringField("Thread ID")
    is_op = StringField("Is OP")
    op_md5_hash = StringField("OP Hash")
    from_address = StringField("From")
    chan = StringField("Chan")
    nation = SelectField(
        "Nations",
        choices=[("", "None")] + nations)
    subject = StringField("Subject")
    body = StringField("Body")
    file = FileField()
    strip_exif = BooleanField("Strip EXIF")
    image_spoiler = BooleanField("Spoiler")
    upload = SelectField(
        "Upload",
        choices=[("bitmessage", "Bitmessage (most secure, ~300K max)")] + UPLOAD_SERVERS_NAMES)
    message_id = StringField("Message ID")
    start_download = SubmitField("Download File")
    submit = SubmitField("Submit")


class SetOptions(FlaskForm):
    modify_admin_addresses = StringField("Modify Admin Addresses")
    modify_user_addresses = StringField("Modify User Addresses")
    modify_restricted_addresses = StringField("Modify Restricted Addresses")
    file_banner = FileField()
    css = StringField("CSS")
    word_replace = StringField("Word Replace")
    set_options = SubmitField("Set Options")


class Steg(FlaskForm):
    steg_message = StringField("Steg Message")
    steg_passphrase = StringField("Steg Passphrase")


class Join(FlaskForm):
    stage = StringField("Stage")
    join_type = SelectField("Join Type")
    require_identity_to_post = BooleanField("Require Identity to Post")
    automatic_wipe = BooleanField("Automatic Wipe")
    wipe_epoch = IntegerField("Time to Clear (UTC Epoch)")
    interval_seconds = IntegerField("Interval (Seconds)")
    restricted_additional = StringField("Restricted Additional Addresses")
    primary_additional = StringField("Primary Additional Addresses")
    secondary_additional = StringField("Secondary Additional Addresses")
    tertiary_additional = StringField("Tertiary Additional Addresses")
    extra_string = StringField("Extra String")
    address = StringField("Address")
    passphrase = PasswordField("Passphrase")
    label = StringField("Label")
    description = StringField("Label")
    next = SubmitField("Next")
    join = SubmitField("Join")


class List(FlaskForm):
    address = StringField("Address")
    add = SubmitField("Add")
    delete = SubmitField("Delete")


class BugReport(FlaskForm):
    bug_report = StringField("Bug Report")
    send = SubmitField("Send")


class DeleteComment(FlaskForm):
    delete_comment = StringField("Delete Comment")
    send = SubmitField("Send")
