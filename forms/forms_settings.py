# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import BooleanField
from wtforms import DecimalField
from wtforms import FileField
from wtforms import IntegerField
from wtforms import StringField
from wtforms import SubmitField

logger = logging.getLogger("bitchan.forms_settings")


class AddressBook(FlaskForm):
    label = StringField("New Label")
    add_label = StringField("Address Label")
    address = StringField("Address")
    add = SubmitField("Add to Address Book")
    delete = SubmitField("Delete")
    rename = SubmitField("Rename")


class UploadSite(FlaskForm):
    domain = StringField("Domain")
    type = StringField("Type")
    uri = StringField("URI")
    download_prefix = StringField("Download Prefix")
    response = StringField("Response")
    direct_dl_url = BooleanField("Direct DL URL")
    extra_curl_options = StringField("Extra cURL Options")
    upload_word = StringField("Upload Word")
    form_name = StringField("Form Name")
    add = SubmitField("Add")
    delete = SubmitField("Delete")
    save = SubmitField("Save")


class PGP(FlaskForm):
    name = StringField("Name")
    email = StringField("Email")
    comment = StringField("Comment")
    key_type_length = StringField("Key Type and Length")
    passphrase = StringField("Passphrase")
    create_master_key = SubmitField("Create Key")
    delete_all = SubmitField("Delete All")


class Diag(FlaskForm):
    del_inventory = SubmitField("Delete BM Inventory")
    del_trash = SubmitField("Delete BM Trash")


class Flag(FlaskForm):
    flag_id = StringField("Flag ID")
    flag_name = StringField("Flag Name")
    flag_file = FileField()
    flag_rename = SubmitField("Rename Flag")
    flag_delete = SubmitField("Delete Flag")
    flag_upload = SubmitField("Upload Flag")


class Identity(FlaskForm):
    label = StringField("Label")
    passphrase = StringField("Passphrase")
    create_identity = SubmitField("Create Identity")
    address = StringField("Addres")
    ident_label = StringField("Label")
    resync = BooleanField("Resync")
    delete = SubmitField("Delete")
    rename = SubmitField("Rename")


class Settings(FlaskForm):
    theme = StringField("Theme")
    chan_update_display_number = IntegerField("Max Home Page Updates")
    max_download_size = DecimalField("Auto-Download Max Size")
    allow_net_file_size_check = BooleanField("Allow connecting to check attachment file sizes")
    allow_net_book_quote = BooleanField("Allow connecting to get book quotes")
    allow_net_ntp = BooleanField("Allow connecting to NTP to sync time")
    never_auto_download_unencrypted = BooleanField("Never allow auto-download of unencrypted attachments")
    save = SubmitField("Save")
    export_chans = SubmitField("Export Boards/Lists")
    export_identities = SubmitField("Export Identities")
    export_address_book = SubmitField("Export Address Book")


class Status(FlaskForm):
    tor_newnym = StringField("Tor NEWNYM")
