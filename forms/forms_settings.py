# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import FileField
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
    delete = SubmitField("Delete")
    rename = SubmitField("Rename")


class Settings(FlaskForm):
    theme = StringField("Theme")
    save = SubmitField("Save")
    export_chans = SubmitField("Export Boards/Lists")
    export_identities = SubmitField("Export Identities")
    export_address_book = SubmitField("Export Address Book")


class Status(FlaskForm):
    tor_newnym = StringField("Tor NEWNYM")
