# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms import SubmitField
from wtforms import FileField

logger = logging.getLogger("bitchan.forms_pgp")


class PGP(FlaskForm):
    name = StringField("Name")
    email = StringField("Email")
    comment = StringField("Comment")
    key_type_length = StringField("Key Type and Length")
    passphrase = StringField("Passphrase")
    create_master_key = SubmitField("Create Key")
    delete_all = SubmitField("Delete All")


class PGPMod(FlaskForm):
    fingerprint = StringField("Fingerprint")
    passphrase = StringField("Passphrase")
    passphrase_save = StringField("Passphrase")
    save_passphrase = SubmitField("Save Passphrase")
    show_private_key_block = SubmitField("Show Private Key Block")
    delete_private_key = SubmitField("Delete Private Key")
    delete_public_key = SubmitField("Delete Public Key")


class PGPAddKey(FlaskForm):
    text_key = StringField("Key")
    passphrase = StringField("Passphrase")
    add_key = SubmitField("Add Key")


class PGPImportExport(FlaskForm):
    keyring_archive = FileField("Keyring Archive")
    export_keyring = SubmitField("Export Keyring")
    import_keyring = SubmitField("Import Keyring")
