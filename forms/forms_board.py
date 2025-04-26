# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import BooleanField
from wtforms import FileField
from wtforms import IntegerField
from wtforms import MultipleFileField
from wtforms import PasswordField
from wtforms import SelectField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField

logger = logging.getLogger("bitchan.forms_board")


class Log(FlaskForm):
    log = StringField("Log")
    lines = IntegerField("Lines")
    submit = SubmitField("Submit")


class Post(FlaskForm):
    board_id = StringField("Board ID")
    thread_id = StringField("Thread ID")
    is_op = StringField("Is OP")
    op_sha256_hash = StringField("OP Hash")
    from_address = StringField("From Address")
    default_from_address = BooleanField("Set default From")
    chan = StringField("Chan")
    nation = SelectField("Nations", choices=[])
    subject = StringField("Subject")
    body = StringField("Body")
    sage = BooleanField("Sage")
    game = StringField("Host a Game")
    game_termination_password = StringField("Game Termination Password")
    game_password_a = StringField("Game Password A (previous)")
    game_password_b = StringField("Game Password B (new)")
    game_player_move = StringField("Game Player Move")
    ttl = IntegerField("TTL")
    file1 = MultipleFileField("Upload Images/Files")
    file2 = MultipleFileField("Upload Images/Files")
    file3 = MultipleFileField("Upload Images/Files")
    file4 = MultipleFileField("Upload Images/Files")
    strip_exif = BooleanField("Strip EXIF")
    image1_spoiler = BooleanField("Image 1 Spoiler")
    image2_spoiler = BooleanField("Image 2 Spoiler")
    image3_spoiler = BooleanField("Image 3 Spoiler")
    image4_spoiler = BooleanField("Image 4 Spoiler")
    upload = StringField("Upload")
    upload_cipher_and_key = StringField("Upload Encryption Cipher")
    message_id = StringField("Message ID")
    page_id = StringField("Page ID")
    game_hash = StringField("Game Hash")

    # Proof of Work
    pow_method = StringField("POW Method")
    pow_difficulty = IntegerField("POW Difficulty")
    pow_repetitions = IntegerField("POW Repetitions")

    # Thread rules
    sort_replies_by_pow = BooleanField("Sort Replies by POW")
    require_pow_to_reply = BooleanField("Require POW to Reply")
    require_pow_method = StringField("POW Method")
    require_pow_difficulty = StringField("POW Difficulty")
    require_pow_repetitions = StringField("POW Repetitions")

    # GPG
    gpg_body = StringField("GPG Body")
    gpg_encrypt_msg = BooleanField("Encrypt Post")
    gpg_sign_post = BooleanField("Sign Post")
    gpg_hide_all_recipients = BooleanField("Hide All Recipients")
    gpg_select_from = SelectField("From", choices=[])
    gpg_select_to = SelectMultipleField("To", choices=[])

    # Additional options
    image_steg_insert = IntegerField("Image to insert steg")
    steg_message = StringField("Steg Message")
    delete_password = StringField("Password to Delete")
    schedule_post_epoch = IntegerField("Schedule to Post after Epoch")

    start_download = SubmitField("Download File")
    preview_post = SubmitField("Preview")
    submit_post = SubmitField("Post")


class SetChan(FlaskForm):
    pgp_passphrase_msg = StringField("Message PGP Passphrase")
    set_pgp_passphrase_msg = SubmitField("Set Message PGP Passphrase")
    pgp_passphrase_attach = StringField("Attachment PGP Passphrase")
    set_pgp_passphrase_attach = SubmitField("Set Attachment PGP Passphrase")
    pgp_passphrase_steg = StringField("Steg PGP Passphrase")
    set_pgp_passphrase_steg = SubmitField("Set Steg PGP Passphrase")


class SetOptions(FlaskForm):
    modify_admin_addresses = StringField("Modify Admin Addresses")
    modify_user_addresses = StringField("Modify User Addresses")
    modify_restricted_addresses = StringField("Modify Restricted Addresses")
    file_banner = FileField()
    long_description = StringField("Long Description")
    css = StringField("CSS")
    word_replace = StringField("Word Replace")
    allow_css = SubmitField("Allow CSS")
    disallow_css = SubmitField("Disallow CSS")
    set_options = SubmitField("Set Options")


class Join(FlaskForm):
    stage = StringField("Stage")
    join_type = SelectField("Join Type", choices=[])
    require_attachment = BooleanField("Require Post Attachment")
    require_pow_to_post = BooleanField("Require Proof of Work (POW) to Post")
    pow_method = StringField("POW Method")
    pow_difficulty = StringField("POW Difficulty")
    pow_repetitions = StringField("POW Repetitions")
    require_identity_to_post = BooleanField("Require Identity to Post")
    restrict_thread_creation = BooleanField("Restrict Thread Creation to Owners, Admins, and Thread Creation Users")
    disallow_attachments = BooleanField("Disallow Post Attachments")
    thread_creation_users = StringField("Thread Creation User Addresses (separated by commas)")
    automatic_wipe = BooleanField("Automatic Wipe")
    allow_list_pgp_metadata = BooleanField("Allow Lists to Store PGP Passphrases")
    wipe_epoch = IntegerField("Time to Clear (UTC Epoch)")
    interval_seconds = IntegerField("Interval (seconds)")
    restricted_additional = StringField("Restricted Additional Addresses")
    primary_additional = StringField("Primary Additional Addresses")
    secondary_additional = StringField("Secondary Additional Addresses")
    tertiary_additional = StringField("Tertiary Additional Addresses")
    extra_string = StringField("Extra String")
    address = StringField("Address")
    passphrase = PasswordField("Passphrase")
    label = StringField("Label")
    description = StringField("Label")
    pgp_passphrase_msg = StringField("Message PGP Passphrase")
    pgp_passphrase_attach = StringField("Attachment PGP Passphrase")
    pgp_passphrase_steg = StringField("Steg PGP Passphrase")
    resync = BooleanField("Resync")
    unlisted = BooleanField("Unlisted")
    restricted = BooleanField("Restricted")
    next = SubmitField("Next")
    join = SubmitField("Join")


class List(FlaskForm):
    address = StringField("Address")
    from_address = StringField("From Address")
    save_from = SubmitField("Save From")
    add = SubmitField("Add")
    add_unlisted = BooleanField("Add Unlisted")
    add_restricted = BooleanField("Add Unlisted")
    add_bulk = SubmitField("Bulk Add")
    delete = SubmitField("Delete")


class BugReport(FlaskForm):
    bug_report = StringField("Bug Report")
    send = SubmitField("Send")


class DeleteComment(FlaskForm):
    address = StringField("Address")
    delete_comment = StringField("Delete Comment")
    send = SubmitField("Send")


class Leave(FlaskForm):
    clear_mod_log = BooleanField("Clear Mod Log")


class Confirm(FlaskForm):
    text = StringField("Text")
    address = StringField("Address")
    confirm = SubmitField("Confirm")


class ModLog(FlaskForm):
    filter_failed_attempts = BooleanField("Failed Attempts")
    filter_remote_moderate = BooleanField("Filter Remote Moderate")
    filter = SubmitField("Filter")
    bulk_delete_mod_log = SubmitField("Delete Selected Entries")
    bulk_restore_post_mod_log = SubmitField("Restore Selected Posts")
    bulk_restore_thread_mod_log = SubmitField("Restore Selected Threads")


class Search(FlaskForm):
    search_type = StringField("Search Type")
    search_boards = StringField("Search Boards")
    search = StringField("Search String")
    filter_hidden = BooleanField("Show Only Hidden")
    filter_op = BooleanField("Show Only OP")
    filter_steg = BooleanField("Show Only STEG")
    page = IntegerField("Page")
    bulk_restore_post = SubmitField("Bulk Restore Posts")
    bulk_restore_thread = SubmitField("Bulk Restore Threads")
    bulk_delete = SubmitField("Bulk Delete")
    submit = SubmitField("Search")


class Recent(FlaskForm):
    message_id = StringField("Message ID")
    start_download = SubmitField("Download File")
    bulk_delete_threads = SubmitField("Delete Selected Posts/Threads")
