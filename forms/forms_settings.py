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


class Login(FlaskForm):
    password = StringField("Password")
    login = SubmitField("Login")


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
    del_deleted_msg_db = SubmitField("Clear Deleted Message Table")
    del_non_bc_msg_list = SubmitField("Clear Non-BC Message List")
    del_popup_html = SubmitField("Delete Popup HTML")
    del_cards = SubmitField("Delete Cards")
    del_mod_log = SubmitField("Delete Mod Log")
    del_posts_without_thread = SubmitField("Delete Posts Without a Thread")
    fix_thread_board_timestamps = SubmitField("Fix Thread and Board Timestamps")
    fix_thread_short_hashes = SubmitField("Fix Thread Short Hashes")
    download_backup = SubmitField("Download Backup Archive")
    restore_backup = SubmitField("Restore Backup Archive")
    restore_backup_file = FileField()
    del_sending_msg = SubmitField("Cancel Send")
    bulk_delete_threads_address = StringField("Bulk Delete Threads Address")
    bulk_delete_threads_submit = SubmitField("Bulk Delete Threads Submit")


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
    max_download_size = DecimalField("Attachment Auto-Download Max Size (MB)")
    max_extract_size = DecimalField("Attachment Extraction Max Size (MB)")
    allow_net_file_size_check = BooleanField("Allow connecting to verify post attachment size")
    allow_net_book_quote = BooleanField("Allow connecting to get book quotes")
    allow_net_ntp = BooleanField("Allow connecting to NTP to sync time")
    never_auto_download_unencrypted = BooleanField("Never allow auto-download of unencrypted attachments")
    auto_dl_from_unknown_upload_sites = BooleanField("Automatically download from unknown upload sites")
    delete_sent_identity_msgs = BooleanField("Automatically delete sent Identity messages")
    home_page_msg = StringField("Home Page Message")
    html_head = StringField("HEAD HTML")
    html_body = StringField("BODY HTML")
    results_per_page_board = IntegerField("Threads Per Page on Board Page")
    results_per_page_overboard = IntegerField("Threads Per Page on Overboard Page")
    results_per_page_catalog = IntegerField("Threads Per Page on Catalog Page")
    results_per_page_recent = IntegerField("Results Per Page on Recent Page")
    results_per_page_search = IntegerField("Results Per Page on Search Page")
    results_per_page_mod_log = IntegerField("Results Per Page on Mod Log Page")
    save = SubmitField("Save")

    export_chans = SubmitField("Export Boards/Lists")
    export_identities = SubmitField("Export Identities")
    export_address_book = SubmitField("Export Address Book")
    enable_rand_tor_address = BooleanField("Enable Random Tor Address")
    get_new_rand_tor = SubmitField("Get New Random Tor Address")
    enable_cus_tor_address = BooleanField("Enable Custom Tor Address")
    tor_file = FileField()
    save_tor_settings = SubmitField("Save Tor Settings")

    # Security
    enable_captcha = BooleanField("Require Captcha to Post")
    enable_verification = BooleanField("Require Verification to Access")
    enable_page_rate_limit = BooleanField("Enable Page Load Rate-Limiting")
    max_requests_per_period = IntegerField("Maximum Requests Per Period")
    rate_limit_period_seconds = IntegerField("Rate Limit Period (seconds)")
    hide_all_board_list_passphrases = BooleanField("Hide Passphrases From Board/List Information")

    # Kiosk mode
    enable_kiosk_mode = BooleanField("Enable Kiosk Mode")
    kiosk_login_to_view = BooleanField("Require Users to Log In")
    kiosk_allow_posting = BooleanField("Allow Users to Post")
    kiosk_disable_bm_attach = BooleanField("Disable Bitmessage as a Post Upload Method")
    kiosk_allow_download = BooleanField("Allow Users to Initiate Post Downloads")
    kiosk_post_rate_limit = IntegerField("Post Refractory Period (seconds)")
    kiosk_attempts_login = IntegerField("Maximum Login Attempts")
    kiosk_ban_login_sec = IntegerField("Login Ban Length (seconds)")
    kiosk_only_admin_access_mod_log = BooleanField("Only Kiosk Admins Can View Mod Log")


class Status(FlaskForm):
    tor_newnym = StringField("Tor NEWNYM")
