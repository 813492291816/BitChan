# -*- coding: utf-8 -*-
import logging

from flask_wtf import FlaskForm
from wtforms import BooleanField
from wtforms import DecimalField
from wtforms import FileField
from wtforms import IntegerField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField

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
    enabled = BooleanField("Enable")
    domain = StringField("Domain")
    type = StringField("Type")
    subtype = StringField("Subtype")
    uri = StringField("URI")
    download_prefix = StringField("Download Prefix")
    response = StringField("Response")
    json_key = StringField("JSON Key")
    direct_dl_url = BooleanField("Direct DL URL")
    extra_curl_options = StringField("Extra cURL Options")
    upload_word = StringField("Upload Word")
    form_name = StringField("Form Name")
    http_headers = StringField("HTTP Headers (as JSON)")
    proxy_type = StringField("Proxy Type (tor or i2p)")
    replace_download_domain = StringField("Replace Download Domain")
    add = SubmitField("Add")
    delete = SubmitField("Delete")
    save = SubmitField("Save")


class Diag(FlaskForm):
    restart_bitmessage = SubmitField("Restart Bitmessage")
    del_inventory = SubmitField("Delete BM Inventory")
    del_trash = SubmitField("Delete BM Trash")
    del_deleted_msg_db = SubmitField("Clear Deleted Message Table")
    del_non_bc_msg_list = SubmitField("Clear Non-BC Message List")
    regenerate_all_thumbnails = SubmitField("Regenerate All Thumbnails")
    regenerate_post_thumbnails = SubmitField("Regenerate Post Thumbnails")
    regenerate_post_thumbnails_id = StringField("Regenerate Thumbnails Post ID")
    regenerate_all_html = SubmitField("Regenerate All HTML")
    regenerate_post_html = SubmitField("Regenerate Post HTML")
    regenerate_post_id = StringField("Regenerate Post ID")
    regenerate_thread_post_id = StringField("Regenerate Thread Post ID")
    regenerate_thread_post_html = SubmitField("Regenerate all HTML of Posts of Thread")
    regenerate_popup_html = SubmitField("Regenerate Popup HTML")
    regenerate_cards = SubmitField("Regenerate Cards")
    del_mod_log = SubmitField("Delete Mod Log")
    del_orphaned_identities = SubmitField("Delete Orphaned Identities")
    add_orphaned_identities = SubmitField("Add Orphaned Identities")
    del_posts_without_thread = SubmitField("Delete Posts Without a Thread")
    fix_thread_board_timestamps = SubmitField("Fix Thread and Board Timestamps")
    fix_thread_short_hashes = SubmitField("Fix Thread Short Hashes")
    fix_chan_thread_timestamps = SubmitField("Fix Chan and Thread Timestamps")
    reset_downloads = SubmitField("Reset Downloads")
    start_all_downloads = SubmitField("Start All Downloads")
    recheck_attachments = SubmitField("Recheck Attachments")
    delete_orphaned_attachments = SubmitField("Delete Orphaned Attachments")
    regenerate_reply_post_ids = SubmitField("Regenerate Reply Post IDs")
    regenerate_all_post_numbers = SubmitField("Regenerate Post Numbers")
    regenerate_all_post_html = SubmitField("Regenerate Post HTML")
    regenerate_upload_sites = SubmitField("Regenerate Upload Sites")
    del_game_table = SubmitField("Delete Game Data")
    del_captcha_table = SubmitField("Delete Captcha Data")
    download_backup = SubmitField("Download Backup Archive")
    restore_backup = SubmitField("Restore Backup Archive")
    restore_backup_file = FileField()
    del_sending_msg = SubmitField("Cancel Send")
    delete_post_id = StringField("Post ID to Delete")
    delete_post_id_submit = SubmitField("Delete post with ID")
    bulk_delete_threads_address = StringField("Bulk Delete Threads Address")
    bulk_delete_threads_submit = SubmitField("Bulk Delete Threads Submit")
    knownnodes_dat_txt = StringField("knownnodes.dat contents")
    knownnodes_submit = SubmitField("Combine with knownnodes.dat")

    # file hash ban
    hash_name = StringField("Hash Name")
    board_addresses = StringField("Board Addresses")
    hash_to_ban = StringField("Hash to Ban")
    imagehash_to_ban = StringField("Imagehash to Ban")
    delete_present_posts = BooleanField("Delete Present Posts")
    delete_present_threads = BooleanField("Delete Present Threads")
    add_banned_hash = SubmitField("Add Banned Hash")
    edit_hash_table = SubmitField("Rename Hashes")
    del_banned_hashes = SubmitField("Unban Selected Hashes")
    regenerate_hashes = SubmitField("Regenerate Hashes")
    save_attachment_options = SubmitField("Save Attachment Options")

    # banned words
    word_name = StringField("Word Name")
    word_board_addresses = StringField("Board Addresses")
    word_to_ban = StringField("Word to Ban")
    word_delete_present_posts = BooleanField("Delete Present Posts")
    word_delete_present_threads = BooleanField("Delete Present Threads")
    word_is_regex = BooleanField("Word is Regex")
    add_banned_word = SubmitField("Ban Word")
    edit_word_table = SubmitField("Rename Words")
    del_banned_words = SubmitField("Unban Selected Words")

    # string replace
    string_name = StringField("String Name")
    string_board_addresses = StringField("Board Addresses")
    string_to_replace = StringField("String to Replace")
    regex_to_match = StringField("Regex to Match")
    string_to_replace_with = StringField("String to Replace With")
    add_string_replacement = SubmitField("Add String Replacement")
    edit_string_table = SubmitField("Rename String")
    del_string_replacement = SubmitField("Remove String Replacement")


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
    generate_shorter_address = BooleanField("Generate Shorter Address")
    create_identity = SubmitField("Create Identity")
    address = StringField("Addres")
    ident_label = StringField("Label")
    resync = BooleanField("Resync")
    delete = SubmitField("Delete")
    rename = SubmitField("Rename")


class Settings(FlaskForm):
    maintenance_mode = BooleanField("Enable Maintenance Mode")
    theme = StringField("Theme")
    chan_update_display_number = IntegerField("Max Home Page Updates")
    max_download_size = DecimalField("Attachment Auto-Download Max Size (MB)")
    max_extract_size = DecimalField("Attachment Extraction Max Size (MB)")
    allow_net_file_size_check = BooleanField("Allow connecting to verify post attachment size")
    allow_net_book_quote = BooleanField("Allow connecting to get book quotes")
    allow_net_ntp = BooleanField("Allow connecting to NTP to sync time")
    never_auto_download_unencrypted = BooleanField("Never allow auto-download of unencrypted attachments")
    allow_unencrypted_encryption_option = BooleanField("Allow unencrypted as attachment option")
    auto_dl_from_unknown_upload_sites = BooleanField("Automatically download from unknown upload sites")
    delete_sent_identity_msgs = BooleanField("Automatically delete sent Identity messages")
    debug_posts = BooleanField("Show Debug Information for Boards/Threads/Posts")
    post_timestamp = StringField("Post Timestamp to Use")
    post_timestamp_timezone = StringField("Post Timestamp Timezone")
    post_timestamp_hour = StringField("Post Timestamp Hour Format")
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
    get_new_rand_tor = SubmitField("Get New Random BitChan Onion Address")
    get_new_bm_tor = SubmitField("Get New Bitmessage Onion Address")
    enable_cus_tor_address = BooleanField("Enable Custom Tor Address")
    tor_file = FileField()
    save_tor_settings = SubmitField("Save Tor Settings")
    save_chan_options = SubmitField("Save Options")

    # Bitmessage
    bm_connections_in_out = StringField("Incoming and Outgoing Connections")
    bitmessage_onion_services_only = BooleanField("Only Allow Bitmessage to Connect to Onion Services")

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
    kiosk_allow_gpg = BooleanField("Allow Users to Encrypt PGP Messages in Posts")
    kiosk_disable_bm_attach = BooleanField("Disable Bitmessage as a Post Upload Method")
    kiosk_allow_download = BooleanField("Allow Users to Initiate Post Downloads")
    kiosk_ttl_option = StringField("TTL Option")
    kiosk_ttl_seconds = IntegerField("TTL Value")
    kiosk_post_rate_limit = IntegerField("Post Refractory Period (seconds)")
    kiosk_max_post_size_bytes = IntegerField("Maximum Post Size (bytes)")
    kiosk_attempts_login = IntegerField("Maximum Login Attempts")
    kiosk_ban_login_sec = IntegerField("Login Ban Length (seconds)")
    kiosk_only_admin_access_mod_log = BooleanField("Only Kiosk Admins Can View Mod Log")


class Status(FlaskForm):
    tor_newnym = StringField("Tor NEWNYM")


class Regex(FlaskForm):
    text = TextAreaField("Text")
    regex = TextAreaField("Regex")
    test_regex = SubmitField("Text Regex")
