from database import CRUDMixin
from flask_extensions import db

HOME_MESSAGE = """<div class="bold" style="text-align: center;">
  BitChan is a decentralized anonymous imageboard built on top of <a class="link" target="_blank" href="https://github.com/Bitmessage/PyBitmessage">Bitmessage</a> with <a class="link" target="_blank" href="https://www.torproject.org">Tor</a> and <a class="link" target="_blank" href="https://gnupg.org">GnuPG</a>.
</div>
<div style="padding-top: 1em;">
  This is a beta release of BitChan. Some features are only partially implemented and there are likely to be bugs. Please report any issues or bugs you find with a <a class="link" href="/bug_report">Bug Report</a>. Also watch the official <a class="link" href="/board/BM-2cVZdtgUe7uq7LbWx12W2btJybAphF3VxG/1">BitChan-Dev Board</a> for announcements, the <a class="link" href="/list/BM-2cUYu7r41Bbnox4P8gEVtdnZGLnisgG7Yu">BitChan List</a> for other boards and lists that may appear for discussion and other purposes, and the <a class="link" href="https://www.github.com/813492291816/BitChan">BitChan GitHub page</a> for updates to the code.
</div>"""


class Flags(CRUDMixin, db.Model):
    __tablename__ = "flags"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.String, default=None)
    flag_extension = db.Column(db.String, default=None)
    flag_base64 = db.Column(db.String, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class GlobalSettings(CRUDMixin, db.Model):
    __tablename__ = "settings_global"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    theme = db.Column(db.String, default="Frosty")
    discard_message_ids = db.Column(db.String, default="[]")
    clear_inventory = db.Column(db.Boolean, default=False)
    messages_per_mailbox_page = db.Column(db.Integer, default=5)
    messages_current = db.Column(db.Integer, default=0)
    messages_older = db.Column(db.Integer, default=0)
    messages_newer = db.Column(db.Integer, default=0)
    chan_update_display_number = db.Column(db.Integer, default=5)
    max_download_size = db.Column(db.Float, default=0.0)
    max_extract_size = db.Column(db.Float, default=20.0)
    allow_net_file_size_check = db.Column(db.Boolean, default=True)
    allow_net_book_quote = db.Column(db.Boolean, default=True)
    allow_net_ntp = db.Column(db.Boolean, default=False)
    never_auto_download_unencrypted = db.Column(db.Boolean, default=True)
    auto_dl_from_unknown_upload_sites = db.Column(db.Boolean, default=False)
    delete_sent_identity_msgs = db.Column(db.Boolean, default=False)
    enable_captcha = db.Column(db.Boolean, default=False)
    enable_verification = db.Column(db.Boolean, default=False)
    home_page_msg = db.Column(db.String, default=HOME_MESSAGE)
    html_head = db.Column(db.String, default="")
    html_body = db.Column(db.String, default="")
    results_per_page_board = db.Column(db.Integer, default=15)
    results_per_page_recent = db.Column(db.Integer, default=35)
    results_per_page_search = db.Column(db.Integer, default=35)
    results_per_page_overboard = db.Column(db.Integer, default=64)
    results_per_page_catalog = db.Column(db.Integer, default=64)
    results_per_page_mod_log = db.Column(db.Integer, default=30)

    # Security
    enable_page_rate_limit = db.Column(db.Boolean, default=False)
    max_requests_per_period = db.Column(db.Integer, default=10)
    rate_limit_period_seconds = db.Column(db.Integer, default=60)
    hide_all_board_list_passphrases = db.Column(db.Boolean, default=False)

    # Kiosk Mode
    enable_kiosk_mode = db.Column(db.Boolean, default=False)
    kiosk_login_to_view = db.Column(db.Boolean, default=False)
    kiosk_allow_posting = db.Column(db.Boolean, default=False)
    kiosk_disable_bm_attach = db.Column(db.Boolean, default=False)
    kiosk_allow_download = db.Column(db.Boolean, default=False)
    kiosk_post_rate_limit = db.Column(db.Integer, default=50)
    kiosk_attempts_login = db.Column(db.Integer, default=5)
    kiosk_ban_login_sec = db.Column(db.Integer, default=300)
    kiosk_only_admin_access_mod_log = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class UploadSites(CRUDMixin, db.Model):
    __tablename__ = "upload_sites"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    domain = db.Column(db.String, default=None)
    type = db.Column(db.String, default=None)
    uri = db.Column(db.String, default=None)
    download_prefix = db.Column(db.String, default=None)
    response = db.Column(db.String, default=None)
    direct_dl_url = db.Column(db.Boolean, default=None)
    extra_curl_options = db.Column(db.String, default=None)
    upload_word = db.Column(db.String, default=None)
    form_name = db.Column(db.String, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
