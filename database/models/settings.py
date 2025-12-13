import json

from sqlalchemy.dialects.mysql import MEDIUMTEXT

from database import CRUDMixin
from flask_extensions import db

HOME_MESSAGE = """<div class="bold" style="text-align: center;">
  BitChan is a decentralized anonymous imageboard built on top of <a class="link" target="_blank" href="https://github.com/Bitmessage/PyBitmessage">Bitmessage</a> with <a class="link" target="_blank" href="https://www.torproject.org">Tor</a>, <a class="link" target="_blank" href="https://i2pd.website">I2P</a>, and <a class="link" target="_blank" href="https://gnupg.org">GnuPG</a>. Learn more in the <a class="link" href="/help">manual</a>.
</div>"""


class Flags(CRUDMixin, db.Model):
    __tablename__ = "flags"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.String(255), default=None)
    flag_extension = db.Column(db.String(255), default=None)
    flag_base64 = db.Column(db.Text, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class GlobalSettings(CRUDMixin, db.Model):
    __tablename__ = "settings_global"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)

    # General
    maintenance_mode = db.Column(db.Boolean, default=False)
    debug_posts = db.Column(db.Boolean, default=False)
    theme = db.Column(db.String(255), default="Frosty")
    font_size = db.Column(db.Float, default=10.0)
    chan_update_display_number = db.Column(db.Integer, default=5)
    chan_update_row_count = db.Column(db.Integer, default=5)
    max_download_size = db.Column(db.Float, default=0.0)
    max_extract_size = db.Column(db.Float, default=20.0)
    form_default_upload_method = db.Column(db.String(255), default="Frosty")
    always_allow_my_i2p_bittorrent_attachments = db.Column(db.Boolean, default=True)
    allow_net_file_size_check = db.Column(db.Boolean, default=True)
    allow_net_book_quote = db.Column(db.Boolean, default=True)
    never_auto_download_unencrypted = db.Column(db.Boolean, default=True)
    allow_unencrypted_encryption_option = db.Column(db.Boolean, default=False)
    auto_dl_from_unknown_upload_sites = db.Column(db.Boolean, default=False)
    delete_sent_identity_msgs = db.Column(db.Boolean, default=False)
    post_timestamp = db.Column(db.String(255), default="sent")
    post_timestamp_timezone = db.Column(db.String(255), default="UTC")
    post_timestamp_hour = db.Column(db.String(255), default="24")
    title_text = db.Column(db.String(255), default="BitChan")
    results_per_page_board = db.Column(db.Integer, default=15)
    results_per_page_overboard = db.Column(db.Integer, default=64)
    results_per_page_catalog = db.Column(db.Integer, default=64)
    results_per_page_recent = db.Column(db.Integer, default=35)
    results_per_page_search = db.Column(db.Integer, default=35)
    results_per_page_mod_log = db.Column(db.Integer, default=30)
    home_page_msg = db.Column(MEDIUMTEXT, default=HOME_MESSAGE)
    html_head = db.Column(MEDIUMTEXT, default="")
    html_body = db.Column(MEDIUMTEXT, default="")
    random_post_method = db.Column(db.String(255), default="all_posts")

    # Bitmessage
    bm_connections_in_out = db.Column(db.String(255), default="minode_i2p_only")
    bitmessage_onion_services_only = db.Column(db.Boolean, default=False)

    # Kiosk Mode
    enable_kiosk_mode = db.Column(db.Boolean, default=False)
    kiosk_login_to_view = db.Column(db.Boolean, default=False)
    kiosk_allow_posting = db.Column(db.Boolean, default=False)
    kiosk_disable_bm_attach = db.Column(db.Boolean, default=False)
    kiosk_disable_i2p_torrent_attach = db.Column(db.Boolean, default=False)
    kiosk_disable_torrent_file_download = db.Column(db.Boolean, default=False)
    kiosk_allow_download = db.Column(db.Boolean, default=False)
    kiosk_ttl_option = db.Column(db.String(255), default="selectable_max_28_days")
    kiosk_ttl_seconds = db.Column(db.Integer, default=2419200)  # 28 days (max allowed by bitmessage)
    kiosk_post_rate_limit = db.Column(db.Integer, default=50)
    kiosk_max_post_size_bytes = db.Column(db.Integer, default=0)
    kiosk_attempts_login = db.Column(db.Integer, default=5)
    kiosk_ban_login_sec = db.Column(db.Integer, default=300)
    kiosk_only_admin_access_mod_log = db.Column(db.Boolean, default=True)
    kiosk_only_admin_access_search = db.Column(db.Boolean, default=True)
    kiosk_allow_gpg = db.Column(db.Boolean, default=False)
    kiosk_allow_pow = db.Column(db.Boolean, default=False)

    # Security
    enable_page_rate_limit = db.Column(db.Boolean, default=False)
    max_requests_per_period = db.Column(db.Integer, default=10)
    rate_limit_period_seconds = db.Column(db.Integer, default=60)
    remote_delete_action = db.Column(db.String(255), default="delete")  # delete/hide when post/thread remotely deleted
    enable_captcha = db.Column(db.Boolean, default=False)
    enable_verification = db.Column(db.Boolean, default=False)
    hide_version = db.Column(db.Boolean, default=False)
    disable_downloading_upload_site = db.Column(db.Boolean, default=False)
    disable_downloading_i2p_torrent = db.Column(db.Boolean, default=False)
    ttl_seed_i2p_torrent_op_days = db.Column(db.Integer, default=60)
    ttl_seed_i2p_torrent_reply_days = db.Column(db.Integer, default=60)

    # RSS
    rss_enable = db.Column(db.Boolean, default=False)
    rss_enable_i2p = db.Column(db.Boolean, default=False)
    rss_url = db.Column(db.Text, default="http://BitChanURL.onion")
    rss_url_i2p = db.Column(db.Text, default="http://BitChanURL.i2p")
    rss_number_posts = db.Column(db.Integer, default=30)
    rss_char_length = db.Column(db.Integer, default=250)
    rss_use_html_posts = db.Column(db.Boolean, default=False)
    rss_rate_limit_number_requests = db.Column(db.Integer, default=10)
    rss_rate_limit_period_sec = db.Column(db.Integer, default=60)

    # Misc
    discard_message_ids = db.Column(MEDIUMTEXT, default="[]")
    clear_inventory = db.Column(db.Boolean, default=False)
    messages_per_mailbox_page = db.Column(db.Integer, default=5)
    messages_current = db.Column(db.Integer, default=0)
    messages_older = db.Column(db.Integer, default=0)
    messages_newer = db.Column(db.Integer, default=0)
    i2p_trackers = db.Column(db.Text, default=json.dumps([
        'http://opentracker.r4sas.i2p/a',
        'http://opentracker.skank.i2p/a',
        'http://opentracker.dg2.i2p/a',
        'http://punzipidirfqspstvzpj6gb4tkuykqp6quurj6e23bgxcxhdoe7q.b32.i2p/a',
        'http://w7tpbzncbcocrqtwwm3nezhnnsw4ozadvi2hmvzdhrqzfxfum7wa.b32.i2p/a',
        'http://6a4kxkg5wp33p25qqhgwl6sj4yh4xuf5b3p3qldwgclebchm3eea.b32.i2p/announce.php'
    ]))

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class UploadSites(CRUDMixin, db.Model):
    __tablename__ = "upload_sites"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    enabled = db.Column(db.Boolean, default=None)
    domain = db.Column(db.String(255), default=None)
    type = db.Column(db.String(255), default=None)
    subtype = db.Column(db.String(255), default=None)
    uri = db.Column(db.String(255), default=None)
    download_prefix = db.Column(db.String(255), default=None)
    response = db.Column(db.String(255), default=None)
    json_key = db.Column(db.String(255), default=None)
    direct_dl_url = db.Column(db.Boolean, default=None)
    extra_curl_options = db.Column(db.Text, default=None)
    upload_word = db.Column(db.String(255), default=None)
    form_name = db.Column(db.String(255), default=None)
    http_headers = db.Column(db.Text, default=None)
    proxy_type = db.Column(db.String(255), default=None)
    replace_download_domain = db.Column(db.Text, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class UploadTorrents(CRUDMixin, db.Model):
    __tablename__ = "upload_torrents"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    file_hash = db.Column(db.String(255), default=None)
    torrent_hash = db.Column(db.String(255), default=None)
    timestamp_started = db.Column(db.Float, default=None)
    auto_start_torrent = db.Column(db.Boolean, default=False)
    torrent_completed = db.Column(db.Boolean, default=False)
    message_id = db.Column(db.String(255), default=None)

    # No longer used. Can be deleted
    torrent_generated = db.Column(db.Boolean, default=False)
    metadata_id = db.Column(db.String(255), default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class RateLimit(CRUDMixin, db.Model):
    __tablename__ = "rate_limit"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    rate_id = db.Column(db.String(255), default=None)
    dt = db.Column(db.DateTime, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
