from database import CRUDMixin
from flask_extensions import db


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
    allow_net_file_size_check = db.Column(db.Boolean, default=True)
    allow_net_book_quote = db.Column(db.Boolean, default=True)
    allow_net_ntp = db.Column(db.Boolean, default=False)
    never_auto_download_unencrypted = db.Column(db.Boolean, default=True)

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
