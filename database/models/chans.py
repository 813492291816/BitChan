import json

from sqlalchemy.dialects.mysql import MEDIUMBLOB
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import relationship

from database import CRUDMixin
from flask_extensions import db


class AddressBook(CRUDMixin, db.Model):
    __tablename__ = "address_book"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    address = db.Column(db.String(255), unique=True, default=None)
    label = db.Column(db.String(255), default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Identity(CRUDMixin, db.Model):
    __tablename__ = "identity"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    address = db.Column(db.String(255), unique=True, default=None)
    label = db.Column(db.String(255), default=None)
    passphrase_base64 = db.Column(MEDIUMTEXT, default=None)
    total_messages = db.Column(db.Integer, default=0)
    unread_messages = db.Column(db.Integer, default=0)
    short_address = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Command(CRUDMixin, db.Model):
    __tablename__ = "command"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    timestamp_utc = db.Column(db.Integer, default=None)
    action = db.Column(db.String(255), default=None)
    action_type = db.Column(db.String(255), default=None)
    do_not_send = db.Column(db.Boolean, default=False)
    chan_address = db.Column(db.String(255), default=None)
    thread_id = db.Column(db.Integer, default=None)
    message_id = db.Column(db.String(255), default=None)
    options = db.Column(MEDIUMTEXT, default="{}")
    locally_deleted = db.Column(db.Boolean, default=False)
    locally_restored = db.Column(db.Boolean, default=False)

    # Thread options
    thread_sticky = db.Column(db.Boolean, default=False)
    thread_sticky_timestamp_utc = db.Column(db.Integer, default=0)
    thread_lock = db.Column(db.Boolean, default=False)
    thread_lock_ts = db.Column(db.Integer, default=0)
    thread_lock_timestamp_utc = db.Column(db.Integer, default=0)
    thread_anchor = db.Column(db.Boolean, default=False)
    thread_anchor_ts = db.Column(db.Integer, default=0)
    thread_anchor_timestamp_utc = db.Column(db.Integer, default=0)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Chan(CRUDMixin, db.Model):
    __tablename__ = "chan"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    access = db.Column(db.String(255), default=None)
    type = db.Column(db.String(255), default=None)
    passphrase = db.Column(MEDIUMTEXT, default=None)
    address = db.Column(db.String(255), unique=True, default=None)
    unlisted = db.Column(db.Boolean, default=False)
    restricted = db.Column(db.Boolean, default=False)
    hide_passphrase = db.Column(db.Boolean, default=False)
    primary_addresses = db.Column(db.Text, default="[]")
    secondary_addresses = db.Column(db.Text, default="[]")
    tertiary_addresses = db.Column(db.Text, default="[]")
    restricted_addresses = db.Column(db.Text, default="[]")
    rules = db.Column(MEDIUMTEXT, default="{}")
    pgp_passphrase_msg = db.Column(db.Text, default="")
    pgp_passphrase_attach = db.Column(db.Text, default="")
    pgp_passphrase_steg = db.Column(db.Text, default="")
    label = db.Column(db.String(255), default=None)
    description = db.Column(db.Text, default=None)
    is_setup = db.Column(db.Boolean, default=False)
    timestamp_sent = db.Column(db.Integer, default=0)
    timestamp_received = db.Column(db.Integer, default=0)
    default_from_address = db.Column(db.String(255), default=None)
    allow_css = db.Column(db.Boolean, default=False)
    last_post_number = db.Column(db.Integer, default=0)
    regenerate_numbers = db.Column(db.Boolean, default=False)

    # List-specific
    list = db.Column(MEDIUMTEXT, default="{}")
    list_timestamp_changed = db.Column(db.Integer, default=0)
    list_message_id_owner = db.Column(db.String(255), default=None)
    list_message_expires_time_owner = db.Column(db.Integer, default=None)
    list_message_timestamp_utc_owner = db.Column(db.Integer, default=None)
    list_message_id_user = db.Column(db.String(255), default=None)
    list_message_expires_time_user = db.Column(db.Integer, default=None)
    list_message_timestamp_utc_user = db.Column(db.Integer, default=None)
    list_send = db.Column(db.Boolean, default=False)

    threads = relationship("Threads", back_populates="chan")

    # Not used, can be removed
    image_banner_base64 = db.Column(MEDIUMTEXT, default=None)
    image_banner_timestamp_utc = db.Column(db.Integer, default=0)
    image_spoiler_base64 = db.Column(MEDIUMTEXT, default=None)
    image_spoiler_timestamp_utc = db.Column(db.Integer, default=0)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Threads(CRUDMixin, db.Model):
    __tablename__ = "thread"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    chan_id = db.Column(db.Integer, db.ForeignKey('chan.id'), default=None)
    thread_hash = db.Column(db.String(512), unique=True, default=None)
    thread_hash_short = db.Column(db.String(255), default=None)
    op_sha256_hash = db.Column(db.String(255), default=None)  # The hash of the OP
    default_from_address = db.Column(db.String(255), default=None)
    subject = db.Column(db.Text, default=None)
    timestamp_sent = db.Column(db.Integer, default=0)
    timestamp_received = db.Column(db.Integer, default=0)
    stickied_local = db.Column(db.Boolean, default=False)
    locked_local = db.Column(db.Boolean, default=False)
    locked_local_ts = db.Column(db.Integer, default=0)
    anchored_local = db.Column(db.Boolean, default=False)
    anchored_local_ts = db.Column(db.Integer, default=0)
    hide = db.Column(db.Boolean, default=False)
    time_ts = db.Column(db.Integer, default=0)
    orig_op_bm_json_obj = db.Column(MEDIUMTEXT, default=None)
    last_op_json_obj_ts = db.Column(db.Integer, default=0)

    chan = relationship("Chan", back_populates="threads")
    messages = relationship("Messages", back_populates="thread")

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Messages(CRUDMixin, db.Model):
    __tablename__ = "message"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    thread_id = db.Column(db.Integer, db.ForeignKey('thread.id'), default=None)
    message_id = db.Column(db.String(255), default=None)
    post_id = db.Column(db.String(255), default=None)
    post_number = db.Column(db.Integer, default=None)
    expires_time = db.Column(db.Integer, default=None)
    address_from = db.Column(db.String(255), default=None)
    timestamp_received = db.Column(db.Integer, default=0)
    timestamp_sent = db.Column(db.Integer, default=0)
    is_op = db.Column(db.Boolean, default=None)  # Is this message an OP or not
    message_sha256_hash = db.Column(db.String(255), default=None)  # This message payload SHA256 hash
    sage = db.Column(db.Boolean, default=False)
    subject = db.Column(db.Text, default=None)
    original_message = db.Column(MEDIUMTEXT, default=None)
    message = db.Column(MEDIUMTEXT, default=None)
    nation = db.Column(db.String(255), default=None)
    nation_base64 = db.Column(db.Text, default=None)
    nation_name = db.Column(db.String(255), default=None)
    file_decoded = db.Column(MEDIUMBLOB, default=None)
    file_filename = db.Column(db.Text, default=None)
    file_extension = db.Column(db.String(255), default=None)
    file_url = db.Column(db.Text, default=None)
    file_torrent_file_hash = db.Column(db.String(255), default=None)
    file_torrent_decoded = db.Column(db.LargeBinary, default=None)
    file_torrent_magnet = db.Column(db.Text, default=None)
    file_upload_settings = db.Column(db.Text, default="{}")
    file_extracts_start_base64 = db.Column(db.Text, default=None)
    file_size = db.Column(db.Float, default=None)
    file_amount = db.Column(db.Integer, default=None)
    file_do_not_download = db.Column(db.Boolean, default=False)
    file_currently_downloading = db.Column(db.Boolean, default=False)
    file_progress = db.Column(db.Text, default="")
    file_download_successful = db.Column(db.Boolean, default=False)
    file_sha256_hash = db.Column(db.String(255), default=None)
    file_enc_cipher = db.Column(db.String(255), default=None)
    file_enc_key_bytes = db.Column(db.Integer, default=None)
    file_enc_password = db.Column(db.Text, default=None)
    file_sha256_hashes_match = db.Column(db.Boolean, default=None)
    file_order = db.Column(db.Text, default="[]")
    start_download = db.Column(db.Boolean, default=False)
    upload_filename = db.Column(db.Text, default=None)
    saved_file_filename = db.Column(db.Text, default=None)
    saved_image_thumb_filename = db.Column(db.Text, default=None)
    media_info = db.Column(db.Text, default="{}")
    media_width = db.Column(db.Integer, default=None)
    media_height = db.Column(db.Integer, default=None)
    image1_spoiler = db.Column(db.Boolean, default=None)
    image2_spoiler = db.Column(db.Boolean, default=None)
    image3_spoiler = db.Column(db.Boolean, default=None)
    image4_spoiler = db.Column(db.Boolean, default=None)
    delete_password_hash = db.Column(db.String(255), default=None)
    message_original = db.Column(MEDIUMTEXT, default=None)
    message_steg = db.Column(MEDIUMTEXT, default="{}")
    popup_html = db.Column(MEDIUMTEXT, default="")
    popup_moderate = db.Column(db.Text, default="")
    regenerate_popup_html = db.Column(db.Boolean, default=True)
    hide = db.Column(db.Boolean, default=False)
    time_ts = db.Column(db.Integer, default=0)
    delete_comment = db.Column(db.Text, default=None)
    post_html = db.Column(MEDIUMTEXT, default=None)
    post_html_board_view = db.Column(MEDIUMTEXT, default=None)
    text_replacements = db.Column(MEDIUMTEXT, default=None)
    regenerate_post_html = db.Column(db.Boolean, default=False)
    post_ids_replied_to = db.Column(db.Text, default="[]")  # Reply Post IDs in this message
    post_ids_replying_to_msg = db.Column(db.Text, default="[]")  # Post IDs that reply to this message

    # GPG
    gpg_texts = db.Column(MEDIUMTEXT, default="{}")

    # Games
    game_password_a = db.Column(db.Text, default=None)
    game_password_b_hash = db.Column(db.String(255), default=None)
    game_player_move = db.Column(db.Text, default=None)
    game_image_file = db.Column(db.Text, default=None)
    game_image_name = db.Column(db.Text, default=None)
    game_image_extension = db.Column(db.String(255), default=None)
    game_message_extra = db.Column(db.Text, default=None)

    thread = relationship("Threads", back_populates="messages")

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class UploadProgress(CRUDMixin, db.Model):
    __tablename__ = "upload_progress"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    upload_id = db.Column(db.String(255), unique=True, default=None)
    uploading = db.Column(db.Boolean, default=None)
    subject = db.Column(db.Text, default=None)
    total_size_bytes = db.Column(db.Integer, default=None)
    progress = db.Column(db.Text, default=None)
    progress_ts = db.Column(db.Integer, default=None)
    progress_size_bytes = db.Column(db.Integer, default=0)
    progress_percent = db.Column(db.Float, default=0)
    post_message = db.Column(MEDIUMTEXT, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class AdminMessageStore(CRUDMixin, db.Model):
    __tablename__ = "admin_message_store"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    message_id = db.Column(db.String(255), unique=True, default=None)
    time_added = db.Column(db.DateTime, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Games(CRUDMixin, db.Model):
    __tablename__ = "games"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    game_hash = db.Column(db.String(255), unique=True, default=None)
    thread_hash = db.Column(db.String(255), default=None)
    is_host = db.Column(db.Boolean, default=None)
    host_from_address = db.Column(db.String(255), default=None)
    moves = db.Column(MEDIUMTEXT, default=json.dumps({"game_moves": [], "game_log": []}))
    players = db.Column(db.Text, default="{}")
    turn_player = db.Column(db.String(255), default=None)
    turn_ts = db.Column(db.Integer, default=None)
    game_type = db.Column(db.String(255), default=None)
    game_ts = db.Column(db.Integer, default=None)
    game_initiated = db.Column(db.String(255), default=None)
    game_over = db.Column(db.Boolean, default=False)
    game_termination_pw_hash = db.Column(db.String(255), default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class PGP(CRUDMixin, db.Model):
    __tablename__ = "pgp"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    fingerprint = db.Column(db.String(255), unique=True, default=None)
    key_id = db.Column(db.String(255), unique=True, default=None)
    passphrase = db.Column(db.Text, default=None)
    keyring_name = db.Column(db.Text, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class BanedHashes(CRUDMixin, db.Model):
    __tablename__ = "banned_hashes"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.Text, default=None)
    hash = db.Column(db.String(255), default=None)
    imagehash = db.Column(db.String(255), default=None)
    thumb_filename = db.Column(db.Text, default=None)
    thumb_b64 = db.Column(db.Text, default=None)
    only_board_address = db.Column(db.Text, default="")

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class BanedWords(CRUDMixin, db.Model):
    __tablename__ = "banned_words"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.Text, default=None)
    word = db.Column(db.Text, default=None)
    is_regex = db.Column(db.Boolean, default=None)
    only_board_address = db.Column(db.Text, default="")

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class StringReplace(CRUDMixin, db.Model):
    __tablename__ = "string_replacement"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.Text, default="")
    string = db.Column(db.Text, default="")
    regex = db.Column(db.Text, default="")
    string_replacement = db.Column(db.Text, default="")
    only_board_address = db.Column(db.Text, default="")

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
