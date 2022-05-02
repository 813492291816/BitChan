import json

from sqlalchemy.orm import relationship

from database import CRUDMixin
from flask_extensions import db


class AddressBook(CRUDMixin, db.Model):
    __tablename__ = "address_book"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    address = db.Column(db.String, unique=True, default=None)
    label = db.Column(db.String, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Identity(CRUDMixin, db.Model):
    __tablename__ = "identity"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    address = db.Column(db.String, unique=True, default=None)
    label = db.Column(db.String, default=None)
    passphrase_base64 = db.Column(db.String, default=None)
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
    action = db.Column(db.String, default=None)
    action_type = db.Column(db.String, default=None)
    do_not_send = db.Column(db.Boolean, default=False)
    chan_address = db.Column(db.String, default=None)
    thread_id = db.Column(db.String, default=None)
    message_id = db.Column(db.String, default=None)
    options = db.Column(db.String, default="{}")
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
    access = db.Column(db.String, default=None)
    type = db.Column(db.String, default=None)
    passphrase = db.Column(db.String, unique=True, default=None)
    address = db.Column(db.String, unique=True, default=None)
    unlisted = db.Column(db.Boolean, default=False)
    primary_addresses = db.Column(db.String, default="[]")
    secondary_addresses = db.Column(db.String, default="[]")
    tertiary_addresses = db.Column(db.String, default="[]")
    restricted_addresses = db.Column(db.String, default="[]")
    rules = db.Column(db.String, default="{}")
    pgp_passphrase_msg = db.Column(db.String, default="")
    pgp_passphrase_attach = db.Column(db.String, default="")
    pgp_passphrase_steg = db.Column(db.String, default="")
    label = db.Column(db.String, default=None)
    description = db.Column(db.String, default=None)
    is_setup = db.Column(db.Boolean, default=False)
    timestamp_sent = db.Column(db.Integer, default=0)
    timestamp_received = db.Column(db.Integer, default=0)
    default_from_address = db.Column(db.String, default=None)
    allow_css = db.Column(db.Boolean, default=False)
    last_post_number = db.Column(db.Integer, default=0)
    regenerate_numbers = db.Column(db.Boolean, default=False)

    # List-specific
    list = db.Column(db.String, default="{}")
    list_timestamp_changed = db.Column(db.Integer, default=0)
    list_message_id_owner = db.Column(db.String, default=None)
    list_message_expires_time_owner = db.Column(db.Integer, default=None)
    list_message_timestamp_utc_owner = db.Column(db.Integer, default=None)
    list_message_id_user = db.Column(db.String, default=None)
    list_message_expires_time_user = db.Column(db.Integer, default=None)
    list_message_timestamp_utc_user = db.Column(db.Integer, default=None)
    list_send = db.Column(db.Boolean, default=False)

    threads = relationship("Threads", back_populates="chan")
    mod_log = relationship("ModLog", back_populates="chan")

    # Not used, can be removed
    image_banner_base64 = db.Column(db.String, default=None)
    image_banner_timestamp_utc = db.Column(db.Integer, default=0)
    image_spoiler_base64 = db.Column(db.String, default=None)
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
    thread_hash = db.Column(db.String, unique=True, default=None)
    thread_hash_short = db.Column(db.String, default=None)
    op_sha256_hash = db.Column(db.String, default=None)  # The hash of the OP
    default_from_address = db.Column(db.String, default=None)
    subject = db.Column(db.String, default=None)
    timestamp_sent = db.Column(db.Integer, default=0)
    timestamp_received = db.Column(db.Integer, default=0)
    stickied_local = db.Column(db.Boolean, default=False)
    locked_local = db.Column(db.Boolean, default=False)
    locked_local_ts = db.Column(db.Integer, default=0)
    anchored_local = db.Column(db.Boolean, default=False)
    anchored_local_ts = db.Column(db.Integer, default=0)
    hide = db.Column(db.Boolean, default=False)
    time_ts = db.Column(db.Integer, default=0)

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
    thread_id = db.Column(db.String, db.ForeignKey('thread.id'), default=None)
    message_id = db.Column(db.String, default=None)
    post_id = db.Column(db.String, default=None)
    post_number = db.Column(db.Integer, default=None)
    expires_time = db.Column(db.Integer, default=None)
    address_from = db.Column(db.String, default=None)
    timestamp_received = db.Column(db.Integer, default=0)
    timestamp_sent = db.Column(db.Integer, default=0)
    is_op = db.Column(db.Boolean, default=None)  # Is this message an OP or not
    message_sha256_hash = db.Column(db.String, default=None)  # This message payload SHA256 hash
    sage = db.Column(db.Boolean, default=False)
    subject = db.Column(db.String, default=None)
    message = db.Column(db.String, default=None)
    nation = db.Column(db.String, default=None)
    nation_base64 = db.Column(db.String, default=None)
    nation_name = db.Column(db.String, default=None)
    file_decoded = db.Column(db.String, default=None)
    file_filename = db.Column(db.String, default=None)
    file_extension = db.Column(db.String, default=None)
    file_url = db.Column(db.String, default=None)
    file_upload_settings = db.Column(db.String, default="{}")
    file_extracts_start_base64 = db.Column(db.String, default=None)
    file_size = db.Column(db.Float, default=None)
    file_amount = db.Column(db.Integer, default=None)
    file_do_not_download = db.Column(db.Boolean, default=False)
    file_currently_downloading = db.Column(db.Boolean, default=False)
    file_progress = db.Column(db.String, default="")
    file_download_successful = db.Column(db.Boolean, default=False)
    file_sha256_hash = db.Column(db.String, default=None)
    file_enc_cipher = db.Column(db.String, default=None)
    file_enc_key_bytes = db.Column(db.Integer, default=None)
    file_enc_password = db.Column(db.String, default=None)
    file_sha256_hashes_match = db.Column(db.Boolean, default=None)
    file_order = db.Column(db.String, default="[]")
    upload_filename = db.Column(db.String, default=None)
    saved_file_filename = db.Column(db.String, default=None)
    saved_image_thumb_filename = db.Column(db.String, default=None)
    media_info = db.Column(db.String, default="{}")
    media_width = db.Column(db.Integer, default=None)
    media_height = db.Column(db.Integer, default=None)
    image1_spoiler = db.Column(db.Boolean, default=None)
    image2_spoiler = db.Column(db.Boolean, default=None)
    image3_spoiler = db.Column(db.Boolean, default=None)
    image4_spoiler = db.Column(db.Boolean, default=None)
    delete_password_hash = db.Column(db.String, default=None)
    message_original = db.Column(db.String, default=None)
    message_steg = db.Column(db.String, default="{}")
    popup_html = db.Column(db.String, default="")
    popup_moderate = db.Column(db.String, default="")
    regenerate_popup_html = db.Column(db.Boolean, default=True)
    hide = db.Column(db.Boolean, default=False)
    time_ts = db.Column(db.Integer, default=0)
    delete_comment = db.Column(db.String, default=None)
    post_html = db.Column(db.String, default=None)
    post_html_board_view = db.Column(db.String, default=None)
    regenerate_post_html = db.Column(db.Boolean, default=False)
    post_ids_replied_to = db.Column(db.String, default="[]")  # Reply Post IDs in this message
    post_ids_replying_to_msg = db.Column(db.String, default="[]")  # Post IDs that reply to this message

    # Games
    game_password_a = db.Column(db.String, default=None)
    game_password_b_hash = db.Column(db.String, default=None)
    game_player_move = db.Column(db.String, default=None)
    game_image_file = db.Column(db.String, default=None)
    game_image_name = db.Column(db.String, default=None)
    game_image_extension = db.Column(db.String, default=None)
    game_message_extra = db.Column(db.String, default=None)

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
    upload_id = db.Column(db.String, unique=True, default=None)
    uploading = db.Column(db.Boolean, default=None)
    subject = db.Column(db.String, default=None)
    total_size_bytes = db.Column(db.Integer, default=None)
    progress_size_bytes = db.Column(db.Integer, default=0)
    progress_percent = db.Column(db.Float, default=0)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class AdminMessageStore(CRUDMixin, db.Model):
    __tablename__ = "admin_message_store"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    message_id = db.Column(db.String, unique=True, default=None)
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
    game_hash = db.Column(db.String, unique=True, default=None)
    thread_hash = db.Column(db.String, default=None)
    is_host = db.Column(db.Boolean, default=None)
    host_from_address = db.Column(db.String, default=None)
    moves = db.Column(db.String, default=json.dumps({"game_moves": [], "game_log": []}))
    players = db.Column(db.String, default="{}")
    turn_player = db.Column(db.String, default=None)
    turn_ts = db.Column(db.Integer, default=None)
    game_type = db.Column(db.String, default=None)
    game_ts = db.Column(db.Integer, default=None)
    game_initiated = db.Column(db.String, default=None)
    game_over = db.Column(db.Boolean, default=False)
    game_termination_pw_hash = db.Column(db.String, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
