from database import CRUDMixin
from flask_extensions import db
from sqlalchemy.orm import relationship


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
    primary_addresses = db.Column(db.String, default="[]")
    secondary_addresses = db.Column(db.String, default="[]")
    tertiary_addresses = db.Column(db.String, default="[]")
    restricted_addresses = db.Column(db.String, default="[]")
    rules = db.Column(db.String, default="{}")
    label = db.Column(db.String, default=None)
    description = db.Column(db.String, default=None)
    is_setup = db.Column(db.Boolean, default=False)
    image_banner_base64 = db.Column(db.String, default=None)
    image_banner_timestamp_utc = db.Column(db.Integer, default=0)

    # List-specific
    list = db.Column(db.String, default="{}")
    list_message_id_owner = db.Column(db.String, default=None)
    list_message_expires_time_owner = db.Column(db.Integer, default=None)
    list_message_timestamp_utc_owner = db.Column(db.Integer, default=None)
    list_message_id_user = db.Column(db.String, default=None)
    list_message_expires_time_user = db.Column(db.Integer, default=None)
    list_message_timestamp_utc_user = db.Column(db.Integer, default=None)
    list_send = db.Column(db.Boolean, default=False)

    threads = relationship("Threads", back_populates="chan")

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
    op_md5_hash = db.Column(db.String, default=None)  # The hash of the OP
    subject = db.Column(db.String, default=None)
    timestamp_sent = db.Column(db.Integer, default=0)
    timestamp_received = db.Column(db.Integer, default=0)

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
    expires_time = db.Column(db.Integer, default=None)
    address_from = db.Column(db.String, default=None)
    timestamp_received = db.Column(db.Integer, default=None)
    timestamp_sent = db.Column(db.Integer, default=None)
    is_op = db.Column(db.Boolean, default=None)  # Is this message an OP or not
    message_md5_hash = db.Column(db.String, default=None)  # This message payload MD5 hash
    subject = db.Column(db.String, default=None)
    message = db.Column(db.String, default=None)
    nation = db.Column(db.String, default=None)
    file_decoded = db.Column(db.String, default=None)
    file_filename = db.Column(db.String, default=None)
    file_extension = db.Column(db.String, default=None)
    file_url = db.Column(db.String, default=None)
    file_extracts_start_base64 = db.Column(db.String, default=None)
    file_size = db.Column(db.Float, default=None)
    file_do_not_download = db.Column(db.Boolean, default=False)
    file_currently_downloading = db.Column(db.Boolean, default=False)
    file_progress = db.Column(db.String, default="")
    file_download_successful = db.Column(db.Boolean, default=False)
    file_md5_hash = db.Column(db.String, default=None)
    file_md5_hashes_match = db.Column(db.Boolean, default=None)
    upload_filename = db.Column(db.String, default=None)
    saved_file_filename = db.Column(db.String, default=None)
    saved_image_thumb_filename = db.Column(db.String, default=None)
    media_width = db.Column(db.Integer, default=None)
    media_height = db.Column(db.Integer, default=None)
    image_spoiler = db.Column(db.Boolean, default=None)
    message_original = db.Column(db.String, default=None)
    passphrase_pgp = db.Column(db.String, default=None)
    decrypted_pgp = db.Column(db.Boolean, default=None)
    message_steg = db.Column(db.String, default=None)
    replies = db.Column(db.String, default="[]")

    thread = relationship("Threads", back_populates="messages")

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class DeletedMessages(CRUDMixin, db.Model):
    __tablename__ = "deleted_message"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    message_id = db.Column(db.String, unique=True, default=None)
    address_from = db.Column(db.String, default=None)
    expires_time = db.Column(db.Integer, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
