from sqlalchemy.orm import relationship

from database import CRUDMixin
from flask_extensions import db


class PostDeletePasswordHashes(CRUDMixin, db.Model):
    __tablename__ = "post_delete_password_hash"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    message_id = db.Column(db.String, unique=True, default=None)
    password_hash = db.Column(db.String, default=None)
    address_from = db.Column(db.String, default=None)
    address_to = db.Column(db.String, default=None)
    timestamp_utc = db.Column(db.Integer, default=None)

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
    address_to = db.Column(db.String, default=None)
    expires_time = db.Column(db.Integer, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class DeletedThreads(CRUDMixin, db.Model):
    __tablename__ = "deleted_threads"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    thread_hash = db.Column(db.String, unique=True, default=None)
    subject = db.Column(db.String, default=None)
    board_address = db.Column(db.String, default=None)
    timestamp_utc = db.Column(db.Integer, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class Captcha(CRUDMixin, db.Model):
    __tablename__ = "captcha"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    captcha_id = db.Column(db.String, unique=True, default=None)
    captcha_answer = db.Column(db.String, default=None)
    timestamp_utc = db.Column(db.Integer, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class SessionInfo(CRUDMixin, db.Model):
    __tablename__ = "session_info"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    session_id = db.Column(db.String, unique=True, default=None)
    request_rate_ts = db.Column(db.Float, default=0.0)
    request_rate_amt = db.Column(db.Integer, default=0)
    verified = db.Column(db.Boolean, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class PostCards(CRUDMixin, db.Model):
    __tablename__ = "post_card"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    message_id = db.Column(db.String, default=None)
    thread_id = db.Column(db.Integer, default=None)
    card_html = db.Column(db.String, default=None)
    regenerate = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class ModLog(CRUDMixin, db.Model):
    __tablename__ = "mod_log"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    message_id = db.Column(db.String, default=None)
    timestamp = db.Column(db.Float, default=None)
    description = db.Column(db.String, default=None)
    user_from = db.Column(db.String, default=None)
    board_address = db.Column(db.String, db.ForeignKey('chan.address'), default=None)
    thread_hash = db.Column(db.String, default=None)
    success = db.Column(db.Boolean, default=True)
    hidden = db.Column(db.Boolean, default=False)

    chan = relationship("Chan", back_populates="mod_log")

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)


class EndpointCount(CRUDMixin, db.Model):
    __tablename__ = "endpoint_count"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    timestamp_epoch = db.Column(db.Integer, default=None)
    category = db.Column(db.String, default=None)
    endpoint = db.Column(db.String, default=None)
    requests = db.Column(db.Integer, default=None)
    thread_hash = db.Column(db.String, default=None)
    chan_address = db.Column(db.String, default=None)
    new_posts = db.Column(db.Integer, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
