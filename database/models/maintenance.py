from database import CRUDMixin
from flask_extensions import db
from sqlalchemy.orm import relationship


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


class PostMessages(CRUDMixin, db.Model):
    __tablename__ = "post_message"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    ack_id = db.Column(db.String, unique=True, default=None)
    address_from = db.Column(db.String, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
