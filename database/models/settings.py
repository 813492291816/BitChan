from database import CRUDMixin
from flask_extensions import db


class GlobalSettings(CRUDMixin, db.Model):
    __tablename__ = "settings_global"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    theme = db.Column(db.String, default="Frosty")
    discard_message_ids = db.Column(db.String, default=None)
    clear_inventory = db.Column(db.Boolean, default=False)
    messages_current = db.Column(db.Integer, default=0)
    messages_older = db.Column(db.Integer, default=0)
    messages_newer = db.Column(db.Integer, default=0)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
