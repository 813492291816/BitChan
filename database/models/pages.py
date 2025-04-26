from sqlalchemy.dialects.mysql import MEDIUMTEXT

from database import CRUDMixin
from flask_extensions import db


class Pages(CRUDMixin, db.Model):
    __tablename__ = "pages"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.String(255), unique=True, default=None)
    slug = db.Column(db.String(255), unique=True, default=None)
    html = db.Column(MEDIUMTEXT, default=None)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
