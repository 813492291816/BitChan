from database import CRUDMixin
from flask_extensions import db


class Auth(CRUDMixin, db.Model):
    __tablename__ = "auth"
    __table_args__ = {
        'extend_existing': True
    }

    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.String(255), default=None, unique=True)
    password_hash = db.Column(db.Text, default=None)
    single_session = db.Column(db.Boolean, default=False)
    global_admin = db.Column(db.Boolean, default=False)
    can_post = db.Column(db.Boolean, default=False)
    janitor = db.Column(db.Boolean, default=False)
    board_list_admin = db.Column(db.Boolean, default=False)
    admin_boards = db.Column(db.Text, default="[]")
    require_change_pw = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return "<{cls}(id={rep.id})>".format(
            cls=self.__class__.__name__, rep=self)
