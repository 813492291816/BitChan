from config import VERSION_ALEMBIC
from database import CRUDMixin
from flask_extensions import db


class Alembic(CRUDMixin, db.Model):
    __tablename__ = "alembic_version"
    __table_args__ = {
        'extend_existing': True
    }

    version_num = db.Column(db.String(32), primary_key=True, nullable=False, default=VERSION_ALEMBIC)

    def __repr__(self):
        return "<{cls}(version_num={s.version_num})>".format(
            s=self, cls=self.__class__.__name__)
