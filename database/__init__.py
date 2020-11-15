from flask import current_app

from flask_extensions import db


class CRUDMixin(object):
    def save(self):
        try:
            db.session.add(self)
            db.session.commit()
            return self
        except Exception as e:
            db.session.rollback()
            current_app.logger.error("Can't save {mod}, error: {e}".format(mod=self, e=e))

    def delete(self):
        try:
            db.session.delete(self)
            db.session.commit()
        except Exception as e:
            current_app.logger.error("Can't delete '{rec}': '{e}'".format(rec=self, e=e))
