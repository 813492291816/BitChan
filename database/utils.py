import logging
import time
from contextlib import contextmanager
from sqlite3 import OperationalError

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import DB_PATH

logger = logging.getLogger(__name__)


@contextmanager
def session_scope(db_uri):
    Session = sessionmaker()
    engine = create_engine(db_uri, pool_size=10, max_overflow=10)
    Session.configure(bind=engine)
    session = Session()
    try:
        yield session
        session.commit()
    except Exception as e:
        logger.exception("session_scope error. Rolled back: error='{e}'".format(u=db_uri, e=e))
        session.rollback()
        raise
    finally:
        session.close()


def db_return(table, index=None):
    attempts = 3
    while attempts > 0:
        try:
            with session_scope(DB_PATH) as new_session:
                return_table = new_session.query(table)

                if index == 'first':
                    return_table = return_table.first()
                elif index == 'all':
                    return_table = return_table.all()

                new_session.expunge_all()
                new_session.close()
            return return_table
        except OperationalError:
            pass
        except sqlalchemy.exc.OperationalError:
            pass

        if attempts == 1:
            logger.exception("Can't read database")
        else:
            logger.error("Database locked.")
        time.sleep(0.5)
        attempts -= 1
