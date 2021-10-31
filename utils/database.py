import logging
import time

import config
from database.utils import session_scope

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger("bitchan.database")


def get_db_table_flask(tab, unique_id=None, entry=None):
    if unique_id:
        return_table = tab.query.filter(tab.unique_id == unique_id)
    else:
        return_table = tab.query

    if entry == 'first' or unique_id:
        return_table = return_table.first()
    elif entry == 'all':
        return_table = return_table.all()

    return return_table


def get_db_table_daemon(tab, unique_id=None, entry=None):
    count = 3
    while count > 0:
        try:
            with session_scope(DB_PATH) as new_session:
                if unique_id:
                    return_table = new_session.query(tab).filter(
                        tab.unique_id == unique_id)
                else:
                    return_table = new_session.query(tab)

                if entry == 'first' or unique_id:
                    return_table = return_table.first()
                elif entry == 'all':
                    return_table = return_table.all()

                new_session.expunge_all()
                new_session.close()
            return return_table
        except Exception:
            logger.exception("read database")

        time.sleep(0.5)
        count -= 1
