# Execute following alembic database upgrade
# latest revision at top
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../..")))

from database.alembic_utils import get_versions
from config import ALEMBIC_POST
from config import DB_PATH
from database.utils import session_scope
import traceback


if __name__ == "__main__":
    error = []
    print("+++ post-upgrade versions found: {con}".format(con=get_versions()))

    for version in get_versions():
        if not version:
            print("+++ Error: empty revision")

        # elif version == '000000000000':
        #     print("+++ Found version {}".format(version))
        #     try:
        #         from database.models import AddressBook
        #         with session_scope(DB_PATH) as session:
        #             new_add = AddressBook()
        #             new_add.test = "EXAMPLE"
        #             session.add(new_add)
        #             session.commit()
        #
        #             mod_add = session.query(AddressBook).filter(
        #                 AddressBook.test == "EXAMPLE").first()
        #             if mod_add:
        #                 mod_add.test = "TEST"
        #                 session.commit()
        #     except Exception:
        #         msg = "+++ Error: Revision {}: {}".format(version, traceback.format_exc())
        #         print(msg)
        #         error.append(msg)

        elif version == '000000000021':
            print("+++ Found version {}".format(version))
            try:
                from database.models import Threads
                with session_scope(DB_PATH) as session:
                    threads = session.query(Threads).all()
                    for each_thread in threads:
                        try:
                            each_thread.thread_hash_short = each_thread.thread_hash[-12:]
                            session.commit()
                        except:
                            pass
            except Exception:
                msg = "+++ Error: Revision {}: {}".format(version, traceback.format_exc())
                print(msg)
                error.append(msg)

        else:
            print("+++ Error: unknown revision {}".format(version))

    if error:
        print("+++ Errors were encountered. See log.")
    else:
        try:
            os.remove(ALEMBIC_POST)
            print("+++ Deleting {}".format(ALEMBIC_POST))
        except Exception:
            pass
