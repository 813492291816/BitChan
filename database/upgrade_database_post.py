# Execute following alembic database upgrade
# latest revision at top
import os, sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../..")))

from database.alembic_utils import get_versions
from config import ALEMBIC_POST
from config import DATABASE_BITCHAN
from database.utils import session_scope


DB_BITCHAN = 'sqlite:///' + DATABASE_BITCHAN


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
        #         with session_scope(DB_BITCHAN) as session:
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
