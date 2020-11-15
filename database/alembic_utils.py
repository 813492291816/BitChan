# adds versions to file
import os
import sys

sys.path.append(os.path.abspath(os.path.join(__file__, "../..")))

from config import ALEMBIC_POST


def get_versions():
    try:
        with open(ALEMBIC_POST, 'r') as fd:
            return fd.read().splitlines()
    except Exception:
        return []


def post_alembic_write(revision):
    with open(ALEMBIC_POST, 'a') as versions_file:
        versions_file.write('{}\n'.format(revision))
