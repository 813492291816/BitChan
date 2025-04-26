"""add file_torrent_hash column

Revision ID: 000000000120
Revises: 000000000119
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000120'
down_revision = '000000000119'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("message") as batch_op:
            batch_op.add_column(sa.Column('file_torrent_hash', sa.String(255)))
    except Exception as err:
        print(err)

def downgrade():
    try:
        with op.batch_alter_table("message") as batch_op:
            batch_op.drop_column('file_torrent_hash')
    except Exception as err:
        print(err)
