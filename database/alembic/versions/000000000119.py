"""add always_allow_my_i2p_bittorrent_attachments and auto_start_torrent columns

Revision ID: 000000000119
Revises: 000000000118
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000119'
down_revision = '000000000118'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.add_column(sa.Column('always_allow_my_i2p_bittorrent_attachments', sa.Boolean))

        with op.batch_alter_table("upload_torrents") as batch_op:
            batch_op.add_column(sa.Column('auto_start_torrent', sa.Boolean))

        op.execute(
            '''
            UPDATE settings_global
            SET always_allow_my_i2p_bittorrent_attachments=0
            '''
        )
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.drop_column('always_allow_my_i2p_bittorrent_attachments')

        with op.batch_alter_table("upload_torrents") as batch_op:
            batch_op.drop_column('auto_start_torrent')
    except Exception as err:
        print(err)