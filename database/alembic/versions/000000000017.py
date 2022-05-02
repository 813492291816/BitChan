"""add home_page_msg to settings_global

Revision ID: 000000000017
Revises: 000000000016
Create Date: 2021-10-06 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000017'
down_revision = '000000000016'
branch_labels = None
depends_on = None

HOME_MESSAGE = """<div class="bold" style="text-align: center;">
  BitChan is a decentralized anonymous imageboard built on top of <a class="link" target="_blank" href="https://github.com/Bitmessage/PyBitmessage">Bitmessage</a> with <a class="link" target="_blank" href="https://www.torproject.org">Tor</a> and <a class="link" target="_blank" href="https://gnupg.org">GnuPG</a>. Learn more in the <a class="link" href="/help">manual</a>.
</div>"""


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('home_page_msg', sa.String))

    op.execute(
        '''
        UPDATE settings_global
        SET home_page_msg='{}'
        '''.format(HOME_MESSAGE)
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('home_page_msg')
