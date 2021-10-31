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
  BitChan is a decentralized anonymous imageboard built on top of <a class="link" target="_blank" href="https://github.com/Bitmessage/PyBitmessage">Bitmessage</a> with <a class="link" target="_blank" href="https://www.torproject.org">Tor</a> and <a class="link" target="_blank" href="https://gnupg.org">GnuPG</a>.
</div>
<div style="padding-top: 1em;">
  This is a beta release of BitChan. Some features are only partially implemented and there are likely to be bugs. Please report any issues or bugs you find with a <a class="link" href="/bug_report">Bug Report</a>. Also watch the official <a class="link" href="/board/BM-2cVZdtgUe7uq7LbWx12W2btJybAphF3VxG/1">BitChan-Dev Board</a> for announcements, the <a class="link" href="/list/BM-2cUYu7r41Bbnox4P8gEVtdnZGLnisgG7Yu">BitChan List</a> for other boards and lists that may appear for discussion and other purposes, and the <a class="link" href="https://www.github.com/813492291816/BitChan">BitChan GitHub page</a> for updates to the code.
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
