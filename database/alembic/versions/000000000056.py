"""add post_html_board_view to endpoint_count

Revision ID: 000000000056
Revises: 000000000055
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000056'
down_revision = '000000000055'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("endpoint_count") as batch_op:
        batch_op.add_column(sa.Column('thread_hash', sa.String))
        batch_op.add_column(sa.Column('chan_address', sa.String))


def downgrade():
    with op.batch_alter_table("endpoint_count") as batch_op:
        batch_op.drop_column('thread_hash')
        batch_op.drop_column('chan_address')
