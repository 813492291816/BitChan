"""add mod_log columns

Revision ID: 000000000024
Revises: 000000000023
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000024'
down_revision = '000000000023'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("mod_log") as batch_op:
        batch_op.add_column(sa.Column('user_from', sa.String))
        batch_op.add_column(sa.Column('board_address', sa.String))
        batch_op.add_column(sa.Column('thread_hash', sa.String))


def downgrade():
    with op.batch_alter_table("mod_log") as batch_op:
        batch_op.drop_column('user_from')
        batch_op.drop_column('board_address')
        batch_op.drop_column('thread_hash')
