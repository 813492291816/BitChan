"""add archive_epoch

Revision ID: 000000000140
Revises: 000000000139
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000140'
down_revision = '000000000139'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("thread") as batch_op:
            batch_op.add_column(sa.Column('archive_epoch', sa.Integer))
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("thread") as batch_op:
            batch_op.drop_column('archive_epoch')
    except Exception as err:
        print(err)
