"""add pow_method and pow_token

Revision ID: 000000000123
Revises: 000000000122
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000123'
down_revision = '000000000122'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("message") as batch_op:
            batch_op.add_column(sa.Column('pow_method', sa.Text))
            batch_op.add_column(sa.Column('pow_token', sa.Text))
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("message") as batch_op:
            batch_op.drop_column('pow_method')
            batch_op.drop_column('pow_token')
    except Exception as err:
        print(err)
