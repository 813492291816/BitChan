"""add pow_filter_value

Revision ID: 000000000129
Revises: 000000000128
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import BIGINT

revision = '000000000129'
down_revision = '000000000128'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("message") as batch_op:
            batch_op.add_column(sa.Column('pow_filter_value', BIGINT))

        op.execute(
            '''
            UPDATE message
            SET pow_filter_value=0
            '''
        )
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("message") as batch_op:
            batch_op.drop_column('pow_filter_value')
    except Exception as err:
        print(err)
