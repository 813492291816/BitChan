"""add chan_update_row_count

Revision ID: 000000000142
Revises: 000000000141
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000142'
down_revision = '000000000141'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.add_column(sa.Column('chan_update_row_count', sa.Integer))
    except Exception as err:
        print(err)

    try:
        op.execute(
            '''
            UPDATE settings_global
            SET chan_update_row_count=5
            '''
        )
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.drop_column('chan_update_row_count')
    except Exception as err:
        print(err)