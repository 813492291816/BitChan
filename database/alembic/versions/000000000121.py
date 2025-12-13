"""add enable_search

Revision ID: 000000000121
Revises: 000000000120
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000121'
down_revision = '000000000120'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.add_column(sa.Column('kiosk_only_admin_access_search', sa.Boolean))
    except Exception as err:
        print(err)

    try:
        op.execute(
            '''
            UPDATE settings_global
            SET kiosk_only_admin_access_search=1
            '''
        )
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.drop_column('kiosk_only_admin_access_search')
    except Exception as err:
        print(err)
