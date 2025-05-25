"""add form_default_upload_method

Revision ID: 000000000132
Revises: 000000000131
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000132'
down_revision = '000000000131'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.add_column(sa.Column('form_default_upload_method', sa.String(255)))

        op.execute(
            '''
            UPDATE settings_global
            SET form_default_upload_method="bitmessage"
            '''
        )
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("settings_global") as batch_op:
            batch_op.drop_column('form_default_upload_method')
    except Exception as err:
        print(err)
