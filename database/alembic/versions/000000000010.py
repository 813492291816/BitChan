"""add enable_verification to settings table

Revision ID: 000000000010
Revises: 000000000009
Create Date: 2021-09-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000010'
down_revision = '000000000009'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('enable_verification', sa.Boolean))

    op.execute(
        '''
        UPDATE settings_global
        SET enable_verification=0
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('enable_verification')
