"""add delete_sent_identity_msgs to settings_global table

Revision ID: 000000000007
Revises: 000000000006
Create Date: 2021-09-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000007'
down_revision = '000000000006'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('delete_sent_identity_msgs', sa.Boolean))

    op.execute(
        '''
        UPDATE settings_global
        SET delete_sent_identity_msgs=1
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('delete_sent_identity_msgs')
