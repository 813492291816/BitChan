"""add total_messages to identity table

Revision ID: 000000000008
Revises: 000000000007
Create Date: 2021-09-14 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000008'
down_revision = '000000000007'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("identity") as batch_op:
        batch_op.add_column(sa.Column('total_messages', sa.Integer))

    op.execute(
        '''
        UPDATE identity
        SET total_messages=0
        '''
    )


def downgrade():
    with op.batch_alter_table("identity") as batch_op:
        batch_op.drop_column('total_messages')
