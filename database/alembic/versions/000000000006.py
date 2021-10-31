"""add post_number to message table and last_post_number to chan table

Revision ID: 000000000006
Revises: 000000000005
Create Date: 2021-09-11 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000006'
down_revision = '000000000005'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('post_number', sa.Integer))

    with op.batch_alter_table("chan") as batch_op:
        batch_op.add_column(sa.Column('last_post_number', sa.Integer))

    op.execute(
        '''
        UPDATE chan
        SET last_post_number=0
        '''
    )


def downgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('post_number')

    with op.batch_alter_table("chan") as batch_op:
        batch_op.drop_column('last_post_number')
