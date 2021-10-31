"""add sticky, lock to thread

Revision ID: 000000000027
Revises: 000000000026
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000027'
down_revision = '000000000026'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("thread") as batch_op:
        batch_op.add_column(sa.Column('stickied_local', sa.Boolean))
        batch_op.add_column(sa.Column('locked_local', sa.Boolean))

    op.execute(
        '''
        UPDATE thread
        SET stickied_local=0
        '''
    )

    op.execute(
        '''
        UPDATE thread
        SET locked_local=0
        '''
    )


def downgrade():
    with op.batch_alter_table("thread") as batch_op:
        batch_op.drop_column('stickied_local')
        batch_op.drop_column('locked_local')
