"""add hide options to thread and message

Revision ID: 000000000040
Revises: 000000000039
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000040'
down_revision = '000000000039'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("thread") as batch_op:
        batch_op.add_column(sa.Column('hide', sa.Boolean))
        batch_op.add_column(sa.Column('time_ts', sa.Integer))

    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('hide', sa.Boolean))
        batch_op.add_column(sa.Column('time_ts', sa.Integer))

    op.execute(
        '''
        UPDATE thread
        SET hide=0
        '''
    )

    op.execute(
        '''
        UPDATE thread
        SET time_ts=0
        '''
    )

    op.execute(
        '''
        UPDATE message
        SET hide=0
        '''
    )

    op.execute(
        '''
        UPDATE message
        SET time_ts=0
        '''
    )


def downgrade():
    with op.batch_alter_table("thread") as batch_op:
        batch_op.drop_column('hide')
        batch_op.drop_column('time_ts')

    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('hide')
        batch_op.drop_column('time_ts')
