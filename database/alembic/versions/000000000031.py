"""add thread options to command

Revision ID: 000000000031
Revises: 000000000030
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000031'
down_revision = '000000000030'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("command") as batch_op:
        batch_op.add_column(sa.Column('thread_sticky', sa.Boolean))
        batch_op.add_column(sa.Column('thread_sticky_timestamp_utc', sa.Integer))
        batch_op.add_column(sa.Column('thread_lock', sa.Boolean))
        batch_op.add_column(sa.Column('thread_lock_ts', sa.Integer))
        batch_op.add_column(sa.Column('thread_lock_timestamp_utc', sa.Integer))
        batch_op.add_column(sa.Column('thread_anchor', sa.Boolean))
        batch_op.add_column(sa.Column('thread_anchor_ts', sa.Integer))
        batch_op.add_column(sa.Column('thread_anchor_timestamp_utc', sa.Integer))

    op.execute(
        '''
        UPDATE command
        SET thread_sticky=0
        '''
    )
    op.execute(
        '''
        UPDATE command
        SET thread_sticky_timestamp_utc=0
        '''
    )

    op.execute(
        '''
        UPDATE command
        SET thread_lock=0
        '''
    )
    op.execute(
        '''
        UPDATE command
        SET thread_lock_ts=0
        '''
    )
    op.execute(
        '''
        UPDATE command
        SET thread_lock_timestamp_utc=0
        '''
    )

    op.execute(
        '''
        UPDATE command
        SET thread_anchor=0
        '''
    )
    op.execute(
        '''
        UPDATE command
        SET thread_anchor_ts=0
        '''
    )
    op.execute(
        '''
        UPDATE command
        SET thread_anchor_timestamp_utc=0
        '''
    )


def downgrade():
    with op.batch_alter_table("command") as batch_op:
        batch_op.drop_column('thread_sticky')
        batch_op.drop_column('thread_sticky_timestamp_utc')
        batch_op.drop_column('thread_lock')
        batch_op.drop_column('thread_lock_ts')
        batch_op.drop_column('thread_lock_timestamp_utc')
        batch_op.drop_column('thread_anchor')
        batch_op.drop_column('thread_anchor_ts')
        batch_op.drop_column('thread_anchor_timestamp_utc')
