"""add anchor columns to thread

Revision ID: 000000000029
Revises: 000000000028
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000029'
down_revision = '000000000028'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("thread") as batch_op:
        batch_op.add_column(sa.Column('anchored_local', sa.Boolean))
        batch_op.add_column(sa.Column('anchored_local_ts', sa.Integer))

    op.execute(
        '''
        UPDATE thread
        SET anchored_local=0
        '''
    )

    op.execute(
        '''
        UPDATE thread
        SET anchored_local_ts=0
        '''
    )


def downgrade():
    with op.batch_alter_table("thread") as batch_op:
        batch_op.drop_column('anchored_local')
        batch_op.drop_column('anchored_local_ts')
