"""add remote thread attributes

Revision ID: 000000000137
Revises: 000000000136
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000137'
down_revision = '000000000136'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("thread") as batch_op:
            batch_op.add_column(sa.Column('anchored_remote', sa.Boolean))
            batch_op.add_column(sa.Column('stickied_remote', sa.Boolean))
            batch_op.add_column(sa.Column('locked_remote', sa.Boolean))
    except Exception as err:
        print(err)

    try:
        op.execute(
            '''
            UPDATE thread
            SET anchored_remote=0
            '''
        )

        op.execute(
            '''
            UPDATE thread
            SET stickied_remote=0
            '''
        )

        op.execute(
            '''
            UPDATE thread
            SET locked_remote=0
            '''
        )
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("thread") as batch_op:
            batch_op.drop_column('anchored_remote')
            batch_op.drop_column('stickied_remote')
            batch_op.drop_column('locked_remote')
    except Exception as err:
        print(err)
