"""add hide_from_recent

Revision ID: 000000000136
Revises: 000000000135
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000136'
down_revision = '000000000135'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("chan") as batch_op:
            batch_op.add_column(sa.Column('hide_from_recent', sa.Boolean))
    except Exception as err:
        print(err)

    try:
        op.execute(
            '''
            UPDATE chan
            SET hide_from_recent=0
            '''
        )
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("chan") as batch_op:
            batch_op.drop_column('hide_from_recent')
    except Exception as err:
        print(err)
