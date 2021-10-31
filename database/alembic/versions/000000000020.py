"""add regenerate_numbers to chan

Revision ID: 000000000020
Revises: 000000000019
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000020'
down_revision = '000000000019'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("chan") as batch_op:
        batch_op.add_column(sa.Column('regenerate_numbers', sa.Boolean))


    op.execute(
        '''
        UPDATE chan
        SET regenerate_numbers=0
        '''
    )


def downgrade():
    with op.batch_alter_table("chan") as batch_op:
        batch_op.drop_column('regenerate_numbers')
