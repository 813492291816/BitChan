"""add popup_moderate to command

Revision ID: 000000000045
Revises: 000000000044
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000045'
down_revision = '000000000044'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("command") as batch_op:
        batch_op.add_column(sa.Column('locally_deleted', sa.Boolean))
        batch_op.add_column(sa.Column('locally_restored', sa.Boolean))

    op.execute(
        '''
        UPDATE command
        SET locally_deleted=0
        '''
    )

    op.execute(
        '''
        UPDATE command
        SET locally_restored=0
        '''
    )


def downgrade():
    with op.batch_alter_table("command") as batch_op:
        batch_op.drop_column('locally_deleted')
        batch_op.drop_column('locally_restored')
