"""add post_ids_replying_to_msg to message

Revision ID: 000000000059
Revises: 000000000058
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000059'
down_revision = '000000000058'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('post_ids_replying_to_msg', sa.String))

    op.execute(
        '''
        UPDATE message
        SET post_ids_replying_to_msg="[]"
        '''
    )


def downgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('post_ids_replying_to_msg')
