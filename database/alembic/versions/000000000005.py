"""add post_id to message table

Revision ID: 000000000005
Revises: 000000000004
Create Date: 2021-09-11 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000005'
down_revision = '000000000004'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('post_id', sa.String))


def downgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('post_id')
