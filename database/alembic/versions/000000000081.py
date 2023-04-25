"""add start_download to message table

Revision ID: 000000000081
Revises: 000000000080
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000081'
down_revision = '000000000080'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('original_message', sa.Text))


def downgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('original_message')
