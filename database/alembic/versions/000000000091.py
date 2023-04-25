"""add message to upload table

Revision ID: 000000000091
Revises: 000000000090
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000091'
down_revision = '000000000090'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("upload_progress") as batch_op:
        batch_op.add_column(sa.Column('post_message', sa.String))

    op.execute(
        '''
        UPDATE upload_progress
        SET post_message=""
        '''
    )


def downgrade():
    with op.batch_alter_table("upload_progress") as batch_op:
        batch_op.drop_column('post_message')
