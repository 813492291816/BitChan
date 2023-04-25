"""add progress

Revision ID: 000000000090
Revises: 000000000089
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000090'
down_revision = '000000000089'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("upload_progress") as batch_op:
        batch_op.add_column(sa.Column('progress', sa.String))

    op.execute(
        '''
        UPDATE upload_progress
        SET progress=""
        '''
    )


def downgrade():
    with op.batch_alter_table("upload_progress") as batch_op:
        batch_op.drop_column('progress')
