"""add popup_html

Revision ID: 000000000002
Revises: 000000000001
Create Date: 2021-03-06 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000002'
down_revision = '000000000001'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('popup_html', sa.String))

    op.execute(
        '''
        UPDATE message
        SET popup_html=''
        '''
    )


def downgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('popup_html')
