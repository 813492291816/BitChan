"""add post_replies

Revision ID: 000000000001
Revises: 000000000000
Create Date: 2021-03-06 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000001'
down_revision = '000000000000'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'post_replies',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('post_id', sa.String, nullable=False, unique=True),
        sa.Column('reply_ids', sa.Text),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True
    )

def downgrade():
    op.drop_table('post_replies')
