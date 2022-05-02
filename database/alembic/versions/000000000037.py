"""create table captcha

Revision ID: 000000000037
Revises: 000000000036
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000037'
down_revision = '000000000036'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'post_delete_password_hash',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('message_id', sa.String),
        sa.Column('password_hash', sa.String),
        sa.Column('address_from', sa.String),
        sa.Column('address_to', sa.String),
        sa.Column('timestamp_utc', sa.Integer),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True
    )


def downgrade():
    op.drop_table('post_delete_password_hash')
