"""create table captcha

Revision ID: 000000000035
Revises: 000000000034
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000035'
down_revision = '000000000034'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'captcha',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('captcha_id', sa.String),
        sa.Column('captcha_answer', sa.String),
        sa.Column('timestamp_utc', sa.Integer),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True
    )


def downgrade():
    op.drop_table('captcha')
