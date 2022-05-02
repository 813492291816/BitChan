"""create table deleted_threads

Revision ID: 000000000034
Revises: 000000000033
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000034'
down_revision = '000000000033'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'deleted_threads',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('thread_hash', sa.String),
        sa.Column('board_address', sa.String),
        sa.Column('timestamp_utc', sa.Integer),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True
    )


def downgrade():
    op.drop_table('deleted_threads')
