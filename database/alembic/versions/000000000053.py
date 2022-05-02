"""add endpoint_count table

Revision ID: 000000000053
Revises: 000000000052
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000053'
down_revision = '000000000052'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'endpoint_count',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('endpoint', sa.String),
        sa.Column('timestamp_epoch', sa.Integer),
        sa.Column('requests', sa.Integer),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True
    )


def downgrade():
    op.drop_table('endpoint_count')
