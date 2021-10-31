"""add session info table

Revision ID: 000000000012
Revises: 000000000011
Create Date: 2021-09-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000012'
down_revision = '000000000011'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    op.create_table(
        'session_info',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('session_id', sa.String),
        sa.Column('request_rate_ts', sa.Float),
        sa.Column('request_rate_amt', sa.Integer),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True)


def downgrade():
    op.drop_table('session_info')
