"""add string_replacement

Revision ID: 000000000078
Revises: 000000000077
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000078'
down_revision = '000000000077'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    op.create_table(
        'string_replacement',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('name', sa.String),
        sa.Column('string', sa.String),
        sa.Column('regex', sa.String),
        sa.Column('string_replacement', sa.String),
        sa.Column('only_board_address', sa.String),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True)


def downgrade():
    op.drop_table('string_replacement')
