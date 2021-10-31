"""add post card table

Revision ID: 000000000015
Revises: 000000000014
Create Date: 2021-09-23 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000015'
down_revision = '000000000014'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    op.create_table(
        'post_card',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('message_id', sa.String),
        sa.Column('card_html', sa.String),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True)


def downgrade():
    op.drop_table('post_card')
