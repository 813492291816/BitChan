"""add replace_download_domain to upload_sites

Revision ID: 000000000071
Revises: 000000000070
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000071'
down_revision = '000000000070'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    op.create_table(
        'banned_hashes',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('name', sa.String),
        sa.Column('hash', sa.String),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True)


def downgrade():
    op.drop_table('banned_hashes')
