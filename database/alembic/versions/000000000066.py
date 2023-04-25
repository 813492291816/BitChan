"""add replace_download_domain to upload_sites

Revision ID: 000000000066
Revises: 000000000065
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000066'
down_revision = '000000000065'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    op.create_table(
        'pgp',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('fingerprint', sa.String),
        sa.Column('passphrase', sa.String),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True)


def downgrade():
    op.drop_table('pgp')
