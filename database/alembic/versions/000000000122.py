"""add pages

Revision ID: 000000000122
Revises: 000000000121
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import MEDIUMTEXT

revision = '000000000122'
down_revision = '000000000121'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        op.create_table(
            'pages',
            sa.Column('id', sa.Integer, nullable=False, unique=True),
            sa.Column('name', sa.String(255)),
            sa.Column('html', MEDIUMTEXT),
            sa.PrimaryKeyConstraint('id'),
            keep_existing=True)
    except Exception as err:
        print(err)


def downgrade():
    try:
        op.drop_table('pages')
    except Exception as err:
        print(err)
