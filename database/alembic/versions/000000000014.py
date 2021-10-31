"""add rate limiting options to settings

Revision ID: 000000000014
Revises: 000000000013
Create Date: 2021-09-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000014'
down_revision = '000000000013'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('enable_page_rate_limit', sa.Boolean))
        batch_op.add_column(sa.Column('max_requests_per_period', sa.Integer))
        batch_op.add_column(sa.Column('rate_limit_period_seconds', sa.Integer))

    op.execute(
        '''
        UPDATE settings_global
        SET enable_page_rate_limit=0
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET max_requests_per_period=10
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET rate_limit_period_seconds=60
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('enable_page_rate_limit')
        batch_op.drop_column('max_requests_per_period')
        batch_op.drop_column('rate_limit_period_seconds')
