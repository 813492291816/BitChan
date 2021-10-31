"""add per page settings to settings_global

Revision ID: 000000000018
Revises: 000000000017
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000018'
down_revision = '000000000017'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('results_per_page_board', sa.Integer))
        batch_op.add_column(sa.Column('results_per_page_recent', sa.Integer))
        batch_op.add_column(sa.Column('results_per_page_search', sa.Integer))
        batch_op.add_column(sa.Column('results_per_page_overboard', sa.Integer))
        batch_op.add_column(sa.Column('results_per_page_catalog', sa.Integer))

    op.execute(
        '''
        UPDATE settings_global
        SET results_per_page_board=15
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET results_per_page_recent=25
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET results_per_page_search=25
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET results_per_page_overboard=64
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET results_per_page_catalog=64
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('results_per_page_board')
        batch_op.drop_column('results_per_page_recent')
        batch_op.drop_column('results_per_page_search')
        batch_op.drop_column('results_per_page_overboard')
        batch_op.drop_column('results_per_page_catalog')
