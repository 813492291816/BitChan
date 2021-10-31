"""add mod_log table

Revision ID: 000000000023
Revises: 000000000022
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000023'
down_revision = '000000000022'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    op.create_table(
        'mod_log',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('message_id', sa.String),
        sa.Column('timestamp', sa.Float),
        sa.Column('description', sa.String),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('results_per_page_mod_log', sa.Integer))

    op.execute(
        '''
        UPDATE settings_global
        SET results_per_page_mod_log=30
        '''
    )


def downgrade():
    op.drop_table('mod_log')

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('results_per_page_mod_log')
