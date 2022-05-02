"""add game_termination_pw_hash to games

Revision ID: 000000000049
Revises: 000000000048
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000049'
down_revision = '000000000048'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("games") as batch_op:
        batch_op.add_column(sa.Column('game_termination_pw_hash', sa.String))


def downgrade():
    with op.batch_alter_table("games") as batch_op:
        batch_op.drop_column('game_termination_pw_hash')
