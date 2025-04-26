"""add SchedulePost table

Revision ID: 000000000131
Revises: 000000000130
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import MEDIUMTEXT

revision = '000000000131'
down_revision = '000000000130'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        op.create_table(
            'schedule_post',
            sa.Column('id', sa.Integer, nullable=False, unique=True),
            sa.Column('schedule_id', sa.String(255), nullable=False, unique=True),
            sa.Column('post_options', MEDIUMTEXT),
            sa.Column('dict_message', MEDIUMTEXT),
            sa.Column('schedule_post_epoch', sa.Integer),
            sa.Column('start_send_ts', sa.Integer),
            sa.PrimaryKeyConstraint('id'),
            keep_existing=True)
    except Exception as err:
        print(err)


def downgrade():
    try:
        op.drop_table('schedule_post')
    except Exception as err:
        print(err)
