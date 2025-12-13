"""change column form float to int

Revision ID: 000000000141
Revises: 000000000140
Create Date: 2057-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000141'
down_revision = '000000000140'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    try:
        with op.batch_alter_table("mod_log") as batch_op:
            batch_op.alter_column('timestamp', existing_type=sa.Float(), type_=sa.Integer())
    except Exception as err:
        print(err)


def downgrade():
    try:
        with op.batch_alter_table("mod_log") as batch_op:
            batch_op.alter_column('timestamp', existing_type=sa.Integer(), type_=sa.Float())
    except Exception as err:
        print(err)
