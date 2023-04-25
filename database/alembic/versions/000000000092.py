"""add orig_op_bm_message

Revision ID: 000000000092
Revises: 000000000091
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000092'
down_revision = '000000000091'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("thread") as batch_op:
        batch_op.add_column(sa.Column('orig_op_bm_json_obj', sa.String))
        batch_op.add_column(sa.Column('last_op_json_obj_ts', sa.Integer))


def downgrade():
    with op.batch_alter_table("thread") as batch_op:
        batch_op.drop_column('orig_op_bm_json_obj')
        batch_op.drop_column('last_op_json_obj_ts')
