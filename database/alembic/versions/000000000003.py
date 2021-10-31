"""add sage

Revision ID: 000000000003
Revises: 000000000002
Create Date: 2021-07-16 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000003'
down_revision = '000000000002'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('sage', sa.Boolean))

    op.execute(
        '''
        UPDATE message
        SET sage=0
        '''
    )


def downgrade():
    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('sage')
