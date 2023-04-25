"""add maintenance_mode

Revision ID: 000000000079
Revises: 000000000078
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000079'
down_revision = '000000000078'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('maintenance_mode', sa.Boolean))

    op.execute(
        '''
        UPDATE settings_global
        SET maintenance_mode=0
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('maintenance_mode')
