"""add bm connection setting

Revision ID: 000000000087
Revises: 000000000086
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000087'
down_revision = '000000000086'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('bm_connections_in_out', sa.String))

    op.execute(
        '''
        UPDATE settings_global
        SET bm_connections_in_out="in_tor+clear_out_tor"
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('bm_connections_in_out')
