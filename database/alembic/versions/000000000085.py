"""add force TTL

Revision ID: 000000000085
Revises: 000000000084
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000085'
down_revision = '000000000084'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('kiosk_ttl_option', sa.String))
        batch_op.add_column(sa.Column('kiosk_ttl_seconds', sa.Integer))

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_ttl_option="selectable_max_28_days"
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_ttl_seconds=2419200
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('kiosk_ttl_option')
        batch_op.drop_column('kiosk_ttl_seconds')
