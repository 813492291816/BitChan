"""add max post size

Revision ID: 000000000084
Revises: 000000000083
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000084'
down_revision = '000000000083'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('kiosk_max_post_size_bytes', sa.Integer))

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_max_post_size_bytes=0
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('kiosk_max_post_size_bytes')
