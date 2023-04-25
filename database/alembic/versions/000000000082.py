"""add timezone and hour settings

Revision ID: 000000000082
Revises: 000000000081
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000082'
down_revision = '000000000081'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('post_timestamp_timezone', sa.Text))
        batch_op.add_column(sa.Column('post_timestamp_hour', sa.Text))

    op.execute(
        '''
        UPDATE settings_global
        SET post_timestamp_timezone='Etc/GMT'
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET post_timestamp_hour='24'
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('post_timestamp_timezone')
        batch_op.drop_column('post_timestamp_hour')
