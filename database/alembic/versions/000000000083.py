"""add encryption setting

Revision ID: 000000000083
Revises: 000000000082
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000083'
down_revision = '000000000082'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('allow_unencrypted_encryption_option', sa.Boolean))

    op.execute(
        '''
        UPDATE settings_global
        SET allow_unencrypted_encryption_option=0
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('allow_unencrypted_encryption_option')
