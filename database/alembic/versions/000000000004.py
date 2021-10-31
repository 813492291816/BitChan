"""add option to prevent automatically downloading from unknown upload sites

Revision ID: 000000000004
Revises: 000000000003
Create Date: 2021-08-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000004'
down_revision = '000000000003'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('auto_dl_from_unknown_upload_sites', sa.Boolean))

    op.execute(
        '''
        UPDATE settings_global
        SET auto_dl_from_unknown_upload_sites=0
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('auto_dl_from_unknown_upload_sites')
