"""add upload site enable option

Revision ID: 000000000086
Revises: 000000000085
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000086'
down_revision = '000000000085'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("upload_sites") as batch_op:
        batch_op.add_column(sa.Column('enabled', sa.Boolean))

    op.execute(
        '''
        UPDATE upload_sites
        SET enabled=1
        '''
    )


def downgrade():
    with op.batch_alter_table("upload_sites") as batch_op:
        batch_op.drop_column('enabled')
