"""add replace_download_domain to upload_sites

Revision ID: 000000000069
Revises: 000000000068
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000069'
down_revision = '000000000068'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('post_timestamp', sa.String))

    op.execute(
        '''
        UPDATE settings_global
        SET post_timestamp="sent"
        '''
    )

def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('post_timestamp')
