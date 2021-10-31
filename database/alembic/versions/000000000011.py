"""add kiosk options to settings table

Revision ID: 000000000011
Revises: 000000000010
Create Date: 2021-09-22 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000011'
down_revision = '000000000010'
branch_labels = None
depends_on = None


def upgrade():
    # import os, sys
    # sys.path.append(os.path.abspath(os.path.join(__file__, "../../../..")))
    # from database.alembic_utils import post_alembic_write
    # post_alembic_write(revision)

    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.add_column(sa.Column('enable_kiosk_mode', sa.Boolean))
        batch_op.add_column(sa.Column('kiosk_login_to_view', sa.Boolean))
        batch_op.add_column(sa.Column('kiosk_allow_posting', sa.Boolean))
        batch_op.add_column(sa.Column('kiosk_disable_bm_attach', sa.Boolean))
        batch_op.add_column(sa.Column('kiosk_allow_download', sa.Boolean))
        batch_op.add_column(sa.Column('kiosk_post_rate_limit', sa.Integer))
        batch_op.add_column(sa.Column('kiosk_attempts_login', sa.Integer))
        batch_op.add_column(sa.Column('kiosk_ban_login_sec', sa.Integer))

    op.execute(
        '''
        UPDATE settings_global
        SET enable_kiosk_mode=0
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_login_to_view=0
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_allow_posting=0
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_disable_bm_attach=1
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_allow_download=1
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_post_rate_limit=50
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_attempts_login=5
        '''
    )

    op.execute(
        '''
        UPDATE settings_global
        SET kiosk_ban_login_sec=300
        '''
    )


def downgrade():
    with op.batch_alter_table("settings_global") as batch_op:
        batch_op.drop_column('enable_kiosk_mode')
        batch_op.drop_column('kiosk_login_to_view')
        batch_op.drop_column('kiosk_allow_posting')
        batch_op.drop_column('kiosk_disable_bm_attach')
        batch_op.drop_column('kiosk_allow_download')
        batch_op.drop_column('kiosk_post_rate_limit')
        batch_op.drop_column('kiosk_attempts_login')
        batch_op.drop_column('kiosk_ban_login_sec')
