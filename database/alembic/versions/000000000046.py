"""create table games

Revision ID: 000000000046
Revises: 000000000045
Create Date: 2021-10-07 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000046'
down_revision = '000000000045'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'games',
        sa.Column('id', sa.Integer, nullable=False, unique=True),
        sa.Column('game_hash', sa.String, unique=True),
        sa.Column('thread_hash', sa.String),
        sa.Column('is_host', sa.Boolean),
        sa.Column('host_from_address', sa.String),
        sa.Column('moves', sa.String),
        sa.Column('players', sa.String),
        sa.Column('turn_player', sa.String),
        sa.Column('turn_ts', sa.Integer),
        sa.Column('game_type', sa.String),
        sa.Column('game_ts', sa.Integer),
        sa.Column('game_initiated', sa.String),
        sa.Column('game_over', sa.Boolean),
        sa.PrimaryKeyConstraint('id'),
        keep_existing=True
    )

    with op.batch_alter_table("message") as batch_op:
        batch_op.add_column(sa.Column('game_password_a', sa.String))
        batch_op.add_column(sa.Column('game_password_b_hash', sa.String))
        batch_op.add_column(sa.Column('game_player_move', sa.String))


def downgrade():
    op.drop_table('games')

    with op.batch_alter_table("message") as batch_op:
        batch_op.drop_column('game_password_a')
        batch_op.drop_column('game_password_b_hash')
        batch_op.drop_column('game_player_move')
