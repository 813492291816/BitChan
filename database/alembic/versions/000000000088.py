"""add is_regex

Revision ID: 000000000088
Revises: 000000000087
Create Date: 2022-06-02 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '000000000088'
down_revision = '000000000087'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("banned_words") as batch_op:
        batch_op.add_column(sa.Column('is_regex', sa.Boolean))

    op.execute(
        '''
        UPDATE banned_words
        SET is_regex=0
        '''
    )


def downgrade():
    with op.batch_alter_table("banned_words") as batch_op:
        batch_op.drop_column('is_regex')
