"""Add user tier and subscription info

Revision ID: 6ae738ae26e0
Revises: 54d0321aa26d
Create Date: 2024-10-22 15:03:43.863083

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6ae738ae26e0'
down_revision = '54d0321aa26d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tier', sa.Enum('FREE', 'PREMIUM', name='usertier'), nullable=False, server_default='FREE'))
        batch_op.add_column(sa.Column('extractions_left', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('subscription_end', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('subscription_end')
        batch_op.drop_column('extractions_left')
        batch_op.drop_column('tier')

    # ### end Alembic commands ###
