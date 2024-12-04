"""Add Transactionn model

Revision ID: 5e767a3ea4d8
Revises: 559eda59a405
Create Date: 2024-10-24 16:11:57.130119

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import func
from datetime import timedelta


# revision identifiers, used by Alembic.
revision = '5e767a3ea4d8'
down_revision = '559eda59a405'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('transaction',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('paddle_customer_id', sa.String(length=255), nullable=False),
    sa.Column('checkout_id', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=50), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('paid_extractions_left', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('next_reset_date', sa.DateTime(), nullable=False, server_default=func.now()))


    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('next_reset_date')
        batch_op.drop_column('paid_extractions_left')

    op.drop_table('transaction')
    # ### end Alembic commands ###
