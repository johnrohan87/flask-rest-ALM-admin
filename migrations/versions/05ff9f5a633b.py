"""empty message

Revision ID: f00c5343725a
Revises: 59bf011ca080
Create Date: 2023-07-16 16:00:10.316123

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '05ff9f5a633b' #just in case - 22db6cec8e8b
down_revision = '59bf011ca080'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('textfile_table',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('person_id', sa.Integer(), nullable=True),
    sa.Column('ip', sa.String(length=20), nullable=False),
    sa.Column('update_feed', sa.Boolean(), nullable=False),
    sa.Column('url', sa.Text(), nullable=False),
    sa.Column('text', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['person_id'], ['person_account.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('textfile')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('textfile',
    sa.Column('textfile_id', mysql.INTEGER(), autoincrement=True, nullable=False),
    sa.Column('owner_id', mysql.INTEGER(), autoincrement=False, nullable=True),
    sa.Column('ip', mysql.VARCHAR(length=20), nullable=False),
    sa.Column('update_feed', mysql.TINYINT(display_width=1), autoincrement=False, nullable=False),
    sa.Column('url', mysql.TEXT(), nullable=False),
    sa.Column('text', mysql.TEXT(), nullable=False),
    sa.ForeignKeyConstraint(['owner_id'], ['person_account.id'], name='textfile_ibfk_1'),
    sa.PrimaryKeyConstraint('textfile_id'),
    mysql_collate='utf8mb4_0900_ai_ci',
    mysql_default_charset='utf8mb4',
    mysql_engine='InnoDB'
    )
    op.drop_table('textfile_table')
    # ### end Alembic commands ###
