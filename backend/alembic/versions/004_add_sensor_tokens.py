"""Add sensor_tokens table for Phase 3 sensor collector architecture.

Revision ID: 004_add_sensor_tokens
Revises: 003_add_account_lockout
Create Date: 2026-10-15 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '004_add_sensor_tokens'
down_revision: Union[str, None] = '003_add_account_lockout'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'sensor_tokens',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('token_id', sa.String(), unique=True, nullable=False),
        sa.Column('sensor_id', sa.String(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), server_default='', nullable=True),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.Column('revoked', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('revoked_at', sa.String(), nullable=True),
    )
    op.create_index('ix_sensor_tokens_token_hash', 'sensor_tokens', ['token_hash'])


def downgrade() -> None:
    op.drop_index('ix_sensor_tokens_token_hash', table_name='sensor_tokens')
    op.drop_table('sensor_tokens')
