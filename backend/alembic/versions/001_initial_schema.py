"""Initial schema for Volcano AI Firewall.

Revision ID: 001_initial
Revises: 
Create Date: 2026-10-14 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Rules table
    op.create_table(
        'rules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('src_ip', sa.String(), nullable=True),
        sa.Column('dst_ip', sa.String(), nullable=True),
        sa.Column('src_port', sa.Integer(), nullable=True),
        sa.Column('dst_port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('priority', sa.Integer(), default=10),
        sa.Column('enabled', sa.Boolean(), default=True),
        sa.Column('description', sa.Text(), default=''),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.Column('metadata', sa.Text(), nullable=True),
    )

    # 2. Alerts table with triage fields
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('timestamp', sa.Float(), nullable=False),
        sa.Column('source', sa.String(), nullable=False),
        sa.Column('severity', sa.String(), nullable=False),
        sa.Column('category', sa.String(), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('status', sa.String(), default='new'),
        sa.Column('assignee', sa.String(), nullable=True),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('metadata', sa.Text(), nullable=True),
        sa.Column('created_at', sa.String(), nullable=True),
    )

    # 3. Devices table
    op.create_table(
        'devices',
        sa.Column('mac_address', sa.String(), primary_key=True),
        sa.Column('last_seen', sa.Float(), nullable=False),
        sa.Column('risk_score', sa.Float(), default=0.0),
        sa.Column('threat_count', sa.Integer(), default=0),
        sa.Column('behavioral_tags', sa.Text(), nullable=True),
        sa.Column('alert_history', sa.Text(), nullable=True),
        sa.Column('metadata', sa.Text(), nullable=True),
    )

    # 4. Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('timestamp', sa.String(), nullable=False),
        sa.Column('user_id', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('resource', sa.String(), nullable=False),
        sa.Column('changes', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), default='success'),
    )

    # 5. Users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('username', sa.String(64), unique=True, nullable=False),
        sa.Column('password_hash', sa.String(256), nullable=False),
        sa.Column('role', sa.String(32), default='viewer', nullable=False),
        sa.Column('created_at', sa.String(), nullable=True),
        sa.Column('last_login', sa.String(), nullable=True),
        sa.Column('active', sa.Boolean(), default=True),
    )


def downgrade() -> None:
    op.drop_table('users')
    op.drop_table('audit_logs')
    op.drop_table('devices')
    op.drop_table('alerts')
    op.drop_table('rules')
