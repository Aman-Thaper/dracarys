"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-25

Creates the full DRACARYS domain from the ORM metadata. Subsequent migrations
should use explicit Alembic operations.
"""
from __future__ import annotations

from alembic import op

from dracarys.db.base import Base
import dracarys.db.models  # noqa: F401

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
