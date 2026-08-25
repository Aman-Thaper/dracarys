"""Async SQLAlchemy engine, session factory, and declarative base.

The platform is DB-agnostic at the model level: SQLite (default, zero-dep local
dev) and PostgreSQL (production) are both supported through the async URL in
``Settings.database_url``. JSON columns use SQLAlchemy's portable ``JSON`` type.
"""
from __future__ import annotations

import enum
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from sqlalchemy import DateTime, String, event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, mapped_column
from sqlalchemy.types import TypeDecorator

from dracarys.config import Settings, get_settings


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    """Human-readable, sortable-ish, prefixed identifier (e.g. ``cmp_ab12...``)."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class TZDateTime(TypeDecorator):
    """Timezone-aware datetime that round-trips correctly on SQLite.

    SQLite drops tzinfo; we store UTC and re-attach it on load so the rest of the
    codebase can assume aware datetimes everywhere.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect):  # noqa: ANN001
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class EnumType(TypeDecorator):
    """Store a str-Enum as its ``.value`` and reconstruct the Enum on load."""

    impl = String
    cache_ok = True

    def __init__(self, enum_cls: type[enum.Enum], length: int = 40, **kw) -> None:
        self.enum_cls = enum_cls
        super().__init__(length=length, **kw)

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        if isinstance(value, self.enum_cls):
            return value.value
        return self.enum_cls(value).value

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is None:
            return None
        return self.enum_cls(value)


class Base(AsyncAttrs, DeclarativeBase):
    """Declarative base with async attribute access support."""


# Enforce foreign keys on SQLite (off by default) for referential integrity.
@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: ANN001
    module = type(dbapi_connection).__module__
    if "sqlite" in module:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


class Database:
    """Owns the async engine and session factory for one process."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.engine: AsyncEngine = create_async_engine(
            self.settings.database_url,
            echo=False,
            future=True,
            pool_pre_ping=True,
        )
        self.session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False, class_=AsyncSession
        )

    async def create_all(self) -> None:
        """Create tables from ORM metadata (used for dev/tests; prod uses Alembic)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    async def dispose(self) -> None:
        await self.engine.dispose()

    async def session(self) -> AsyncIterator[AsyncSession]:
        """FastAPI-style dependency yielding a session with commit/rollback."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise


# Common column helpers ------------------------------------------------------

def pk_column(prefix: str):
    return mapped_column(
        String(48), primary_key=True, default=lambda: new_id(prefix)
    )


def created_column():
    return mapped_column(TZDateTime, default=utcnow, nullable=False)


def updated_column():
    return mapped_column(
        TZDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )
