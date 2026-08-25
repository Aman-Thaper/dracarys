"""Shared pytest fixtures for the DRACARYS test suite."""
from __future__ import annotations

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager

from dracarys.api.app import create_app
from dracarys.config import Settings
from dracarys.db.base import Database
from dracarys.engine.policy import PolicyEngine, Scope
from dracarys.tools import HttpTool
from lab.app import create_lab_app
from lab.ground_truth import CANARY_TOKEN

LAB_BASE = "http://127.0.0.1:8888"
PATCHED_BASE = "http://127.0.0.1:8889"


@pytest.fixture
def settings(tmp_path) -> Settings:
    db_path = tmp_path / "dracarys_test.db"
    return Settings(
        database_url=f"sqlite+aiosqlite:///{db_path}",
        environment="test",
        debug=False,
    )


@pytest_asyncio.fixture
async def db(settings) -> Database:
    database = Database(settings)
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()


@pytest.fixture
def make_scope():
    def _make(hosts=("127.0.0.1", "localhost"), ports=(8888, 8889)) -> Scope:
        return Scope.create(list(hosts), list(ports))
    return _make


@pytest_asyncio.fixture
async def lab_factory():
    """Yield a factory that builds policy-bounded HTTP tools against a lab app.

    Returns (tool, client). All clients are closed at teardown.
    """
    clients: list[httpx.AsyncClient] = []

    def _make(patches=frozenset(), base_url=LAB_BASE, max_requests=500):
        app = create_lab_app(set(patches))
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=base_url
        )
        clients.append(client)
        scope = Scope.create(["127.0.0.1", "localhost"], [8888, 8889])
        policy = PolicyEngine(
            scope, max_requests=max_requests, max_concurrency=4, timeout_seconds=5
        )
        return HttpTool(base_url, policy, client), client

    yield _make
    for c in clients:
        await c.aclose()


@pytest_asyncio.fixture
async def api_client(settings):
    app = create_app(settings)
    async with LifespanManager(app) as manager:
        transport = httpx.ASGITransport(app=manager.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as client:
            yield client


@pytest.fixture
def canary() -> str:
    return CANARY_TOKEN
