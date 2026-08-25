"""Lab controller — supplies the target under test and disposable patched instances.

Two implementations:

* InProcessLabController builds the lab app in-process and drives it via an ASGI
  transport. Requests are real HTTP (through httpx and the policy engine); they
  simply do not cross a socket. This is the reliable default for tests, CI, and a
  zero-setup demo.
* SubprocessLabController launches the lab as a real uvicorn process on a port,
  used for the "live" demo where the target is a separate service.

A retest obtains a *patched* handle (a freshly built lab with the fix applied),
which is genuinely disposable: it exists only for the replay.
"""
from __future__ import annotations

import asyncio
import contextlib
import sys
from dataclasses import dataclass
from typing import Protocol

import httpx

from dracarys.config import Settings, get_settings
from dracarys.logging import get_logger

log = get_logger("lab.controller")


@dataclass
class LabHandle:
    base_url: str
    client: httpx.AsyncClient
    label: str = "lab"
    _process: asyncio.subprocess.Process | None = None

    async def aclose(self) -> None:
        with contextlib.suppress(Exception):
            await self.client.aclose()
        if self._process is not None and self._process.returncode is None:
            self._process.terminate()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._process.wait(), timeout=5)


class LabController(Protocol):
    async def primary(self) -> LabHandle: ...
    async def patched(self, patches: set[str], label: str = "patched") -> LabHandle: ...


class InProcessLabController:
    def __init__(
        self,
        settings: Settings | None = None,
        primary_patches: set[str] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.primary_patches = primary_patches or set()

    def _handle(self, patches: set[str], base_url: str, label: str) -> LabHandle:
        # Imported lazily so the platform package does not hard-depend on the lab.
        from lab.app import create_lab_app

        app = create_lab_app(patches)
        transport = httpx.ASGITransport(app=app)
        client = httpx.AsyncClient(transport=transport, base_url=base_url)
        return LabHandle(base_url=base_url, client=client, label=label)

    async def primary(self) -> LabHandle:
        return self._handle(self.primary_patches, self.settings.lab_base_url, "primary")

    async def patched(self, patches: set[str], label: str = "patched") -> LabHandle:
        return self._handle(patches, self.settings.lab_patched_base_url, label)


class SubprocessLabController:
    """Launches the lab as a real uvicorn process (live demo / over-the-socket)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    async def _spawn(self, port: int, patches: set[str], label: str) -> LabHandle:
        env_patches = ",".join(sorted(patches))
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "lab.run",
            "--host", self.settings.lab_host,
            "--port", str(port),
            "--patches", env_patches,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        base_url = f"http://{self.settings.lab_host}:{port}"
        client = httpx.AsyncClient(base_url=base_url)
        await self._wait_healthy(client)
        return LabHandle(base_url=base_url, client=client, label=label, _process=proc)

    async def _wait_healthy(self, client: httpx.AsyncClient, timeout: float = 15.0) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                r = await client.get("/api/health", timeout=2.0)
                if r.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.25)
        raise RuntimeError("lab process did not become healthy in time")

    async def primary(self) -> LabHandle:
        # In live mode the primary lab is expected to already be running.
        client = httpx.AsyncClient(base_url=self.settings.lab_base_url)
        await self._wait_healthy(client)
        return LabHandle(base_url=self.settings.lab_base_url, client=client, label="primary")

    async def patched(self, patches: set[str], label: str = "patched") -> LabHandle:
        return await self._spawn(self.settings.lab_patched_port, patches, label)
