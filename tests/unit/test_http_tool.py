"""Unit tests for the HTTP tool: success capture, policy block, transport error."""
import httpx

from dracarys.engine.policy import PolicyEngine, Scope
from dracarys.tools import HttpRequestSpec, HttpTool
from dracarys.tools.base import ToolStatus


async def test_success_capture(lab_factory):
    tool, _ = lab_factory()
    ex = await tool.execute(HttpRequestSpec(path="/api/health", note="health"))
    assert ex.status == ToolStatus.OK
    assert ex.status_code == 200
    assert ex.sha256 and ex.elapsed_ms >= 0
    assert ex.contains("ok")


async def test_out_of_scope_is_blocked():
    scope = Scope.create(["127.0.0.1"], [8888])
    policy = PolicyEngine(scope, max_requests=10, max_concurrency=2, timeout_seconds=2)
    # Point the tool at a base URL that is not on the allowlist.
    client = httpx.AsyncClient(base_url="http://evil.example:8888")
    tool = HttpTool("http://evil.example:8888", policy, client)
    ex = await tool.execute(HttpRequestSpec(path="/", note="should block"))
    assert ex.status == ToolStatus.BLOCKED_BY_POLICY
    assert policy.requests_made == 0
    await client.aclose()


async def test_transport_error_is_captured():
    def _raise(request):
        raise httpx.ConnectError("connection refused", request=request)

    scope = Scope.create(["127.0.0.1"], [8888])
    policy = PolicyEngine(scope, max_requests=10, max_concurrency=2, timeout_seconds=2)
    client = httpx.AsyncClient(transport=httpx.MockTransport(_raise), base_url="http://127.0.0.1:8888")
    tool = HttpTool("http://127.0.0.1:8888", policy, client)
    ex = await tool.execute(HttpRequestSpec(path="/api/health", note="err"))
    assert ex.status == ToolStatus.ERROR
    assert "refused" in (ex.error or "")
    await client.aclose()
