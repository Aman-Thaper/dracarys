"""DRACARYS BANK — the deliberately vulnerable FastAPI target.

The app is built by a factory that takes a set of patch ids. When a patch id is
present the corresponding LAB-* flaw is fixed; otherwise the vulnerable code path
runs. This is how the retest engine obtains a real *patched* environment: it
launches a second instance with the relevant patch applied and replays the attack.

Auto-generated API docs are disabled on purpose so reconnaissance must discover
endpoints by probing (a realistic content-discovery exercise).
"""
from __future__ import annotations

import secrets as _secrets
import sqlite3

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from lab.ground_truth import GROUND_TRUTH
from lab.seed import build_seed_db


class LabState:
    def __init__(self, patches: set[str]) -> None:
        self.patches = patches
        self.db: sqlite3.Connection = build_seed_db()
        self.tokens: dict[str, str] = {}  # bearer token -> username

    def patched(self, vuln_id: str) -> bool:
        return vuln_id in self.patches

    def issue_token(self, username: str) -> str:
        tok = "tok_" + _secrets.token_hex(16)
        self.tokens[tok] = username
        return tok

    def user_for_token(self, token: str | None) -> sqlite3.Row | None:
        if not token or token not in self.tokens:
            return None
        username = self.tokens[token]
        return self.db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def _bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def _unauth() -> JSONResponse:
    return JSONResponse({"error": "authentication required"}, status_code=401)


def create_lab_app(patches: set[str] | None = None, name: str = "DRACARYS BANK") -> FastAPI:
    state = LabState(patches or set())

    app = FastAPI(
        title=name,
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,  # force real content discovery during recon
    )
    app.state.lab = state

    def current_user(request: Request) -> sqlite3.Row | None:
        return state.user_for_token(_bearer(request))

    # --- Public ---------------------------------------------------------

    @app.get("/")
    def root() -> dict:
        return {
            "service": name,
            "description": "Fake retail bank for authorized red-team testing.",
            "note": "All data is synthetic. Local-only lab.",
            "health": "/api/health",
        }

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "service": name, "patches_applied": sorted(state.patches)}

    # LAB-INFO-001: verbose status discloses staging credentials.
    @app.get("/api/system/status")
    def system_status(request: Request) -> dict:
        verbose = request.query_params.get("verbose", "") in ("1", "true", "yes")
        body: dict = {"status": "ok", "service": name, "version": "1.0.0"}
        if verbose and not state.patched("LAB-INFO-001"):
            # VULNERABLE: leaks seeded staging credentials + internal scheme.
            row = state.db.execute(
                "SELECT username, password FROM users WHERE username = 'qa_bot'"
            ).fetchone()
            body["debug"] = {
                "build": "staging-1.0.0+debug",
                "seed_accounts": [
                    {
                        "user": row["username"],
                        "password": row["password"],
                        "note": "staging service account - REMOVE BEFORE PROD",
                    }
                ],
                "treasury_account_id": 9001,
                "account_id_scheme": "sequential customer ids from 5001; treasury=9001",
                "db": "sqlite (in-memory)",
            }
        elif verbose:
            body["debug"] = {"note": "verbose diagnostics disabled"}
        return body

    # LAB-AUTH-001: exposed staging account is a live login.
    @app.post("/api/login")
    async def login(request: Request):
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        # NOTE: login itself is parameterized (safe). The weakness is that the
        # leaked staging account is enabled in production.
        row = state.db.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        if row is None or not row["enabled"]:
            return _unauth()
        if state.patched("LAB-AUTH-001") and username == "qa_bot":
            # FIX: the exposed staging service account has been disabled.
            return JSONResponse(
                {"error": "account disabled"}, status_code=401
            )
        token = state.issue_token(username)
        return {
            "access_token": token,
            "token_type": "bearer",
            "username": row["username"],
            "role": row["role"],
        }

    @app.get("/api/me")
    def me(request: Request):
        user = current_user(request)
        if user is None:
            return _unauth()
        return {
            "username": user["username"],
            "role": user["role"],
            "primary_account": user["primary_account"],
        }

    # LAB-SQL-001: UNION-injectable account search (declared before the {id} route).
    @app.get("/api/accounts/search")
    def account_search(request: Request):
        user = current_user(request)
        if user is None:
            return _unauth()
        q = request.query_params.get("q", "")
        if state.patched("LAB-SQL-001"):
            # FIX: parameterized query; injection is inert.
            sql = "SELECT id, holder_name, kind FROM accounts WHERE holder_name LIKE ?"
            rows = state.db.execute(sql, (f"%{q}%",)).fetchall()
        else:
            # VULNERABLE: string-concatenated SQL (real injection sink).
            sql = (
                "SELECT id, holder_name, kind FROM accounts "
                f"WHERE holder_name LIKE '%{q}%'"
            )
            try:
                rows = state.db.execute(sql).fetchall()
            except sqlite3.Error as exc:
                # Verbose SQL error is itself a disclosure signal for the attacker.
                return JSONResponse(
                    {"error": "query failed", "detail": str(exc), "query": sql},
                    status_code=500,
                )
        return {"query": q, "results": [dict(r) for r in rows]}

    # LAB-IDOR-001: no object-level authorization on account reads.
    @app.get("/api/accounts/{account_id}")
    def get_account(account_id: int, request: Request):
        user = current_user(request)
        if user is None:
            return _unauth()
        row = state.db.execute(
            "SELECT * FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        if row is None:
            return JSONResponse({"error": "account not found"}, status_code=404)
        if state.patched("LAB-IDOR-001"):
            # FIX: enforce ownership (admins may view any account).
            if row["owner_username"] != user["username"] and user["role"] != "admin":
                return JSONResponse({"error": "forbidden"}, status_code=403)
        data = {
            "id": row["id"],
            "owner_username": row["owner_username"],
            "holder_name": row["holder_name"],
            "kind": row["kind"],
            "balance": row["balance"],
        }
        if row["canary_secret"]:
            data["vault_recovery_code"] = row["canary_secret"]
        return data

    # LAB-MISCONFIG-001: admin dump authorized by a client-supplied header.
    @app.get("/api/admin/users")
    def admin_users(request: Request):
        user = current_user(request)
        if user is None:
            return _unauth()
        if state.patched("LAB-MISCONFIG-001"):
            is_admin = user["role"] == "admin"
        else:
            # VULNERABLE: trusts a client-controlled role header.
            is_admin = (
                user["role"] == "admin"
                or request.headers.get("X-Account-Role", "").lower() == "admin"
            )
        if not is_admin:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        rows = state.db.execute(
            "SELECT id, username, role, password_hash, primary_account FROM users"
        ).fetchall()
        return {"users": [dict(r) for r in rows]}

    # Metadata endpoint used by the evaluation harness (not part of the attack surface).
    @app.get("/__meta__/patches")
    def meta_patches() -> dict:
        return {
            "patches_applied": sorted(state.patches),
            "known_vulns": list(GROUND_TRUTH.keys()),
        }

    return app
