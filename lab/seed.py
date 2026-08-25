"""Synthetic seed data for the DRACARYS LAB, loaded into an in-memory SQLite DB.

Raw sqlite3 (stdlib) is used deliberately so the injection sink in
``GET /api/accounts/search`` is a *real* string-concatenated query, not a
simulation. All values are fake and local-only.
"""
from __future__ import annotations

import hashlib
import sqlite3

from lab.ground_truth import CANARY_TOKEN

# username -> plaintext password (synthetic). qa_bot is the intentionally leaked one.
USERS = [
    # id, username, password, role, enabled, primary_account
    (1, "alice", "alice-lives-here-2019", "customer", 1, 5001),
    (2, "bob", "bob-hunter2-account", "customer", 1, 5002),
    (3, "qa_bot", "qa-staging-7f3a91", "service", 1, 5003),
    (4, "admin", "c0rrect-horse-battery-treasury-staple", "admin", 1, 9001),
]

ACCOUNTS = [
    # id, owner_username, holder_name, kind, balance, canary_secret
    (5001, "alice", "Alice Nguyen", "checking", 4210.55, None),
    (5002, "bob", "Bob Marsh", "savings", 88123.10, None),
    (5003, "qa_bot", "QA Staging Bot", "service", 0.0, None),
    (9001, "admin", "DRACARYS Treasury", "treasury", 100_000_000.0, CANARY_TOKEN),
]

SECRETS = [
    ("vault_recovery_code", CANARY_TOKEN),
    ("smtp_relay_password", "decoy-relay-pw-not-the-canary"),
]


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def build_seed_db() -> sqlite3.Connection:
    """Create and populate a fresh in-memory database. One connection per app."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            primary_account INTEGER NOT NULL
        );
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            owner_username TEXT NOT NULL,
            holder_name TEXT NOT NULL,
            kind TEXT NOT NULL,
            balance REAL NOT NULL DEFAULT 0,
            canary_secret TEXT
        );
        CREATE TABLE secrets (
            secret_name TEXT PRIMARY KEY,
            secret_value TEXT NOT NULL
        );
        """
    )
    cur.executemany(
        "INSERT INTO users (id, username, password, password_hash, role, enabled, "
        "primary_account) VALUES (?,?,?,?,?,?,?)",
        [
            (uid, un, pw, _hash(pw), role, en, acct)
            for (uid, un, pw, role, en, acct) in USERS
        ],
    )
    cur.executemany(
        "INSERT INTO accounts (id, owner_username, holder_name, kind, balance, "
        "canary_secret) VALUES (?,?,?,?,?,?)",
        ACCOUNTS,
    )
    cur.executemany(
        "INSERT INTO secrets (secret_name, secret_value) VALUES (?,?)", SECRETS
    )
    conn.commit()
    return conn
