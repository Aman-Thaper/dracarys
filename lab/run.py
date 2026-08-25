"""Entry point to run the DRACARYS LAB as a standalone service.

Usage:
    python -m lab.run --host 127.0.0.1 --port 8888
    python -m lab.run --port 8889 --patches LAB-IDOR-001,LAB-SQL-001
"""
from __future__ import annotations

import argparse
import os

import uvicorn

from lab.app import create_lab_app


def _parse_patches(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {p.strip() for p in raw.split(",") if p.strip()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the DRACARYS LAB")
    parser.add_argument("--host", default=os.getenv("DRACARYS_LAB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("DRACARYS_LAB_PORT", "8888")))
    parser.add_argument(
        "--patches", default=os.getenv("DRACARYS_LAB_PATCHES", ""),
        help="Comma-separated LAB-* ids to patch (default: fully vulnerable)",
    )
    args = parser.parse_args()
    patches = _parse_patches(args.patches)
    app = create_lab_app(patches)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
