"""Generic, target-agnostic DAST engine.

Unlike the bundled lab modules (which prove a specific chain), the scanner crawls
an arbitrary authorized HTTP target, discovers its attack surface, and runs
generic detectors that confirm vulnerabilities with deterministic oracles and
captured evidence. This is the part that makes DRACARYS a tool, not a demo.
"""
from dracarys.scanner.engine import Scanner
from dracarys.scanner.models import ScanConfig, ScanFinding, ScanResult

__all__ = ["Scanner", "ScanConfig", "ScanFinding", "ScanResult"]
