"""DRACARYS LAB — the deliberately vulnerable target ("DRACARYS BANK").

Every vulnerability has a ground-truth id (LAB-*), a genuinely exploitable code
path, and a patched code path selected at runtime by a set of patch flags. This
lets the retest engine launch a real, disposable *patched* instance and replay
the original attack to prove a fix.

ALL data here is synthetic and local-only. No real credentials or secrets.
"""
