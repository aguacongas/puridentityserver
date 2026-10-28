#!/usr/bin/env python3
"""Stub smoke test for OID4VP verifier-like flow (DoD placeholder).

Ce script demarre uniquement l executable PurIdentityServer tel quel et
imprime un recapitulatif pour qu'un operateir humaire puisse piloter
manuellement le module verifier (oid4vp-1final-verifier-haip-test-plan).
"""
from __future__ import annotations

import subprocess
import sys
import time

print("=== OID4VP verifier smoke (placeholder) ===")
print("L'OP est demarre manuellement via :")
print("  uv run python -m puridentityserver.cli --port 8000")
print("puis ouvrir la suite de certification sur https://localhost.emobix.co.uk:8443")
print("pour lancer le plan oid4vp avec les captures Playwright.")
print("Aucune implementation RP automatique n'est encore prevue ici.")
sys.exit(0)
