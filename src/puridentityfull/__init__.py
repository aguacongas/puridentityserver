"""Serveur complet (protocole + administration) de PurIdentityServer."""

from __future__ import annotations

from puridentityfull.server import app, create_app

__all__ = ["app", "create_app"]
