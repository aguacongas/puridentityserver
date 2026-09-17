"""Layer "infrastructure" — frameworks et drivers.

PyJWT, storage concret (in-memory d'abord, puis SQL/Mongo), Uvicorn, TLS/proxy.
Implémente les ports d'interfaces ; jamais importé par domain ou application.
"""
