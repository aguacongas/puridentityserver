# Test manuel : OID4VCI pre-authorized code grant

Squelette pour le flux issuer-initiated (pre-authorized code).

## Lancement

1. Demarrer l OP avec `oid4vci_enabled = true`.
2. Obtenir un pre-authorized code (endpoint d offre a venir) puis :

```bash
BASE_URL=http://127.0.0.1:8000 PRE_AUTHORIZED_CODE=... uv run python samples/oid4vci-preauth-client/smoke_test.py
```

## Resultat attendu

- `POST /token` avec `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`
  renvoie un access token.
- `POST /credential` avec ce token emet le credential.