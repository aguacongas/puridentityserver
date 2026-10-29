# Test manuel : OpenID4VCI 1.0 (issuance + metadonnees signees)

Ce repertoire est un **squelette** d un client exercant le flux OpenID4VCI
propose par PurIdentityServer (OP), dont l endpoint de metadonnees signees
(`Accept: application/jwt`) livre en `application/jwt`.

## Configuration

Activer le support dans `config.toml` (ou via variables d environnement) :

```toml
[server]
oid4vci_enabled = true
issuer = "http://127.0.0.1:8000"
```

## Lancement

1. Demarrer l OP :

```bash
uv run python -m puridentityserver.cli --port 8000
```

2. Exercer le flux (metadonnees signees + issuance preparee) :

```bash
BASE_URL=http://127.0.0.1:8000 uv run python samples/oid4vci-client/smoke_test.py
```

## Resultat attendu

- `/.well-known/openid-credential-issuer` repond `200 application/json` par defaut.
- Avec `Accept: application/jwt`, il repond `200 application/jwt` ; le JWT
  porte `typ=openidvci-issuer-metadata+jwt`, un `jwk` embarque, `sub` egal a
  l URL d issuer et une signature verifiable avec cette cle.
- Le flux complet (token, nonce, proof, credential) s exerce via la suite
  de certification docker (plan `oid4vci`), documentee dans
  `certification/README.md`.

## Suite complete

Le parcours complet se rejoue via la vraie suite de certification (harness
local, plan `oid4vci`) deja documentee dans `certification/README.md`.

## DoD

- README pas-a-pas, lancement, config, resultat attendu.
- Coherent avec `samples/oid4vp-verifier-client` et `samples/fapi2-client`.
- Variante batch : la metadata annonce batch_credential_issuance.batch_size; /credential accepte plusieurs proofs.jwt.

