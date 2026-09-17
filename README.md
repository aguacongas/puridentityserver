# PurIdentityServer — Serveur OpenID Connect

Serveur **OpenID Connect** (OIDC) / identity Provider, dans l'esprit de
[TheIdServer](https://github.com/aguacongas/TheIdServer) mais implémenté en Python
et conçu autour de la **specification** OIDC / OAuth 2.0.

L'objectif n'est pas de réinventer la roue :

- **HTTP + TLS** : on utilise **FastAPI** (sous **Uvicorn**), et TLS est géré par
  l'infrastructure (proxy / ingress / terminateur TLS) — pas de ré-implémentation.
- **JWT** : on utilise **PyJWT**, la bibliothèque JWT la plus largement utilisée
  dans l'industrie (sérialisation, signature, vérification des claims).
- **Cryptographie bas niveau** : `cryptography` (bindings OpenSSL) pour les clés,
  le RSA/EC, le chiffrement.

L'implémentation maison se concentre donc sur ce qui fait la valeur d'un serveur
OIDC : **les flows, les endpoints, la gestion des clients/consentements/sessions,
les politiques de sécurité** — le glue entre la spec et la lib crypto.

## Stack

- **Python 3.10+** (référencé : 3.14)
- **FastAPI + Uvicorn** — serveur HTTP / API
- **PyJWT** — JWT (RFC 7519) / JWS (RFC 7515) / JWA (RFC 7518) / JWK (RFC 7517)
- **cryptography** — primitives de bas niveau
- **Pydantic** — modèles et validation des requêtes/réponses OIDC
- **pytest** (+ `httpx`/TestClient de FastAPI pour les tests d'intégration)

## Spécifications couvertes

- [OAuth 2.0 Core] (RFC 6749)
- [OAuth 2.0 Bearer Tokens] (RFC 6750)
- [OpenID Connect Core 1.0] — code, implicit, hybrid, UserInfo, logout
- [OpenID Connect Discovery] (RFC 8414) — `/.well-known/openid-configuration`
- [JWK Set] — `/.well-known/jwks.json`
- [PKCE] (RFC 7636) — authorization code + PKCE
- [OAuth 2.0 Token Revocation] (RFC 7009)
- [OAuth 2.0 Token Introspection] (RFC 7662)
- [Device Authorization Grant] (RFC 8628) — `/device_authorization` + page `/device`
- [OAuth 2.0 JWT Access Tokens] (RFC 9068) — extension
- [Pushed Authorization Requests] (RFC 9126) — extension
- [OpenID Connect RP-Initiated Logout] (OIDC spec) — `/end_session`

## Endpoints prévus

| Endpoint                            | Rôle                                      | État |
| ----------------------------------- | ----------------------------------------- | ---- |
| `/.well-known/openid-configuration` | Discovery                                 | ✅   |
| `/.well-known/jwks.json`            | Clés publiques de signature               | ✅   |
| `/authorize`                        | Code / Implicit / Hybrid                  | ⬜   |
| `/token`                            | Échange code / refresh / client_credentials / device_code | ✅   |
| `/device_authorization`             | Device Authorization Grant (RFC 8628)    | ✅   |
| `/userinfo`                         | Claims de l'utilisateur                   | ✅   |
| `/introspect`                       | Introspection de token (RFC 7662)         | ✅   |
| `/revoke`                           | Révocation de token (RFC 7009)            | ✅   |
| `/registration`                     | Client registration dynamique (option)    | ⬜   |
| `/end_session`                      | RP-Initiated Logout                       | ⬜   |

## Documentation

- [Installation](docs/installation.md) — prérequis, installation, lancement, déploiement
- [Configuration du serveur](docs/configuration.md) — variables `PURIDENTITYSERVER_*`, `.env`, démarrage

## Structure (Clean Architecture)

Le code suit **Clean Architecture** : chaque cercle ne dépend que de son cercle intérieur
(`domain` ← `application` ← `interfaces` ← `infrastructure`).

```text
src/puridentityserver/
  domain/          entités OIDC (Client, Grant, Scope, Claims) — zéro dépendance
  application/     cas d'utilisation : émission code/token, validation, consentement
  interfaces/
    api/           routes FastAPI (authorize, token, userinfo, jwks, discovery...)
    schemas/       modèles Pydantic request/response OIDC
    repositories/  abstractions de persistance (ports)
  infrastructure/  PyJWT, storage concret (in-memory d'abord, puis SQL/Mongo)
  server.py        composition root — montage FastAPI + injection de dépendances
tests/             pytest unit + intégration (TestClient httpx)
```

## Plan d'implémentation

1. **Bootstrap** — FastAPI + models Pydantic + endpoints `/token` et `/authorize` squelettes
2. ✅ **JWKS + Discovery** — génération de clés de signature multi-algorithmes
   (RSA `RS*`/`PS*`, EC `ES*` — liste configurable via `PURIDENTITYSERVER_JWKS_ALGORITHMS`,
   **tous les algorithmes fournis par défaut**),
   rotation par algorithme, `/.well-known/*`
3. ✅ **Authorization Code + PKCE** (grant principal, RFC 6749 + 7636)
4. ✅ **ID Token + UserInfo** — émission et validation JWT via PyJWT,
   endpoint `/userinfo` (Bearer, filtrage des claims par scopes accordés)
5. ✅ **Refresh tokens** — rotation, expiration, rejeu
6. ✅ **Client Credentials** (RFC 6749 §4.4)
7. ✅ **Device Authorization Grant** (RFC 8628)
8. **Implicit & Hybrid** (OIDC Core 1.0)
9. **Logout** — RP-Initiated Logout
10. **Introspection / Revocation** (RFC 7662 / 7009)
11. **Client Registration** — registration dynamique
12. **Persistence** — stockage pluggable (SQL, Mongo, etc.)

## Développement local

```sh
uv sync                    # installe les dépendances (prod + dev)
uv run python -m puridentityserver    # lance le serveur sur http://127.0.0.1:8000

uv run python scripts/check.py   # vérification locale complète : ruff + mypy + pytest
uv run python scripts/check.py lint format type test  # ou une sous-sélection
```

Config via variables d'environnement `PURIDENTITYSERVER_*` (`PURIDENTITYSERVER_ISSUER`, `PURIDENTITYSERVER_HOST`,
`PURIDENTITYSERVER_PORT`, `PURIDENTITYSERVER_JWKS_ALGORITHMS`, ...).

## Qualité et SonarCloud

Le projet passe par **SonarCloud** (org `aguacongas`, projet `aguacongas_puridentityserver`).
Les règles de codage sont alignées sur celles de Sonar en local :

- **Complexité cyclomatique** ≤ 10 par fonction (équivalent S3776) — via ruff `C90`
- **Nommage**, imports inutilisés, sécurité (bandit), prints — via la config ruff
- **Typage strict** (mypy `strict`) et **couverture** pytest ≥ 80% (branch) exigés en local

CI GitHub (`.github/workflows/ci.yml`) : ruff lint/format, mypy strict, pytest+couv,
puis analyse SonarCloud sur `push`/`pull_request`.

À faire une fois par dépôt :

```sh
# 1. Token d'analyse SonarCloud (User > Security > Generate Token), puis :
gh secret set SONAR_SECRET
# 2. Créer le projet "PurIdentityServer" dans l'org aguacongas sur sonarcloud.io
#    (clé : aguacongas_puridentityserver) et activer la "Pull request decoration" GitHub.
```

## Notes

- Pas de ré-implémentation de JWT/TLS/HTTP : PyJWT, FastAPI et l'infra de transport
  font le travail — on implémente **la spec**, pas la crypto.
- Chaque feature = un endpoint + ses tests.

[OAuth 2.0 Core]: https://datatracker.ietf.org/doc/html/rfc6749
[OAuth 2.0 Bearer Tokens]: https://datatracker.ietf.org/doc/html/rfc6750
[OpenID Connect Core 1.0]: https://openid.net/specs/openid-connect-core-1_0.html
[OpenID Connect Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html
[JWK Set]: https://www.rfc-editor.org/rfc/rfc7517
[PKCE]: https://www.rfc-editor.org/rfc/rfc7636
[OAuth 2.0 Token Revocation]: https://datatracker.ietf.org/doc/html/rfc7009
[OAuth 2.0 Token Introspection]: https://datatracker.ietf.org/doc/html/rfc7662
[OAuth 2.0 JWT Access Tokens]: https://datatracker.ietf.org/doc/html/rfc9068
[Pushed Authorization Requests]: https://datatracker.ietf.org/doc/html/rfc9126
[OpenID Connect RP-Initiated Logout]: https://openid.net/specs/openid-connect-rpinitiated-1_0.html
