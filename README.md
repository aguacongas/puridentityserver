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
- [OpenID Connect Front-Channel Logout] + [Back-Channel Logout] (OIDC spec) — notifications de déconnexion
- [OAuth 2.0 Dynamic Client Registration] (RFC 7591) + [Client Management] (RFC 7592) — `/register`
- CORS — origines autorisées **déduites des URIs des clients actifs** (`redirect_uris` + `web_origins`, OAuth 2.0 for Browser-Based Apps), pour les SPA publics en Authorization Code + PKCE
- **Ressources protégées** (ApiResources) — registre des audiences API et de leurs scopes : l'`aud` d'un access token porte le nom des resources dont des scopes ont été accordés, tout scope non enregistré est refusé (`invalid_scope`)

## Endpoints prévus

| Endpoint                            | Rôle                                      | État |
| ----------------------------------- | ----------------------------------------- | ---- |
| `/.well-known/openid-configuration` | Discovery                                 | ✅   |
| `/.well-known/jwks.json`            | Clés publiques de signature               | ✅   |
| `/authorize`                        | Code / Implicit / Hybrid                  | ✅   |
| `/token`                            | Échange code / refresh / client_credentials / device_code | ✅   |
| `/device_authorization`             | Device Authorization Grant (RFC 8628)    | ✅   |
| `/par`                              | Pushed Authorization Request (RFC 9126)  | ✅   |
| `/userinfo`                         | Claims de l'utilisateur                   | ✅   |
| `/introspect`                       | Introspection de token (RFC 7662)         | ✅   |
| `/revoke`                           | Révocation de token (RFC 7009)            | ✅   |
| `/register`                         | Client registration dynamique (RFC 7591/7592) | ✅   |
| `/identity-resources`              | Gestion CRUD des IdentityResources (scopes + claims) | ✅   |
| `/api-resources`                   | Gestion CRUD des ApiResources (scopes d'API / audiences) | ✅   |
| `/end_session`                      | RP-Initiated Logout                       | ✅   |

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
  infrastructure/  PyJWT, storage concret (memory + SQL/SQLAlchemy, factory)
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
8. ✅ **Implicit & Hybrid** (OIDC Core 1.0)
9. ✅ **Logout** — RP-Initiated Logout (`/end_session`, `id_token_hint`,
   `post_logout_redirect_uri` enregistrée, `state`, purge du cookie) avec
   **session OIDC `sid`** (émis au login, claim `sid` de l'`id_token` et du
   cookie de session, corrélé code d'autorisation → jeton) : notification
   **Front-Channel Logout 1.0** (iframes vers les `frontchannel_logout_uri`
   des clients actifs, `sid` ajouté si `frontchannel_logout_session_required`)
   et **Back-Channel Logout 1.0** (POST d'un `logout_token` signé RS256
   serveur — `iss`/`aud`/`sub`/`sid`/`events`/`jti`, TTL `logout_token_ttl_seconds`
   60 s — vers chaque `backchannel_logout_uri`, best effort hors-boucle
   uvicorn). Annonces au discovery : `frontchannel_logout_supported`,
   `frontchannel_logout_session_supported`, `backchannel_logout_supported`,
   `backchannel_logout_session_supported`. Échantillon testable pas-à-pas :
   `samples/logout-channel-client/` (les deux canaux vérifiés de bout en bout).
10. ✅ **Introspection / Revocation** (RFC 7662 / 7009)
11. ✅ **Client Registration** — registration dynamique (RFC 7591 + 7592) :
    `POST /register` (création, `client_id` + `client_secret` + registration
    access token émis une seule fois), gestion `GET/PUT/DELETE
    /register/{client_id}` via le registration access token. Initial access
    token exigé (configurable, hash SHA-256 — aucune valeur en clair stockée) ;
    métadonnées restreintes : grant `authorization_code`, response `code`,
    auth methods `client_secret_basic`/`client_secret_post`/`none`, redirect
    URIs absolues http(s) sans fragment, scopes connus ; `registration_endpoint`
    publié au discovery quand activé.
12. ✅ **Pushed Authorization Request** (RFC 9126) : `POST /par` — le client
    pousse les paramètres d'autorisation (form-urlencoded, authentification
    comme à `/token`) et reçoit un `request_uri` opaque à usage unique
    (`urn:ietf:params:oauth:request_uri:<réference>`, TTL 5-600 s), résolu à
    `/authorize` via `request_uri` (+ `client_id` uniquement — tout paramètre
    supplémentaire est rejeté). Le `request_uri` ne peut être utilisé qu'une
    fois et est détruit après usage ; les paramètres passent par le même
    validateur que le flow standard ; `pushed_authorization_request_endpoint`
    publié au discovery quand activé (`par_enabled`). L'exigence PAR est
    réglable **par client** (`par_required` dans `clients_seed` /
    `require_pushed_authorization_requests` à la registration, RFC 9126
    §5.2 §6.1) : un tel client voit toute demande directe à `/authorize`
    rejetée en `invalid_request`.
13. ✅ **Persistence** — stockage pluggable : chaque store (clés de
    signature, clients, codes d'autorisation, device codes, requêtes PAR,
    refresh tokens, jetons révoqués, profils utilisateurs) est décliné en
    deux implémentations choisies via `storage_type` — `memory`
    (process-local, développement) et `sql` (SQLAlchemy 2.0 asynchrone :
    SQLite, PostgreSQL, MySQL — DSN `storage_dsn`, dialecte asynchrone
    résolu automatiquement, migrations légères `ALTER TABLE ADD COLUMN` au
    démarrage). Le backend `sql` autorise le load balancing multi-instance
    et la reprise après redémarrage.
14. ✅ **Démo SPA interactive** — `samples/spa-client/` : page statique sans
    framework qui exerce tous les flows depuis le navigateur (Authorization
    Code + PKCE, Implicit, Hybrid, PAR, Device, Client Credentials, Refresh,
    Introspection, Révocation, Logout) avec callback géré dans la page, CORS
    **dérivé des URIs des clients** (`redirect_uris` + `web_origins` du
    client `sample-spa-client`).
15. ✅ **Écran de consentement** (OIDC Core 1.0 §3.1.2.2) : pour un client
    marqué `require_consent`, `/authorize` redirige vers `GET /consent`
    (client, scopes demandés, `redirect_uri`) quand un consentement mémorisé
    ne couvre pas déjà la demande. `POST /consent` autorise (`ConsentUseCase.grant`
    — scopes fusionnés, jamais retirés — puis exécution directe d'`AuthorizeUseCase`)
    ou refuse (`access_denied` vers `redirect_uri`). Utilisateur non connecté :
    `login?next=/consent…`. Consentements persistés avec les stores (`memory` /
    `sql`), auto-approbation des demandes déjà couvertes ; compatible PAR
    (exécution directe après consultation, le `request_uri` étant à usage unique).
16. ✅ **IdentityResources** (OIDC Core 1.0 §5.4) : scopes identité et claims
    exposés injectés en seed (`identity_resources_seed`, **en plus** des
    resources standard seedées quoi qu'il arrive — openid, profile, email,
    address, phone, offline_access ; un nom égal à un standard le surcharge)
    et gérables en cours de vie via l'API CRUD `/identity-resources`. Elles
    alimentent `scopes_supported` / `claims_supported` du discovery et le
    filtrage des claims de `/userinfo` par scope accordé au jeton (un jeton
    `openid` seul n'expose que `sub`).
17. ✅ **ApiResources** (ressources protégées) : registre des audiences API et
    de leurs scopes d'API, injecté en seed (`api_resources_seed` : `name`,
    `display_name`, `scopes`, `allowed_access_token_signing_algos` en option)
    et gérable en vie via l'API CRUD `/api-resources`. Les scopes d'API
    complètent `scopes_supported` du discovery ; un scope non enregistré
    (standard ou API) est refusé en `invalid_scope` à l'émission —
    `/authorize`, `/par`, `/token` (client_credentials, code, refresh,
    device_code) et `/device_authorization` — et à la registration
    dynamique (RFC 7591, métadonnée `scope`). L'`aud` d'un access token
    porte le nom des ApiResources dont des scopes ont été accordés (chaîne
    unique ou liste triée), sinon le `client_id` émetteur ; l'introspection
    RFC 7662 conserve une audience multiple sans l'attribuer comme
    `client_id`. Échantillon testable pas-à-pas :
    `samples/api-resources-client/` (test manuel complet + démo CLI).
18. ✅ **Séparation administration / protocole + protection JWT** : le réglage
    `role` (`full` par défaut, `protocol`, `admin`) choisit les endpoints montés
    — `protocol` n'expose que le protocole OIDC/OAuth, `admin` n'expose que la
    gestion des resources (CRUD `/identity-resources` et `/api-resources`,
    sans génération de clés ni seed clients). Deux processus déployés
    séparément partagent le même état via `storage_type = "sql"`. Les CRUD
    d'administration sont **protégés par défaut** par un JWT Bearer validé
    (signature JWKS, `iss`, `exp`, `aud` optionnelle) contre l'issuer de
    gestion (`management_jwt_issuer` : local si vide, distant via
    `management_jwt_jwks_url` sinon) et portant un claim configurable
    (`admin_required_claim` / `admin_required_claim_values` : `scope` en
    appartenance, sinon égalité). `POST /register` gagne un mode
    `registration_initial_access_token_mode` : `static` (défaut, initial access
    tokens hachés), `jwt` (Bearer JWT + claim configurable) ou `disabled`.
    Les deux serveurs sont des **packages indépendants** guidés par `role`,
    déployables via leur propre point d'entrée
    (`puridentityprotocol.server:app`, `puridentityadmin.server:app`) et
    composés par-dessus les **mêmes stores** en mono-processus
    (`puridentityfull.server:app`, mémoire seule) ; la façade historique
    `puridentityserver.server:app` dispatche sur `role`.
    Échantillon testable pas-à-pas : `samples/admin-api-client/`.
19. ✅ **Algorithmes d'`id_token`** (issue #47, OIDC Core 1.0 §3.1.3) — signature
    par client : `RS*`/`PS*`/`ES*` (clé serveur du JWKS) ou **HS*** (`HS256`/
    `HS384`/`HS512`, signé avec le secret partagé du client, jamais publié) via
    `id_token_signed_response_alg` ; **chiffrement JWE** (RFC 7516) optionnel via
    `id_token_encrypted_response_alg`/`_enc` — `RSA-OAEP`/`RSA-OAEP-256`
    (clé publique RSA ≥ 2048 bits du `jwks` enregistré), `A128KW`/`A256KW`/`dir`
    (clé dérivée du secret partagé, HKDF-SHA256), méthodes `A*CBC-HS*`/`A*GCM`.
    Les clés JWKS embarquées sont validées à l'enregistrement et re-vérifiées à
    l'émission (matériel indisponible ⇒ `invalid_client`). Annonces au discovery
    (`id_token_signing_alg_values_supported`, `id_token_encryption_alg_values_supported`,
    `id_token_encryption_enc_values_supported`) ; réglages serveur
    `PURIDENTITYSERVER_JWKS_ENCRYPTION_ALGORITHMS` / `_METHODS`.

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
[OpenID Connect Front-Channel Logout]: https://openid.net/specs/openid-connect-frontchannel-1_0.html
[OpenID Connect Back-Channel Logout]: https://openid.net/specs/openid-connect-backchannel-1_0.html
