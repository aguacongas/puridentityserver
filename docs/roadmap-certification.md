# Roadmap certification OIDC

Objectif final : **passer la certification OIDC (Core + extensions) et automatiser la suite
de certification officielle en CI**, afin que chaque PR soit un pas vérifiable vers la conformité.

État au merge de cette PR (issue #46) : IdentityResources (#44) et
Authentification client **JWT** + grant **jwt-bearer** (#46) implémentés —
`client_secret_jwt` / `private_key_jwt` (RFC 7523 §2.2), `tls_client_auth` /
`self_signed_tls_client_auth` (RFC 8705), secrets HMAC **chiffrés au repos**
(RSA-OAEP, clé de scellement auto-rotée) ; grant `urn:ietf:params:oauth:grant-type:jwt-bearer` (§2.1) ;
années au discovery (`grant_types_supported`, `token_endpoint_auth_methods_supported`) ;
sample DoD `samples/jwt-bearer-client/` ; gate CI + SonarCloud vert.
Chaque feature restante = **une issue indépendante** (traçabilité + gate par delta).

---

## Socle — OIDC Core (P0, indispensable avant toute playlist)

| # | Feature | Pourquoi (playlist OIDC) |
|---|---|---|
| #44 ✅ | **IdentityResources** CRUD + seed (username/profile/email/phone/address) | `claims_supported`, `/userinfo`, `scopes_supported` — livré au merge PR#53 |
| [#45](https://github.com/aguacongas/puridentityserver/issues/45) 🎯 | **ApiResources** CRUD + seed (ressources protégées) + validation audience | `aud` des access_tokens, `resource` introspection/revocation — implémenté, PR en cours |
| [#46](https://github.com/aguacongas/puridentityserver/issues/46) ✅ | Grant **jwt-bearer** (RFC 7523) + `client_secret_jwt` + `tls_client_auth` (RFC 8705) — méthodes d'auth client exigées par la playlist de certification, livré avec sample DoD `samples/jwt-bearer-client/` |
| [#47](https://github.com/aguacongas/puridentityserver/issues/47) ✅ | Algos manquants (HS256/384/512, ES384/512, JWE : RSA-OAEP, A128KW, dir) | `id_token` encryption + `jwt algos` attendus par la playlist alg — livré au merge PR#60 |
| [#48](https://github.com/aguacongas/puridentityserver/issues/48) ✅ | **Logout front/back-channel** (OIDC Session Mgmt) | `sid` émis au login, claim `sid` des `id_token` ; `/end_session` → iframes `frontchannel_logout_uri` (+ `?sid=` si session_required) et POST du `logout_token` signé vers chaque `backchannel_logout_uri` ; annonces discovery — livré avec sample DoD `samples/logout-channel-client/` |
| [#62](https://github.com/aguacongas/puridentityserver/issues/62) ✅ | **Session Management natif navigateur** (OIDC Session Mgmt 1.0) | `session_state` dans la réponse d'`/authorize` (empreinte salée client + origin + `sid` cookie HttpOnly, jamais lisible en JS) ; page `check_session_iframe` (`/session_state`) + endpoint de statut `/check_session` (réponses `unchanged`/`changed`/`error`) ; métadonnée discovery — livré dans sample DoD `samples/spa-client/` |

Ordre d'implémentation conseillé : **#44 → #45 → #46 → #47** (terminés : #44, #46, #47, #48, #62).

## Extensions — OIDC Advanced / proche (P1)

| # | Feature | Référence |
|---|---|---|
| [#49](https://github.com/aguacongas/puridentityserver/issues/49) ✅ | **DPoP** (RFC 9449) — proof-of-possession du token | `cnf.jkt` des access_tokens + `token_type: DPoP` (§5.1), preuve exigée par client (`require_dpop`, §5.2), anti-replay `jti` (§11), `/userinfo` scheme `DPoP` (§7), `dpop_jkt` à l'authorization + PAR (§10), annonce `dpop_signing_alg_values_supported` — livré avec sample DoD `samples/dpop-client/` |
| [#50](https://github.com/aguacongas/puridentityserver/issues/50) ✅ | **CIBA** (Client-Initiated Backchannel Authentication) — modes poll/ping | OIDC CIBA 1.0 : `POST /bc-authorize` (hints `login_hint`/`login_hint_token`/`id_token_hint`), grant `urn:openid:params:grant-type:ciba` (`authorization_pending`/`slow_down`/`access_denied`), approbation démo `POST /ciba/approve` (flag `ciba_approval_enabled`), notification `ping` (POST JSON, 1 seul essai), métadonnées discovery + DCR (`backchannel_token_delivery_modes_supported`) — livré au merge PR#102 ; sample DoD `samples/ciba-client/` ; plan `fapi-ciba-id1-test-plan` en witness, découpé en [#100](https://github.com/aguacongas/puridentityserver/issues/100) (JAR signé) et [#101](https://github.com/aguacongas/puridentityserver/issues/101) (Resource Indicators RFC 8707 + resource servers) |
| [#100](https://github.com/aguacongas/puridentityserver/issues/100) 🎯 | **CIBA — request object signé (JAR) exigé par FAPI-CIBA-ID1** | Champ DCR `backchannel_authentication_request_signing_alg` (PS256/ES256/RS256) : tout client enregistré doit adresser un `request` JWT signé à `/bc-authorize` — claims fusionnés (`scope`, `login_hint`, `login_hint_token`, `id_token_hint`, `binding_message`, `acr_values`, `client_notification_token`, `requested_expiry`), `iss` = `client_id` / `aud` = issuer / `exp − nbf` ≤ 60 min / `jti` anti-replay (store `dpop_jtis`, namespace `ciba:`), client déduit de l'`iss` de l'assertion (corps sans `client_id`), échec → `invalid_request` 400 (pas `invalid_request_object`), `iss` ≠ client authentifié → `invalid_client` 401, discovery `backchannel_authentication_request_signing_alg_values_supported` — implémenté, PR en cours ; sample DoD étendu `samples/ciba-client/` (mode `CIBA_SIGNED=1` : DCR à clé RSA éphémère + poll par assertion) |
| [#101](https://github.com/aguacongas/puridentityserver/issues/101) 🎯 | **Resource Indicators (RFC 8707) + resource servers de la certification** | Paramètre `resource` sur `/authorize` (GET/POST), `/par`, `/bc-authorize` et `/token` (occurrences multiples repliées en tableau JSON compact), URI contrôlées contre l'`indicator` des `ApiResource` (malformée ou hors registre → `invalid_target`, redirectable sur `/authorize`), resources **liées au support** (code d'autorisation, refresh token, ticket CIBA — le `/token` n'accepte qu'un sous-ensemble, §4), `aud` de l'access token = l'URI ciblée (chaîne) ou la liste des URI (ordre du client, prioritaire sur le calcul par scopes) ; resource server intégré `GET /protected-resource` (flag `protected_resource_enabled`, Bearer uniquement — query string refusée, `401` + challenge `WWW-Authenticate`, `x-fapi-interaction-id` échoyée ou `uuid4` générée, `Date` posé par uvicorn) — implémenté, PR en cours ; fixes certification `resource.resourceUrl` (`certification/plans/ciba.json`) + `client2.acr_value = "loa2"` ; sample DoD `samples/resource-indicators-client/` |

## Certification — automatisation (P2, bouteille finale)

| # | Feature |
|---|---|
| [#51](https://github.com/aguacongas/puridentityserver/issues/51) | Automatiser la **suite de certification OIDC officielle** (OpenID Certification / `oidc-certification`) en CI + autoriser le gate |
| [#69](https://github.com/aguacongas/puridentityserver/issues/69) → [#72](https://github.com/aguacongas/puridentityserver/issues/72) ✅ | **Rejeu local des plans Core** : 188 tests `conformance` (Basic/Implicit/Hybrid) extraits de `release-v5.2.4` + smoke contre un vrai serveur uvicorn (`samples/conformance-smoke/`) — traçabilité `tests/conformance/TRACEABILITY.md`, doc « Rejeu local sans la suite » dans `certification/README.md` ; plus aucun skip depuis [#76](https://github.com/aguacongas/puridentityserver/issues/76) ✅ (`alg=none` + request objects RFC 9101) |
| [#90](https://github.com/aguacongas/puridentityserver/issues/90) | **Captures d'écran réelles des verdicts `review`** (21 occurrences = 4 modules Core) : `certification/capture_screenshots.py` rejoue les scénarios contre l'OP déployé (Playwright/chromium headless) en CI, `conformance-screenshots.patch` téléverse ce PNG à la place du PNG 1x1 de secours, publiés dans l'artefact `certification-screenshots` **et sur la page GitHub Pages** (`report.py --screenshots`) |

---

## Critère de fin global

- Chaque playlist OIDC officielle (Core, Form Post, Session Mgmt, CIBA, DPoP si applicable)
  passe **en CI** sur le dépôt, avec preuve exporter (rapports de la suite).
- `docs/configuration.md` et `docs/installation.md` restent synchronisés (gate « Docs à jour »).
