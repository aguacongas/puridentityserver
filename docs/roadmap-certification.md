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
| [#47](https://github.com/aguacongas/puridentityserver/issues/47) | Algos manquants (HS256/384/512, ES384/512, JWE : RSA-OAEP, A128KW, dir) | `id_token` encryption + `jwt algos` attendus par la playlist alg |

Ordre d'implémentation conseillé : **#44 → #45 → #46 → #47**.

## Extensions — OIDC Advanced / proche (P1)

| # | Feature | Référence |
|---|---|---|
| [#48](https://github.com/aguacongas/puridentityserver/issues/48) | Logout **front-channel + back-channel** (hors `end_session` seul) | OIDC Session Mgmt |
| [#49](https://github.com/aguacongas/puridentityserver/issues/49) | **DPoP** (RFC 9449) — proof-of-possession du token | authorization/token/introspection |
| [#50](https://github.com/aguacongas/puridentityserver/issues/50) | **CIBA** (Client-Initiated Backchannel Authentication) — modes poll/ping | OIDC CIBA |

## Certification — automatisation (P2, bouteille finale)

| # | Feature |
|---|---|
| [#51](https://github.com/aguacongas/puridentityserver/issues/51) | Automatiser la **suite de certification OIDC officielle** (OpenID Certification / `oidc-certification`) en CI + autoriser le gate |

---

## Critère de fin global

- Chaque playlist OIDC officielle (Core, Form Post, Session Mgmt, CIBA, DPoP si applicable)
  passe **en CI** sur le dépôt, avec preuve exporter (rapports de la suite).
- `docs/configuration.md` et `docs/installation.md` restent synchronisés (gate « Docs à jour »).
