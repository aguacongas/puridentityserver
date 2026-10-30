# OpenID for Verifiable Presentations (OID4VP 1.0)

PurIdentityServer implémente un slice initial de la capacité **verifier** (issue #172), désactivé
par défaut : l'endpoint `/vp_response` n'est exposé qu'avec le réglage

```toml
oid4vp_enabled = true
```

ou `PURIDENTITYSERVER_OID4VP_ENABLED=true`.

Dans cet état, l'OP monte `POST /presentation_requests` (request object signé) et
`POST /vp_response`, qui renvoie `501` en attente de la validation complète de la
présentation (sous-issue #223).

Validation de la reponse direct_post implementee (vp_token, nonce).

Verification cryptographique du `vp_token` (signature auto-portee, audience, expiration, nonce) implementee pour `direct_post`.

Verification cryptographique du `vp_token` (JWK embarque, signature, audience, nonce) implementee.

Support DCQL : `create_presentation_request` accepte `dcql_query`, et `/vp_response`
accepte un `vp_token` scalaire, tableau ou objet DCQL (mappage id -> vp_token).
