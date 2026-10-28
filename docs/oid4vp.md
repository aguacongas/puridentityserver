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
