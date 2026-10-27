# OpenID for Verifiable Credential Issuance (OID4VCI 1.0)

PurIdentityServer implémente un **slice initial** du support OID4VCI (issue #172), désactivé
par défaut : l'endpoint `/credential` n'est exposé qu'avec le réglage

```toml
oid4vci_enabled = true
```

ou `PURIDENTITYSERVER_OID4VCI_ENABLED=true`.

Dans cet état, l'OP publie ses métadonnées d'émetteur (`GET
/.well-known/openid-credential-issuer`) et monte `POST /credential`, qui répond `501`
en attente de l'implémentation de l'émission complète (sous-issue #222).

Les fonctionnalités prévues (grants, proof_type JWT, SD-JWT VC avec disclosure,
mdoc, c_nonce, HAIP) sont traitées dans les sous-issues #222, #223 et #224.
