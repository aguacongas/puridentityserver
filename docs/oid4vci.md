# OpenID for Verifiable Credential Issuance (OID4VCI 1.0)

PurIdentityServer implémente un **slice initial** du support OID4VCI (issue #172), désactivé
par défaut : l'endpoint `/credential` n'est exposé qu'avec le réglage

```toml
oid4vci_enabled = true
```

ou `PURIDENTITYSERVER_OID4VCI_ENABLED=true`.

Dans cet état, l'OP publie ses métadonnées d'émetteur (`GET
/.well-known/openid-credential-issuer`) et monte `POST /credential`, qui **rejette
401** tout requête sans access token, **valide la preuve** `proof_type=jwt`
(émetteur = issuer, preuve signée par la JWK embarquée) et émet, en cas de jeton
valide, un credential **SD-JWT** (`vc+sd-jwt`) signé à la clé active de l'OP
pour le `sub` transporté, avec `cnf.jwk` si une preuve est fournie. Le consentement,
le flux wallet/authorization code et le c_nonce durable restent à implémenter.

Les fonctionnalités prévues (grants, proof_type JWT, SD-JWT VC avec disclosure,
mdoc, c_nonce, HAIP) sont traitées dans les sous-issues #222, #223 et #224.


Le harness de certification expose le plan oid4vci (selectors + plan JSON) pour mesurer l'ecart restant.


## Metadonnees d emetteur signees (OID4VCI 1.0)

L emetteur peut servir ses metadonnees signees en envoyant :

    GET /.well-known/openid-credential-issuer
    Accept: application/jwt

La reponse est un JWT signe avec la cle active de l OP (media type application/jwt),
typ openidvci-issuer-metadata+jwt, la cle publique dans l entete JOSE (jwk),
les claims sub et iat requis et tous les parametres de metadonnees au
premier niveau. Par defaut (pas d entete Accept: application/jwt), la
reponse reste en application/json non signe.

## Emission par lot (batch) (OID4VCI 1.0)

L emetteur annonce batch_credential_issuance.batch_size dans ses metadonnees. Une requete /credential avec plusieurs preuves (proofs.jwt) declenche l emission d un credential SD-JWT par preuve,
chacun lie a sa propre cle (cnf.jwk), avec des claims temporels
arrondis a l heure pour eviter la correlation (RFC 9901 s10.1).

## Attestation de cle (OID4VCI appendice D.1)

L emetteur annonce key_attestations_required dans proof_types_supported.jwt. Une preuve peut transporter une attestation
de cle via le parametre d en-tete key_attestation; sa signature est
verifiee et une attestation invalide est rejetee (invalid_proof).
