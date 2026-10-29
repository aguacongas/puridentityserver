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
pour le `sub` transporté, avec `cnf.jwk` si une preuve est fournie. Le flux pre-autorisé (offre de credential, code à usage unique, échange au
token endpoint) et le flux interactif (authorization code avec
`authorization_details` RFC 9396, type `openid_credential`) sont implémentés.
Le consentement réutilise l'écran OIDC existant. Le jeton d'accès porte le
claim `authorization_details` (avec `credential_identifiers`) quand ce
paramètre a été utilisé ; `/credential` exige alors `credential_identifier`
et refuse `credential_configuration_id`. La publication AS annonce
`authorization_details_types_supported: ["openid_credential"]`. Le c_nonce
durable reste à implémenter.

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

L emetteur annonce une entree proof_types_supported.attestation dediee (key_attestations_required). Une preuve peut transporter une attestation
de cle via le parametre d en-tete key_attestation; sa signature est
verifiee et une attestation invalide est rejetee (invalid_proof).

## Grant pre-autorise (OID4VCI 1.0 s6.1)

L'OP accepte le grant `urn:ietf:params:oauth:grant-type:pre-authorized_code` au token
endpoint, avec `tx_code` optionnel. Les codes sont a usage unique et
expirent; le jeton d'acces emis permet ensuite d'appeler `/credential`.

## Offre de credential (OID4VCI 1.0 s4.1)

Deux routes, ajoutees par l'OP (la specification ne normalise pas d'endpoint
de creation d'offre : elle decrit l'objet et sa reference), completent le
flux issuer-initiated :

    POST /credential-offer
    Authorization: Bearer <access token portant le scope openid4vci>
    {"subject": "alice", "credential_configuration_ids": ["puridentityserver-sdjwt-vc"], "tx_code": true}

    GET /credential-offer/{offer_id}

La creation exige un access token portant le scope `openid4vci`. Le
titulaire du credential est le `sub` du jeton ; un jeton machine
(`client_credentials`, `sub` egal au `client_id`) doit fournir `subject`
et peut designer n'importe quel sujet, alors qu'un jeton utilisateur ne
peut pas designer un autre sujet que le sien (403 sinon). La reponse
porte l'offre par valeur (`credential_offer`), sa reference
(`credential_offer_uri`) et, si `tx_code` est demande, le code de
transaction a 6 chiffres — restitue une seule fois (canal separe).

`GET /credential-offer/{offer_id}` est non authentifie (le wallet n'a pas
encore de jeton), repond sans cache (`Cache-Control: no-store`) et cesse
de repondre (404) des que le code pre-autorise est consomme ou expire.
Les offres sont persistees (`credential_offers`, backend memoire ou SQL)
pour que la reference reste servable derriere plusieurs workers. La
reference est une URL `https` en production (OID4VCI 1.0 s4.1 : scheme
`https` exige), duree de vie et usage unique compris (s13.5).


## Flux interactif (authorization code) (OID4VCI 1.0 s5.1.1)

L'OP accepte `authorization_details` (RFC 9396) de type `openid_credential`
sur `/authorize` et `/par`, en plus du scope `openid4vci` conserve en repli.
Chaque detail porte un `credential_configuration_id` reconnu par l'OP. Le
parametre est persiste sur le code d'autorisation, porte dans l'access token
(claim RFC 9396 s7) et impose, sur `/credential`, l'usage de
`credential_identifier` (appartenant aux `credential_identifiers` accordes)
a la place de `credential_configuration_id`. Sans `authorization_details`,
`/credential` conserve l'exigence du scope `openid4vci` et de
`credential_configuration_id`.
