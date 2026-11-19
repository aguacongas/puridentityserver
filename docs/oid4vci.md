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


## Authentification client par attestation (issues #304 / #172)

Les plans HAIP `oid4vci-1_0-issuer-haip-test-plan` (issues `oid4vci` et
`oid4vci-mdoc`) attendent une authentification client par attestation sur
`/par` et `/token` (draft-ietf-oauth-attestation-based-client-auth) : l'OP
accepte les en-têtes `OAuth-Client-Attestation` et `OAuth-Client-Attestation-PoP`
pour une méthode `attest_jwt_client_auth` enregistrée (seed ou DCR), dès que
l'attester de confiance est configuré (`PURIDENTITYSERVER_CLIENT_ATTESTATION_ISSUER`
/ `..._JWKS` — voir `docs/configuration.md`). Les seeds
`puridentityserver-oid4vci-client{,2}` de `certification/config.render.toml`
sont en `attest_jwt_client_auth`.


## Émission x5c et PKI de credential (issue #304)

Deux settings de PKI (chemins JSON relatifs à la racine de travail) équipent
l'émission des credentials :

- **SD-JWT VC** — `PURIDENTITYSERVER_CREDENTIAL_PKI_PATH` : CA racine RSA +
  leaf RSA. Quand le fichier est chargé, chaque credential SD-JWT emporte la
  chaîne `x5c` (leaf seule, base64 standard) validée par le wallet contre
  l'ancre `credential.trust_anchor_pem` (HAIP-6.1), signé en RS256 (alg
  épinglé) avec `kid` = b64u(SKI de la leaf). Sans le setting, le credential
  est émis sans `x5c`.
- **mdoc (ISO 18013-5)** — `PURIDENTITYSERVER_MDOC_PKI_PATH` : IACA
  (profil IACA Table B.1, `issuer_key_pem` / `issuer_cert_pem`,
  rétrocompatible 4 champs) + leaf du document signataire. Le document signer est
  minté au démarrage avec l'issuer runtime de l'OP ; la chaîne `x5chain` ne
  porte que le document signer (l'ancre reste hors chaîne) et le CDP est
  `{issuer}/crl/mdoc.crl` (endpoint CRL déjà monté). Sans le setting, pas de
  `x5chain`.

Les deux fichiers de la certification (`certification/pki/credential-pki.json`
et `certification/pki/mdoc-iaca.json`) sont régénérés de façon idempotente par
`uv run python certification/generate_pki.py` ; leurs PEM ancre
(`credential-root.pem`, `mdoc-iaca.pem`) sont injectés dans les plans
`certification/plans/oid4vci.json` / `oid4vci-mdoc.json`.


## Chiffrement des credential requests / responses (OID4VCI 1.0 s8.2)

Réglage `oid4vci_encryption_enabled` (défaut `false`, actif dans
`certification/config.render.toml`). Quand il est actif, l'OP :

- publie les blocs `credential_request_encryption` (sa clé publique EC P-256
  dans `jwks`, avec `kid` = empreinte RFC 7638, `alg` = `ECDH-ES`, `use` =
  `enc`) et `credential_response_encryption` (`alg_values_supported` =
  `["ECDH-ES"]`) dans les métadonnées d'émetteur, JSON et signées ;
  `enc_values_supported` a `A256GCM` en tête (les deux parties retiennent
  l'élément `[0]` par défaut), `encryption_required` est `false` et
  `zip_values_supported` vaut `["DEF"]` ;
- accepte les corps `POST /credential` en `application/jwt` : le credential
  request est un JWE compact ECDH-ES (mode Direct Key Agreement, courbe
  P-256) chiffré avec la clé publiée ; un en-tête hors capability
  (`alg`, `enc` ou `zip` inconnus) oppose
  `invalid_encryption_parameters`, tout autre échec `invalid_request` ;
- chiffre la réponse quand le wallet la demande via
  `credential_response_encryption` (`jwk` EC P-256 du wallet, `enc`, `zip`
  optionnel) : la réponse est alors un JWE compact en `application/jwt`
  qui reprend le `kid` du jwk du wallet et `zip = DEF` si demandé.

Sans le réglage, aucune capability n'est annoncée ni acceptée : une demande
de chiffrement est refusée (`invalid_encryption_parameters`).

La clé privée de chiffrement est provisionnée à la première usage dans le
store de cléf partagé (`storage_type` = `memory` ou `sql`), donc
partagée entre instances (load balancing) et stable d'un redémarrage à
l'autre ; deux instances concurrentes convergent sur la même clé
(insertion unique, la perdante est ignorée).

Les erreurs `/credential` restent en JSON non chiffré, même quand le
chiffrement de la réponse est demandé (OID4VCI s8.3.1).


## Divulgations selectives SD-JWT (RFC 9901)

Le credential SD-JWT emis porte les claims `given_name` et `family_name`
sous forme selectivement divulgables : le JWT emetteur contient leur
digest sale dans le membre `_sd` (`_sd_alg = sha-256`), et les
divulgations completes figurent dans le format combine (apres le premier
`~`). Des digests leurres masquent le nombre de claims. Le wallet peut
ainsi reveler un sous-ensemble de ces claims lors de la presentation, sans
reveler le reste.


## Endpoints differe et notification (OID4VCI s9 et s11)

L'OP expose `POST /deferred_credential` (aucun transaction_id n'est emis,
l'issuance etant immediate) et `POST /notification`. Chaque reponse
`/credential` porte un `notification_id`, que le wallet peut renvoyer a
`/notification` avec l'event `credential_accepted` (ou
`credential_failure`/`credential_deleted`) ; la notification est idempotente.
Les metadonnees d'emetteur publient les deux endpoints.


## c_nonce durable (OID4VCI s7-s8)

Le `c_nonce` durable de l'OP reste fourni par l'endpoint `/nonce` (JWT signe)
et n'est plus duplique dans la reponse `/credential`, conformement aux cles
attendues par la suite OIDF (`credentials`, `transaction_id`,
`notification_id`, `interval`). Le nonce est un JWT signe par l'OP : il reste valide derriere
plusieurs workers et redemarrages pendant sa duree de vie.


## Emission mdoc ISO 18013-5 (format mso_mdoc)

L'OP emet egalement un credential mdoc (ISO/IEC 18013-5) en plus du SD-JWT VC.
La configuration `puridentityserver-mso-mdoc` est publiee dans les
metadonnees d'emetteur, avec le format `mso_mdoc`, le doctype
`org.iso.18013.5.1.mDL` et la methode de liaison `cose_key`.

Quand le wallet cible cette configuration sur `/credential`, l'OP delivre un
`IssuerSigned` CBOR (encode en base64url sans padding) dont :

- l'`issuerAuth` est un COSE Sign1 en tableau COSE de 4 éléments **sans tag
  CBOR 18** (exigence des parseurs mdoc, dont `CoseSign1.fromDataItem`),
  portant la MobileSecurityObject (docType, digestAlgorithm `SHA-256`,
  digests des éléments indexés par `digestId`, validityInfo en tag CBOR 0,
  deviceKeyInfo) ;
- la chaine `x5chain` (RFC 9360) embarque le document signer puis l'IACA ;
- le device key du wallet (proof EC P-256) est converti en cle COSE publique et
  lie au mdoc via `deviceKeyInfo.deviceKey` ;
- chaque élément est porté par un `IssuerSignedItem` (tag CBOR 24) en carte
  CBOR **à clés texte** (`digestID`, `random`, `elementIdentifier`,
  `elementValue`) : l'encodage de la librairie multipaz, celui que lit la
  suite de conformance OIDF ;
- les **11 éléments obligatoires du mDL** (ISO 18013-5 §13.4.2, table 20,
  présence « M ») sont émis dans le namespace `org.iso.18013.5.1` :
  `family_name`, `given_name`, `birth_date`, `issue_date`, `expiry_date`,
  `issuing_country` (aligné sur le `countryName` du document signer),
  `issuing_authority`, `document_number`, `portrait` (bstr),
  `driving_privileges` (tableau de maps avec `vehicle_category_code`
  obligatoire, dates full-date et `codes`) et `un_distinguishing_sign` ;
  les dates sont encodées en **tag CBOR 1004** (full-date RFC 3339) et les
  textes respectent les contraintes de la table 20 (latin-1, 150 caractères
  au plus, pays en alpha-2).

La PKI mdoc (IACA auto-signee + document signer) est generee a la volee, en
memoire, a la premiere emission ; le certificat de l IACA est publie dans
les metadonnees sous la cle `mdoc_iaca_certificates` (x5c base64 DER sans
padding) pour servir d ancre de confiance aux verifiers externes. Le
certificat du document signer suit le profil ISO 18013-5 Table B.3 :
`countryName` `FR`, `keyUsage` critique limité à `digitalSignature`,
`extendedKeyUsage` critique avec l'OID `mdlDS` (`1.0.18013.5.1.2`),
identifiants de clé SKI/AKI, nom alternatif de l'émetteur et point de
distribution de CRL, `basicConstraints` non critique, validité de 456 jours
(plafond 457) supérieure au `validUntil` du MSO. Les timestamps du MSO
(`signed`, `validFrom`, `validUntil`) sont arrondis à l'heure comme sur le
chemin SD-JWT, pour que deux credentials d'un même lot ne soient pas
corrélables par leurs dates (RFC 9901 §10.1). La
configuration mdoc annonce :
- `credential_signing_alg_values_supported` : identifiant COSE `-7` (ES256) -
  entier COSE requis par le schema OIDF ;
- preuve de liaison EC P-256 via `proof_types_supported.jwt` (`ES256`).
Une cle de preuve non EC P-256 est refusee (`invalid_proof`).
- proof type `attestation` annoncé avec `key_attestations_required` (parité
  avec la configuration SD-JWT) : une key attestation transportée par la
  preuve est validée (signature, couverture de la clé de liaison) et une
  attestation invalide est rejetée (`invalid_proof`).

Un sample pas-a-pas est disponible dans `samples/oid4vci-mdoc-client/`.



## Persistance de la PKI mdoc (OID4VCI tranche 3)

La PKI mdoc (IACA + document signer) peut être persistée via `Settings` :

- `mdoc_pki_path` : chemin complet d'un fichier JSON de PEM persistant.

Configuration via `config.toml` :

```toml
mdoc_pki_path = "/var/data/puridentity-mdoc-pki.json"
```

ou env :

```bash
PURIDENTITYSERVER_MDOC_PKI_PATH=/var/data/puridentity-mdoc-pki.json
```

Si vide (défaut), le comportement éphémère conserve la génération à la volée
à chaque démarrage. Quand un chemin est fourni, la PKI est chargée depuis le
fichier si présent ; sinon une nouvelle PKI est générée puis persistée pour
les redémarrages suivants et les autres processus.
