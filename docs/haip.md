# Checklist HAIP 1.0 (OpenID4VC High Assurance Interoperability Profile)

Cette page trace, exigence par exigence, le respect du profil
[OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html)
(Standard Track, Final du 24 decembre 2025) par PurIdentityServer, sur les
deux flux couverts par l'issue #172 :

- **OID4VCI issuance** — role **Credential Issuer** + Authorization Server
  ([docs/oid4vci.md](oid4vci.md)) ;
- **OID4VP presentation** — role **Verifier**, en `direct_post.jwt`
  ([docs/oid4vp.md](oid4vp.md)).

Le role **Wallet** n'est pas implemente dans ce depot : les exigences
addressées aux wallets sont marquees *Non pertinent*.

## Legende des statuts

| Statut | Signification |
| --- | --- |
| **Implemente** | Exigence couverte ; la preuve (code, test ou module de certification) est citee dans la ligne. |
| **Non pertinent** | Exigence adressee a un role non implemente (wallet), a un flux non retenu (W3C Digital Credentials API), ou point d'extension ecosysteme (HAIP §9.3) qui n'a pas ete choisi. |
| **Gap** | Exigence normative non couverte ; l'impact et le suivi sont documentes (voir [Gaps](#gaps-recapitulatifs)). |

## 1. Exigences transverses (HAIP §3, §7, §8)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §3 — chaque flux implemente supporte au moins un profil de format (§6) : SD-JWT VC ou ISO mdoc | Implemente | Issuance : SD-JWT VC (`vc+sd-jwt`) et mdoc (`mso_mdoc`), [docs/oid4vci.md](oid4vci.md) ; presentation : SD-JWT VC (`dc+sd-jwt`), [docs/oid4vp.md](oid4vp.md) |
| §3 — conformite complete aux exigences des flux retenus | Implemente | Flux issuance + presentation par redirection joues par les plans HAIP `oid4vci`, `oid4vci-mdoc` et `oid4vp` ([certification/README.md](../certification/README.md)) |
| §7 — support minimum d'ES256 (ECDSA P-256 + SHA-256) pour valider attestations, presentations et requetes signees | Implemente | Cle active OP ES256 (`identity/rotating_signer.py`), kb-jwt verifie ES256 ([application/oid4vp.py](../src/puridentityserver/application/oid4vp.py)), mdoc COSE `-7` ([infrastructure/mdoc.py](../src/puridentityserver/infrastructure/mdoc.py)), request object ES256 |
| §7 — suites cryptographiques additionnelles explicitees dans les metadata | Implemente | `credential_signing_alg_values_supported` (RS256/ES256), `dpop_signing_alg_values_supported`, `request_object_signing_alg_values_supported` ([application/discovery.py](../src/puridentityserver/application/discovery.py)) |
| §8 — SHA-256 pour tous les digests SD-JWT VC et mdoc | Implemente | `_sd_alg = sha-256` et digests des divulgations ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)), `digestAlgorithm SHA-256` du MSO ([infrastructure/mdoc.py](../src/puridentityserver/infrastructure/mdoc.py)), `sd_hash` SHA-256 du kb-jwt ([application/oid4vp.py](../src/puridentityserver/application/oid4vp.py)) |

## 2. OID4VCI — flux issuance (HAIP §4)

### 4.0 Exigences generales du flux

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §4 — support du flux authorization code (MUST) | Implemente | [docs/oid4vci.md](oid4vci.md) « Flux interactif » ; `application/authorize.py` |
| §4 — conformite FAPI 2.0 : PKCE `S256`, PAR, `iss` dans la reponse d'autorisation (RFC 9207) | Implemente | `code_challenge_method` impose a `S256` pour les clients publics (`application/authorize.py`), PAR active par defaut (`settings.par_enabled`, `application/discovery.py` publie `require_pushed_authorization_requests`), claim `iss` de la reponse (`application/authorize.py`) |
| §4 — access token sender-constrained : DPoP (RFC 9449) MUST + en-tete `DPoP-Nonce` | Implemente | `infrastructure/dpop.py` (validateur + replay), `application/dpop.py` (garde de grant), `domain/dpop.py` (`DPoP-Nonce`), endpoint `/nonce`, metadata `dpop_signing_alg_values_supported` |
| §4 — authentification du client par Wallet Attestation (la validation FAPI classique etant remplacee) | Implemente | [docs/oid4vci.md](oid4vci.md) « Authentification client par attestation » (issue #304) : en-tetes `OAuth-Client-Attestation(-PoP)` sur `/par` et `/token`, seeds `attest_jwt_client_auth` |
| §4 — indication `batch_credential_issuance` dans les metadata (MUST si le lot est supporte) | Implemente | `batch_credential_issuance.batch_size` publie ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)), [docs/oid4vci.md](oid4vci.md) « Emission par lot » |

### 4.1 Metadata de l'emetteur (HAIP §4.1)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §4.1 — metadata AS RFC 8414 (MUST) | Implemente | `/.well-known/openid-configuration` ([application/discovery.py](../src/puridentityserver/application/discovery.py)) |
| §4.1 — retrieval des metadata Credential Issuer (OID4VCI §12.2.2) (MUST) | Implemente | `GET /.well-known/openid-credential-issuer`, [docs/oid4vci.md](oid4vci.md) |
| §4.1 — une `scope` par Credential Configuration supporte (MUST) | Implemente | `scope` publie sur chaque configuration ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)) |
| §4.1 — metadata signees si l'ecosysteme l'exige, resolution de la cle par en-tete `x5c` (ancre exclue, signataire non auto-signe) (MUST) | **Gap** | Les metadata signees existent ([docs/oid4vci.md](oid4vci.md) « Metadonnees d emetteur signees ») mais la cle publique est embarquee en en-tête `jwk` (OID4VCI §12.2.2) et non en `x5c` — voir [Gaps](#gaps-recapitulatifs) |
| §4.1 — rendu des images fournies par l'emetteur (SVG/PNG, data URI/HTTPS) | Non pertinent | Cote Wallet |
| §4.1 — `nonce_endpoint` present des que le holder binding est supporte (MUST) | Implemente | `nonce_endpoint` publie ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)), endpoint `/nonce` : [docs/oid4vci.md](oid4vci.md) « c_nonce durable » |

### 4.2 Credential Offer (HAIP §4.2)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §4.2 — support du grant `authorization_code` dans l'offre (MUST) | Implemente | [docs/oid4vci.md](oid4vci.md) « Offre de credential » (grant porté par l'offre) |
| §4.2 — la `scope` de l'offre identifie le Credential Type (MUST) | Implemente | `credential_configuration_ids` de l'offre + `scope openid4vci` publiee, [docs/oid4vci.md](oid4vci.md) |
| §4.2 — scheme d'invocation `haip-vci://` (MAY) | Non pertinent | Choix : URL `https` pour l'offre (OID4VCI §4.1 l'exige en production), [docs/oid4vci.md](oid4vci.md) |
| §4.2 — support de l'offre en same-device **et** cross-device (MUST) | Implemente | Offre servie par valeur (`credential_offer`) et par reference (`credential_offer_uri` https, `no-store`, usage unique) : transportable sur les deux canaux, [docs/oid4vci.md](oid4vci.md) |

### 4.3 Endpoint d'autorisation (HAIP §4.3)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §4.3 — le wallet s'authentifie au PAR avec les memes regles qu'au token endpoint (MUST) | Implemente | En-tetes d'attestation acceptes sur `/par` comme sur `/token`, [docs/oid4vci.md](oid4vci.md) |
| §4.3 — la `scope` communique le(s) Credential Type(s), mappee a un type precis (MUST) | Implemente | `scope openid4vci` en repli, `authorization_details` RFC 9396 (`credential_configuration_id` / `credential_identifier`), [docs/oid4vci.md](oid4vci.md) « Flux interactif » |

### 4.4 Endpoint de token (HAIP §4.4)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §4.4 — refresh tokens pour le rafraichissement du credential (RECOMMENDED) | Implemente | Grant `refresh_token` (scope `offline_access`), publie au discovery ([application/discovery.py](../src/puridentityserver/application/discovery.py), `application/registration.py`) |

### 4.4.1 Wallet Attestation (HAIP §4.4.1)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §4.4.1 — authentification client obligatoire du wallet sur les endpoints OAuth (PAR, token) (MUST) | Implemente | Mecanisme d'attestation exigé dans la configuration de certification (seeds `attest_jwt_client_auth`, [certification/config.render.toml](../certification/config.render.toml)) ; en production il est conditionne au reglage de l'attester de confiance (`PURIDENTITYSERVER_CLIENT_ATTESTATION_ISSUER`/`_JWKS`) — reglage d'exploitation, cf. [docs/configuration.md](configuration.md) |
| §4.4.1 — format d'attestation (x5c de validation, `sub` partage entre instances de wallet, `client_id` = `sub`) quand le format appendice E est retenu | Non pertinent | Le format retenu est le draft `attestation-based-client-auth` valide contre le JWKS de confiance configure (`infrastructure/client_attestation.py`) ; HAIP §9.3 autorise un autre format d'attestation |

### 4.5 Endpoint de credential et key attestation (HAIP §4.5, §4.5.1)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §4.5.1 — validation des key attestations (proof types `jwt` avec `key_attestation` et `attestation`) (MUST cote wallet, supporte cote emetteur) | Implemente | `proof_types_supported.attestation` + `key_attestations_required` publies, validation de la signature et de la couverture de la cle de liaison ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)), [docs/oid4vci.md](oid4vci.md) « Attestation de cle » |
| §4.5.1 — en-tête `x5c` de la key attestation (cle publique incluse, ancre exclue, signataire non auto-signe) | Implemente | Lecture `x5c` (ou `jwk`) de l'en-tête de l'attestation, extraction de la cle de validation ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)) |
| §4.5.1 — lot + holder binding : toutes les cles attestees dans une seule key attestation (SHOULD) | Non pertinent | L'emetteur traite une attestation par preuve (une preuve = une cle de liaison, emission par lot une credential par preuve) |

## 3. OID4VP — flux de presentation (HAIP §5, role verifier)

### 5.0 Exigences communes a tous les flux

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §5 — support d'au moins un profil de format (MUST) | Implemente | SD-JWT VC (`dc+sd-jwt`), [docs/oid4vp.md](oid4vp.md) |
| §5 — `response_type` = `vp_token` (MUST) | Implemente | [docs/oid4vp.md](oid4vp.md) « Demandes et reponses » |
| §5 — Client Identifier Prefix `x509_hash`, ancre hors `x5c`, signataire non auto-signe (MUST) | Implemente | `client_id` au format `x509_hash:`, en-tête `x5c` du request object = seul le certificat leaf ([application/oid4vp.py](../src/puridentityserver/application/oid4vp.py), [infrastructure/oid4vp_pki.py](../src/puridentityserver/infrastructure/oid4vp_pki.py)) ; ancre servie par `client.request_object_trust_anchor_pem` ([certification/plans/oid4vp.json](../certification/plans/oid4vp.json)) |
| §5 — DCQL query et reponse (OID4VP §6) (MUST) | Implemente | `dcql_query` gere de bout en bout, controle `vct_values` ([application/oid4vp.py](../src/puridentityserver/application/oid4vp.py)), [docs/oid4vp.md](oid4vp.md) |
| §5 — chiffrement de la reponse : `alg = ECDH-ES` (P-256), `enc` A128GCM **et** A256GCM supportes par le verifier, listes dans `encrypted_response_enc_values_supported` (MUST) | Implemente | `SUPPORTED_ENC_VALUES = ("A128GCM", "A256GCM")` et `encrypted_response_enc_values_supported` ([application/oid4vp.py](../src/puridentityserver/application/oid4vp.py)), accord de cle ECDH-ES P-256 ([infrastructure/jwe.py](../src/puridentityserver/infrastructure/jwe.py)) |
| §5 — cle de chiffrement ephemere par demande via `client_metadata` (MUST) | Implemente | Cle P-256 generee par demande, `kid` = empreinte RFC 7638, [docs/oid4vp.md](oid4vp.md) |
| §5 — requete DCQL `trusted_authorities` (resolution par Authority Key Identifier) (MUST) | **Gap** | Aucun support de `trusted_authorities`/`aki` — voir [Gaps](#gaps-recapitulatifs) |

### 5.1 Presentation par redirections (HAIP §5.1)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §5.1 — scheme d'invocation `haip-vp://` (MAY) | Non pertinent | Choix : `response_uri` en `https`, [docs/oid4vp.md](oid4vp.md) |
| §5.1 — requetes signees via JAR (RFC 9101) avec `request_uri` (MUST) | Implemente | Request object signé ES256 (`typ = oauth-authz-req+jwt`), routes `GET`/`POST /oid4vp/request_uri/{request_id}` ([docs/oid4vp.md](oid4vp.md)) |
| §5.1 — chiffrement de la reponse en `direct_post.jwt` + securite OID4VP §14.3 (MUST) | Implemente | `response_mode = direct_post.jwt` ([application/oid4vp.py](../src/puridentityserver/application/oid4vp.py)), reponse chiffrée JWE reçue au `response_uri` |
| §5.1 — flux same-device : `redirect_uri` dans la reponse HTTP au POST du wallet (MUST) | Implemente | `200 {"redirect_uri": ...}` puis page de resultat ([docs/oid4vp.md](oid4vp.md) routes `vp_response` et `result`) |
| §5.1 — rejet si le wallet ne suit pas le retour de redirection ou si il arrive dans une session differente (MUST) | **Gap** | Aucune liaison de session sur `GET /oid4vp/result/{request_id}` — voir [Gaps](#gaps-recapitulatifs) |

### 5.2 Presentation via W3C Digital Credentials API (HAIP §5.2)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §5.2 — invocation du wallet via la DC API, response mode `dc_api.jwt`, appendice A d'OID4VP, requetes signees/unsigned/multi-signees | Non pertinent | Choix d'ecosysteme (§9.3) : flux par redirections seul (`direct_post.jwt`), aucun module DC API dans le plan `oid4vp` |

### 5.3 Exigences par format de credential (HAIP §5.3)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §5.3.1 — format `mso_mdoc`, DeviceResponse separe(s), mecanisme de revocation MSO | Non pertinent | Le verifier n'accepte que `dc+sd-jwt` ; le mdoc est supporte cote issuance uniquement (plan `oid4vci-mdoc`), plan `oid4vp` joue en `credential_format=sd_jwt_vc` |
| §5.3.2 — format `dc+sd-jwt` (MUST) | Implemente | Controle d'en-tête `typ = dc+sd-jwt`, [docs/oid4vp.md](oid4vp.md) |

## 4. Profils de format (HAIP §6)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §6 — profil SD-JWT VC (OID4VCI A.3 / OID4VP B.3) | Implemente | Issuance + presentation, [docs/oid4vci.md](oid4vci.md), [docs/oid4vp.md](oid4vp.md) |
| §6 — profil ISO mdoc (OID4VCI A.2 / OID4VP B.2) | Implemente | Issuance `mso_mdoc` ([docs/oid4vci.md](oid4vci.md) « Emission mdoc ») ; presentation mdoc hors perimetre (§5.3.1) |
| §6.1 — serialisation compacte MUST (RFC 9901) | Implemente | Format combine `credential~divulgations~` ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)) |
| §6.1 — limitation de la duree de validite : `exp` ou `status` (RECOMMENDED puis MUST si limite) | Implemente | `exp = iat + 3600` sur chaque credential emis ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)) |
| §6.1 — claim `cnf` conforme, membre `jwk` si holder binding cryptographique (MUST) | Implemente | `cnf.jwk` pose des qu'une preuve est fournie ([application/oid4vci.py](../src/puridentityserver/application/oid4vci.py)) |
| §6.1 — claim `status` s'il est present : `status_list` (MUST) | Non pertinent | L'emetteur n'emet pas de claim `status` (la validite est bornee par `exp`) ; cote verifier le type `status_list` est exige et valide, [docs/oid4vp.md](oid4vp.md) |
| §6.1 — jeton Status List : cle de validation dans l'en-tête `x5c` (ancre exclue, signataire non auto-signe) | Non pertinent | L'OP n'emet pas de status list ; dans la certification le jeton est publie par la suite OIDF (ancre `credential.status_list_trust_anchor_pem`, [certification/README.md](../certification/README.md)) ; le verifier valide la signature contre son JWKS de confiance, [docs/oid4vp.md](oid4vp.md) |
| §6.1 — index de status unique et imprevisible par credential | Non pertinent | Meme constat : producteur du jeton = suite OIDF en certification, OP non emetteur |
| §6.1.1 — emission SD-JWT VC portant la chaine `x5c` du signataire (ancre exclue, signataire non auto-signe) : supporte par **toutes** les entites (MUST) | Implemente | Emission `x5c` via la PKI de credential ([docs/oid4vci.md](oid4vci.md) « Emission x5c et PKI de credential », issue #304) ; PEM ancre injecte dans les plans (`credential.trust_anchor_pem`, HAIP-6.1) ; tests `tests/test_oid4vci_issuance.py` |
| §6.1.1 — resolution X.509 de la cle de l'emetteur cote verifier (MUST) | **Gap** | Le verifier resout la signature du credential contre le JWKS de confiance `oid4vp_credential_jwks`, sans resolution `x5c` de la chaine embarquee — voir [Gaps](#gaps-recapitulatifs) |
| §6.1.1.1 — KB-JWT toujours present a la presentation d'un SD-JWT VC avec holder binding (MUST) | Implemente | Exigence et controles `iat`/`aud`/`nonce`/`sd_hash` + signature contre `cnf.jwk`, [docs/oid4vp.md](oid4vp.md) |

## 5. Considerations implementation, securite et privacy (HAIP §9 a §11)

| Exigence | Statut | Preuve |
| --- | --- | --- |
| §9.1 — prerequis navigateur/OS (schemes, DC API) | Non pertinent | Choix de n'utiliser que des URL `https` (aucune dependance a un scheme custom ou a la DC API) |
| §9.2 / §11.1 — backend de transformation des key attestations (disponibilite, privacy) | Non pertinent | Cote Wallet |
| §9.4 — versions des specifications pre-finales de reference (SD-JWT VC draft-13, Token Status List draft-14) | Implemente | Implemente sur les versions referencees par HAIP (RFC 9901 publie, OTSL draft-14 consomme tel quel) |
| §10.1 — validation par les outils de conformite OIDF | Implemente | Plans HAIP joues en CI : `oid4vci`, `oid4vci-mdoc`, `oid4vp` ([certification/README.md](../certification/README.md), `.github/workflows/certification-local.yml`) |
| §10.2 — tailles de cles appropriees | Implemente | EC P-256 partout, RSA parametrable (`jwks_key_size`) ; conformite des trousseaux dans `tests/test_key_conformity.py` |
| Annexe A — schemes `haip-vci` / `haip-vp` (IANA) | Non pertinent | Schemes MAY non retenus (voir §4.2 et §5.1) ; l'enregistrement IANA est porte par l'OIDF |

## Choix d'ecosysteme (HAIP §9.3)

HAIP laisse le choix de plusieurs points aux ecosystemes. Les choix retenus
par PurIdentityServer :

| Point d'extension (§9.3) | Choix retenu |
| --- | --- |
| Flux a adopter | Issuance OID4VCI + presentation OID4VP par redirections (pas de DC API) |
| Formats de credential | SD-JWT VC (issuance + presentation), ISO mdoc (issuance seul) |
| Metadata signees | Supportees (variante `jwk` — ecart `x5c` documente plus bas) |
| Methode de mise a disposition de l'offre | URL `https` (pas de scheme `haip-vci://`) |
| Format de Wallet Attestation | Draft `attestation-based-client-auth` valide contre un JWKS de confiance |
| Format de Key Attestation | Appendice D d'OID4VCI (proof types `jwt`/`key_attestation` et `attestation`) |
| Profil de certificat X.509 | PKI locale du projet (`certification/generate_pki.py`, leaf seule hors `x5c`) |
| Suites cryptographiques supplementaires | RS256 pour l'emission `x5c`, annonce dans les metadata |

## Gaps recapitulatifs

| # | Exigence | Ecart | Impact | Suivi |
| --- | --- | --- | --- | --- |
| 1 | HAIP §4.1 — resolution `x5c` des metadata signees | Les metadata signees embarquent la cle publique en en-tête `jwk` (variante OID4VCI §12.2.2) au lieu de `x5c` | Un wallet HAIP exigeant la resolution `x5c` refuserait les metadata signees ; les metadata non signees (defaut) restent utilisables | Documente ici ; non teste par les plans HAIP actuels |
| 2 | HAIP §5 — requete DCQL `trusted_authorities` (aki) | Non implemente | Une demande de notre verifier ne peut pas exprimer d'ancres de confiance par Authority Key Identifier ; les wallets fondes sur `aki` ne peuvent pas filtrer | Non teste par le plan `oid4vp` (modules `sd_jwt_vc`) |
| 3 | HAIP §5.1 — liaison de session du retour de redirection | `GET /oid4vp/result/{request_id}` sert la page sans liaison de session | La protection anti-phishing supplementaire (rejet si session differente) n'est pas couverte ; l'acceptation elle-meme reste decidee au `response_uri` apres validation complete du `vp_token` | Non teste par le plan `oid4vp` |
| 4 | HAIP §6.1.1 — resolution X.509 cote verifier | Signature du credential validee contre le JWKS configure `oid4vp_credential_jwks`, sans resolution de la chaine `x5c` embarquee | Un credential dont la chaine `x5c` menerait a une ancre de confiance, mais signe par une cle absente du JWKS configure, serait rejeté | En certification, la cle de signature attendue est injectee dans le plan (`credential.signing_jwk`) : modules verts |

Ces ecarts ne sont detectes par aucun module des plans HAIP actuels
(`expected-failures` vides pour `oid4vci`, `oid4vci-mdoc` et `oid4vp`) : ils
constituent le perimetre documentaire de l'issue #172 pour les reglages a
venir, dont la variante `issuer_initiated` du plan `oid4vci` (issue #306).
