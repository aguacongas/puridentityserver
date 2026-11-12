# OpenID for Verifiable Presentations (OID4VP 1.0)

PurIdentityServer implémente le rôle **verifier** d'OpenID4VP 1.0 Final
(issue #224), en mode `direct_post.jwt` du profil HAIP — désactivé par défaut.

## Activation

```toml
oid4vp_enabled = true
```

ou `PURIDENTITYSERVER_OID4VP_ENABLED=true`. Sans ce réglage, les quatre
routes ci-dessous répondent `501`.

Réglages complémentaires (voir `src/puridentityserver/infrastructure/settings.py`) :

| Réglage | Rôle |
| --- | --- |
| `oid4vp_pki_path` | fichier JSON persistant de la PKI du verifier (CA + leaf). Absent = PKI éphémère générée en mémoire au premier usage. |
| `oid4vp_credential_jwks` | JWKS public de confiance pour la signature des credentials SD-JWT. Vide = le contrôle de signature est **escamoté** (mode witness, seul cas où la suite peut rejeter `invalid-credential-signature`). |

## Routes (`/oid4vp/*`)

| Route | Rôle |
| --- | --- |
| `POST /oid4vp/presentation_requests` | crée et signe une demande : `201` `{request_id, client_id, request_uri, nonce, request_object}`. Corps JSON objet (vide accepté), `dcql_query` optionnel (défaut : credential PID `dc+sd-jwt`). |
| `GET /oid4vp/request_uri/{request_id}` | sert le request object (`application/oauth-authz-req+jwt`), idempotent. |
| `POST /oid4vp/request_uri/{request_id}` | variante `request_uri_method=post` : re-signé avec le `wallet_nonce` reçu en formulaire (OID4VP §5.10). |
| `POST /oid4vp/vp_response/{request_id}` | reçoit le `response` (JWE compact) du wallet en `application/x-www-form-urlencoded` ; `200 {"redirect_uri": ...}` accepté, `400`/`404` motivé rejeté (RFC 6749 §5.2). |
| `GET /oid4vp/result/{request_id}` | page HTML du `redirect_uri` : « Presentation acceptee » ou « Presentation refusee » + motif. |

## Demandes et réponses

- **Request object** signé ES256, `typ = oauth-authz-req+jwt`,
  `aud = https://self-issued.me/v2` (OID4VP §5.8), en-tête `x5c` de la PKI du
  verifier, `client_id` au format `x509_hash:`, `response_type = vp_token`,
  `response_mode = direct_post.jwt`, `response_uri`, `nonce` (32 octets
  base64url), `dcql_query` et `client_metadata` (clé de chiffrement
  éphémère P-256 par demande, `kid` = empreinte RFC 7638, `alg = ECDH-ES` —
  HAIP §5-6 interdit tout réemploi de clé).
- **Réponse du wallet** : `vp_token` (objet d'un seul credential SD-JWT
  `credential~divulgations~kb+jwt`), chiffré en JWE compact
  `ECDH-ES`/`A128GCM` vers la clé du `client_metadata`.

## Contrôles appliqués au `vp_token`

Toute anomalie produit un `400 invalid_request` motivé :

1. JWE lisible, `kid` connu du déchiffrement de la demande ;
2. `vp_token` : objet d'un unique credential, chaîne SD-JWT présente ;
3. en-tête credential `typ = dc+sd-jwt` ;
4. `kb+jwt` : claims strictement `iat`, `aud`, `nonce`, `sd_hash` ;
5. `nonce` et `aud` (`client_id`) conformes à la demande ;
6. `sd_hash` = SHA-256 (base64url) du préfixe présenté jusqu'au dernier `~`
   (RFC 9901 §3.2) ;
7. `iat` du kb-jwt dans ± 5 minutes ;
8. signature du kb-jwt vérifiée contre `cnf.jwk` du credential ;
9. signature du credential vérifiée contre `oid4vp_credential_jwks` (si
   configuré).

Les demandes vivent en mémoire (FIFO bornée à 32) : un `response_uri` déjà
consommé ou inconnu répond `404`.

## Sample de démonstration

`samples/oid4vp-verifier-client/` rejoue le round-trip complet (création,
`request_uri` GET et POST `wallet_nonce`, réponse chiffrée, page de résultat,
contre-épreuve de signature) contre un OP dédié :

```bash
uv run python samples/oid4vp-verifier-client/smoke_test.py
```

Le wallet simulé est `tests/oid4vp_wallet.py` pour les tests unitaires
(également utilisé pour les modules négatifs de certification).

## Certification

Le plan `oid4vp-1final-verifier-haip-test-plan` (11 modules : 4 positifs en
relecture, 7 négatifs) se rejoue contre la suite OIDF :

```bash
bash certification/local/setup.sh
bash certification/local/run-plan.sh oid4vp
```

Matériel : `certification/plans/oid4vp.json` (alias `puridentityserver-oid4vp`,
clé `credential.signing_jwk`, ancre `client.request_object_trust_anchor_pem`),
`certification/oid4vp-pki.json` (PKI statique du verifier), activation dans
`certification/config.render.toml`. Le driver est patché par
`certification/conformance-oid4vp-initiator.patch` : à l'état `WAITING`, le
hook `certification/local/oid4vp_initiator.py` crée la demande côté OP puis
livre le `request_uri` sur l'`/authorize` émulé de la suite. Voir
`certification/README.md` (section « Plan `oid4vp` »).
