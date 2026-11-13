# OID4VP — verifier 1.0 (initiation + direct_post.jwt)

Ce sample exerce la capacité **verifier** OpenID4VP de PurIdentityServer
(issue #224) de bout en bout : création d'une demande de présentation signée,
service du `request_uri` (GET et variante `request_uri_method=post` avec
`wallet_nonce`), réception d'une présentation chiffrée `direct_post.jwt`
(JWE `ECDH-ES`/`A128GCM`) et affichage de la page de résultat.

Le scénario est joué par un **wallet simulé** intégré au script : il émet un
credential SD-JWT VC (`vct = urn:eudi:pid:1`, disclosure, `cnf.jwk`), lie un
key binding JWT au `nonce` de la demande, puis chiffle le `vp_token` vers la
clé éphémère annoncée dans le `client_metadata` du request object. La crypto
passe exclusivement par `PyJWT` / `cryptography` et les primitives du projet
(`src/puridentityserver/infrastructure/jwe.py`).

## Prérequis

- Python 3.13 + `uv` (dépendances du dépôt : `uv sync --extra dev`).
- Aucun service externe : le sample lance **son propre OP** sur le port 8127
  avec une configuration générée à la volée (`samples/smoke_common.py`).

## Lancement

Depuis la racine du dépôt :

```bash
uv run python samples/oid4vp-verifier-client/smoke_test.py
```

## Ce qui est configuré

`smoke_common.run_server` génère un `config.toml` temporaire portant :

```toml
oid4vp_enabled = true
oid4vp_credential_jwks = '{"keys": [{...clé publique EC P-256 du test...}]}'
```

- `oid4vp_enabled` monte les quatre routes `/oid4vp/*` ;
- `oid4vp_credential_jwks` déclare le JWKS public de confiance : le verifier
  **contrôle réellement** la signature du credential SD-JWT (sans ce réglage,
  il escamote ce contrôle en mode witness, comme le fait la suite de
  conformance sur ses modules de rejet de signature).

## Résultat attendu

Six étapes numérotées, puis `=== SCÉNARIO OK ===` :

1. `POST /oid4vp/presentation_requests` -> `201` avec `client_id`
   `x509_hash:` (PKI du verifier), `nonce`, `request_uri` et request object
   signé `typ = oauth-authz-req+jwt` (chaîne `x5c` du verifier) ;
2. `GET /oid4vp/request_uri/{request_id}` -> `200
   application/oauth-authz-req+jwt` portant `aud = https://self-issued.me/v2`,
   `response_mode = direct_post.jwt`, la requête DCQL PID (`dc+sd-jwt`) et le
   `client_metadata` (clé `ECDH-ES` éphémère) ;
3. `POST /oid4vp/request_uri/{request_id}` avec `wallet_nonce` -> request
   object **re-signé** portant le claim (OID4VP 1.0 Final §5.10) ;
4. `POST /oid4vp/vp_response/{request_id}` avec le JWE du wallet -> `200`
   `{"redirect_uri": ".../oid4vp/result/<request_id>"}` ;
5. `GET <redirect_uri>` -> page HTML `<h1>Presentation acceptee</h1>` listant
   les claims du credential présenté (liste `<dl>` échappée) ;
6. contre-épreuve : credential signé par une clé étrangère -> `400`
   `{"error": "invalid_request", "error_description": "signature du
   credential non appariee au JWKS de confiance"}`.

Toute déviation fait échouer le script (code de sortie non nul).

## Variantes

- **Sans contrôle de signature** : retirer `oid4vp_credential_jwks` de la
  config générée -> l'étape 6 échoue (le verifier accepte : mode witness).
- **Rejet de nonce** : le même wallet rejoue les modules négatifs du plan de
  certification (voir `tests/oid4vp_wallet.py`, qui couvre nonce, `aud`,
  `sd_hash`, `iat`, signatures et `vp_token`, et `tests/test_oid4vp_verifier.py`,
  qui couvre le `vct` demandé par la DCQL et la révocation via la status
  list référencée).

## Certification

Le round-trip réel contre la suite OIDF se rejoue via le harness local
(plan `oid4vp`, voir `certification/README.md`) :

```bash
bash certification/local/run-plan.sh oid4vp
```
