# Test manuel : FAPI2 Security Profile (issue #111)

Script de démonstration du profil **FAPI 2.0 Security Profile** de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8108`, issuer `https://id.example`, clients seedés `fapi2-app` et
`fapi2-app-2` à clés statiques, `token_endpoint_auth_method =
private_key_jwt` et `fapi2_enabled = true`, identité `alice@example.com`)
puis joue le scénario complet en 8 étapes.

Le scénario vérifie :

1. le discovery déclare `require_pushed_authorization_requests`,
   `authorization_response_iss_parameter_supported` (RFC 9207), le défi
   PKCE `S256` (seul accepté pour les clients FAPI2) et `PS256` pour les
   assertions client ;
2. `POST /par` en **params plats** (profil FAPI2 `unsigned` : pas de
   request object signé) avec `code_challenge` `S256`, `dpop_jkt` et
   `client_assertion` `private_key_jwt` → `201` `request_uri` opaque ;
3. un push sans PKCE → `400 invalid_request`
   (FAPI2-SP-5.3.2.2-5 : PKCE obligatoire) ;
4. `/authorize?request_uri=…` → login + consentement → callback en
   **query** portant `code`, `state` et `iss` (RFC 9207) ;
5. `/token` avec un `code_verifier` erroné → `400 invalid_grant`
   (le code d'autorisation reste intact) ;
6. `/token` **sans preuve DPoP** → `400 invalid_dpop_proof` ; avec la
   bonne preuve fraîche → `200` : `token_type=DPoP`, claim `cnf.jkt`
   (RFC 9449 §6.1), id_token `PS256` et `refresh_token` ;
7. `/protected-resource` sans preuve → `401` ; avec preuve portant
   `ath` → `200` ;
8. réutilisation de la `request_uri` après consommation → erreur
   `invalid_request_uri`, jamais de code (RFC 9126 §2.2.2).

## Lancement

```bash
uv run python samples/fapi2-client/smoke_test.py
```

Sortie attendue (8 × `OK`, 6 à 10 s) :

```text
étape 1/8  discovery FAPI2 (PAR requis, iss RFC 9207, S256)  OK
…
étape 8/8  request_uri réutilisée -> invalid_request_uri     OK
=== PARCOURS FAPI2 OK en 6.5s ===
```

## Rejeu de la suite de certification complète

Le même parcours, décliné en 107 tests (114 exécutions de modules des
plans Final + ID2), se rejoue avec le plan
`tests/conformance/test_plan_fapi2.py` :

```bash
uv run python -m pytest tests/conformance/test_plan_fapi2.py \
  -m conformance --no-cov -p no:cacheprovider
```

## À quoi sert FAPI 2.0 Security Profile ?

FAPI 2.0 (mars 2024) unifie les profils Advanced Final et ID2 : la
demande d'autorisation est **toujours poussée** (PAR obligatoire, RFC
9126), PKCE `S256` obligatoire, `response_type=code` seul, assertion
`private_key_jwt` (`PS256`) au PAR et au token, et le client est
**contraint par une preuve DPoP** (RFC 9449) : l'access token porte
`cnf.jkt` et tout appel au resource server exige une preuve signée par
la même clé. Contrairement à FAPI1, il n'y a **pas de request object
signé** : les paramètres sont plats au `/par` (request object implicite).
Le mode se configure **par client** (`fapi2_enabled = true` dans
`config.toml`, exclusif de `fapi_enabled`).
