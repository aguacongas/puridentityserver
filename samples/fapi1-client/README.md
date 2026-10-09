# Test manuel : FAPI1 Advanced Final (issue #110)

Script de démonstration du profil **FAPI 1.0 Advanced Final** de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8107`, issuer `https://id.example`, clients seedés `fapi-app` et
`fapi-app-2` à clés statiques PS256 et
`token_endpoint_auth_method = private_key_jwt`, identité
`alice@example.com`) puis joue le scénario complet en 8 étapes.

Le scénario vérifie :

1. le discovery déclare `PS256`/`ES256` pour les request objects,
   `request_parameter_supported`, l'endpoint `/par` et le défi PKCE
   `S256` ;
2. `POST /par` (JAR signé `PS256` + `client_assertion` `private_key_jwt`
   + défi PKCE `S256`) → `201` `request_uri` opaque
   (`urn:ietf:params:oauth:request_uri:<…>`) ;
3. `response_mode=query` sur `code id_token` → `400 invalid_request`
   au `/par` (OIDC Core 1.0 §3.1.2.1 : jamais de `code` en query) ;
4. `/authorize?request_uri=…` → login + consentement → callback en
   **fragment** : `code`, `state`, `id_token` `PS256` avec `nonce` et
   `s_hash` ;
5. `/token` avec un `code_verifier` erroné → `400 invalid_grant`
   (le code d'autorisation reste intact) ;
6. `/token` avec la bonne assertion `private_key_jwt` et le bon
   `code_verifier` → `200` : access_token, `id_token` `PS256` (`kid`,
   `nonce`) et refresh_token ;
7. `/protected-resource` (Bearer + `x-fapi-interaction-id`) → `200` ;
8. réutilisation de la `request_uri` après consommation → erreur
   `invalid_request_uri`, jamais de code (PAR-2.2.2).

## Lancement

```bash
uv run python samples/fapi1-client/smoke_test.py
```

Sortie attendue (8 × `OK`, 6 à 10 s) :

```text
étape 1/8  discovery FAPI1 (JAR PS256, https://id.example/par, S256)   OK
…
étape 8/8  request_uri réutilisée -> invalid_request_uri     OK
=== PARCOURS FAPI1 OK en 6.3s ===
```

## Rejeu de la suite de certification complète

Le même parcours, décliné en 106 exécutions (44 by-value + 62 pushed),
se rejoue avec le plan `tests/conformance/test_plan_fapi1.py` :

```bash
uv run python -m pytest tests/conformance/test_plan_fapi1.py \
  -m conformance --no-cov -p no:cacheprovider
```

## À quoi sert FAPI 1.0 Advanced Final ?

FAPI (Financial-grade API) renforce OIDC pour les banques et assurances :
request object signé obligatoire (JAR), PKCE `S256`, PAR obligatoire,
assertions `private_key_jwt` au token endpoint, tokens signés `PS256`/`ES256`
et réponse d'autorisation en fragment (jamais de `code` en query). Le profil
« Advanced Final » ajoute les exigences métier : `s_hash`, liaison du code
d'autorisation au client, vie courte des codes et interdiction de réutiliser
une `request_uri`. Le mode FAPI se configure **par client**
(`fapi_enabled = true` dans `config.toml`, ou champs `fapi_*` à
l'enregistrement dynamique).
