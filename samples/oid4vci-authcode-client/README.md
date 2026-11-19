# OID4VCI — flux interactif (authorization code)

Smoke test du parcours interactif OpenID4VCI : un wallet (ici un script
Python) demande une autorisation via `authorization_details` (RFC 9396,
type `openid_credential`), l'utilisateur consent dans son navigateur, puis
le script recupere le code, l'echange contre un access token portant le
claim `authorization_details` et emet un credential.

Deux modes d'authentification client sont proposes :

- **defaut** : un client public enregistre au prealable, l'echange du code
  se fait sans credential client ;
- **attestation** (`CLIENT_AUTH=attest_jwt_client_auth`, issue #304) : le
  client est cree dynamiquement (DCR) avec la methode
  `attest_jwt_client_auth`
  (draft-ietf-oauth-attestation-based-client-auth), la demande est poussee
  via `POST /par` et l'echange `POST /token` porte les en-tetes
  `OAuth-Client-Attestation` / `OAuth-Client-Attestation-PoP`.

## Lancement (mode defaut)

1. Demarrer l'OP avec OID4VCI active :

   ```bash
   PURIDENTITYSERVER_OID4VCI_ENABLED=true uv run python -m puridentityprotocol
   ```

2. Enregistrer un client **public** (redirect_uri
   `http://127.0.0.1:8765/callback`, methode `none` — le script n'envoie
   aucun credential a `/token`) :

   ```bash
   curl -s -X POST http://127.0.0.1:8000/register \
     -H "Authorization: Bearer dev-registrar-token" \
     -H "Content-Type: application/json" \
     -d '{"redirect_uris": ["http://127.0.0.1:8765/callback"],
          "scope": "openid profile email",
          "token_endpoint_auth_method": "none"}'
   # -> 201 { "client_id": ... }
   ```

3. Lancer le smoke test :

   ```bash
   BASE_URL=http://127.0.0.1:8000 CLIENT_ID=<id> python samples/oid4vci-authcode-client/smoke_test.py
   ```

4. Ouvrir l'URL affichee, se connecter (alice / alice) et autoriser.

### Resultat attendu

Le script affiche l'access token recu (avec `authorization_details`) puis le
credential SD-JWT emis via `credential_identifier`.

## Mode attestation (`attest_jwt_client_auth`)

L'OP ne publie la methode `attest_jwt_client_auth` (ni les listes
`client_attestation_*_signing_alg_values_supported`) qu'avec un attester de
confiance configure ; `POST /register` refuse la methode sans lui
(`400 invalid_client_metadata`).

1. Demarrer l'OP avec OID4VCI **et** l'attester de confiance — la cle
   publique ci-dessous est la contrepartie de la cle privee de
   demonstration embarquee dans le script (a jeter, demonstration
   uniquement) :

   ```bash
   PURIDENTITYSERVER_OID4VCI_ENABLED=true \
   PURIDENTITYSERVER_CLIENT_ATTESTATION_ISSUER=https://client-attester.example.org/ \
   PURIDENTITYSERVER_CLIENT_ATTESTATION_JWKS='{"keys": [{"kty": "EC", "crv": "P-256", "x": "U9phd41jZYFA4ALsafsvDHza8H9IYks0AGFxJy9WHDc", "y": "867k9avVc_0uoawIY8PTpOBnBA-VcdFPcdjajF6VG5c", "kid": "ct-attester-demo", "alg": "ES256", "use": "sig"}]}' \
   uv run python -m puridentityprotocol
   ```

   L'`iss` de l'attestation est comparee en egalite stricte : la valeur de
   `ATTESTER_ISSUER` (script) doit correspondre exactement au settings OP,
   barre finale comprise.

2. Lancer le smoke test en mode attestation :

   ```bash
   BASE_URL=http://127.0.0.1:8000 CLIENT_AUTH=attest_jwt_client_auth \
     python samples/oid4vci-authcode-client/smoke_test.py
   ```

3. Ouvrir l'URL affichee, se connecter (alice / alice) et autoriser.

### Resultat attendu

```text
client enregistre (DCR, attest_jwt_client_auth) : <client_id>
demande poussee (PAR) : urn:ietf:params:oauth:request_uri:...
code recu
access token recu ; authorization_details present : True
credential emis : eyJ...
```

Le script passe par `POST /register` (client confidentiel sans secret),
`POST /par` puis `POST /token` : chaque requete porte un PoP neuf (`jti`
unique — l'anti-replay du draft refuse toute reutilisation), l'attestation
etant signee par l'attester de confiance et liant le client par son
`cnf.jwk`.

### Variables d'environnement (mode attestation)

| Variable            | Defaut                              | Role                                        |
| ------------------- | ----------------------------------- | ------------------------------------------- |
| `CLIENT_AUTH`       | (vide)                              | `attest_jwt_client_auth` active le mode     |
| `ATTESTER_ISSUER`   | `https://client-attester.example.org/` | `iss` attendu de l'attestation (egal au settings OP) |
| `REGISTRATION_TOKEN`| `dev-registrar-token`               | initial access token de `POST /register`    |
| `BASE_URL`          | `http://127.0.0.1:8000`             | issuer de l'OP, aussi `aud` du PoP          |

## Mode chiffrement (`ENCRYPTION=1`)

Exercice du chiffrement des credential requests / responses (OID4VCI 1.0
§8.2, issue #304). Combinable avec l'un ou l'autre mode d'authentification.

1. Demarrer l'OP avec les deux flags :

   ```bash
   PURIDENTITYSERVER_OID4VCI_ENABLED=true \
   PURIDENTITYSERVER_OID4VCI_ENCRYPTION_ENABLED=true \
   uv run python -m puridentityprotocol.server
   ```

2. Lancer le smoke test avec `ENCRYPTION=1` (et `CLIENT_AUTH` si desired) :

   ```bash
   ENCRYPTION=1 uv run python smoke_test.py
   ```

3. Ouvrir l'URL affichee, se connecter (alice / alice) et autoriser.

### Resultat attendu

```text
capability de chiffrement annoncee (enc_values : ['A256GCM', ...])
reponse chiffree (alg ECDH-ES, enc A256GCM, kid sample-oid4vci-encryption)
credential emis : eyJ...
```

Le script lit les blocs `credential_request_encryption` /
`credential_response_encryption` publies dans les metadonnees d'emetteur,
genere sa propre paire EC P-256, demande le chiffrement de la reponse
(`credential_response_encryption` avec `enc = A256GCM`), puis dechiffre le
JWE renvoye en `application/jwt` avec `decrypt_compact_ecdh_es`.
