# OID4VCI — flux interactif (authorization code)

Smoke test du parcours interactif OpenID4VCI : un wallet (ici un script
Python) demande une autorisation via `authorization_details` (RFC 9396,
type `openid_credential`), l'utilisateur consent dans son navigateur, puis
le script recupere le code, l'echange contre un access token portant le
claim `authorization_details` et emet un credential.

## Lancement

1. Demarrer l'OP avec OID4VCI active :

   ```bash
   PURIDENTITYSERVER_OID4VCI_ENABLED=true uv run python -m puridentityprotocol
   ```

2. Enregistrer un client public (redirect_uri `http://127.0.0.1:8765/callback`) :

   ```bash
   uv run python samples/registration-client/smoke_test.py   # ou POST /register
   ```

3. Lancer le smoke test :

   ```bash
   BASE_URL=http://127.0.0.1:8000 CLIENT_ID=<id> python samples/oid4vci-authcode-client/smoke_test.py
   ```

4. Ouvrir l'URL affichee, se connecter (alice / alice) et autoriser.

## Resultat attendu

Le script affiche l'access token recu (avec `authorization_details`) puis le
credential SD-JWT emis via `credential_identifier`.