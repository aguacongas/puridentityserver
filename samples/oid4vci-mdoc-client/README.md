# OID4VCI — émission mdoc (format `mso_mdoc`, ISO 18013-5)

Smoke test bout-en-bout de l'émission d'un credential **mdoc** (ISO/IEC
18013-5) via le même flux pre-autorisé que le SD-JWT VC. Le wallet (ici un
script Python) demande la configuration `puridentityserver-mso-mdoc`, prouve
la possession d'une clé EC P-256 (device key), et reçoit un ``IssuerSigned``
CBOR signé en COSE Sign1 avec la chaîne ``x5chain`` du document signer.

C'est le pendant mdoc du sample `oid4vci-preauth-client` (SD-JWT VC).

## Lancement

1. Démarrer l'OP avec OID4VCI active :

   ```bash
   PURIDENTITYSERVER_OID4VCI_ENABLED=true uv run python -m puridentityprotocol
   ```

2. Enregistrer un client (si ce n'est pas déjà fait) :

   ```bash
   uv run python samples/registration-client/smoke_test.py
   ```

3. Lancer le smoke test :

   ```bash
   BASE_URL=http://127.0.0.1:8000 CLIENT_ID=<id> CLIENT_SECRET=<secret> \
     uv run python samples/oid4vci-mdoc-client/smoke_test.py
   ```

## Résultat attendu

Le script affiche, à l'étape 5 :

- `issuerAuth tag=18` (COSE Sign1 CBOR-tagué),
- les éléments émis (ex. `['family_name', 'given_name']`),
- `signature COSE structurellement valide : True`,
- la clé device liée (`EC/P-256`).

## Ce qui est vérifié

- La configuration `puridentityserver-mso-mdoc` est publiée dans les
  métadonnées de l'émetteur (`/.well-known/openid-credential-issuer`).
- La réponse `/credential` contient un CBOR base64url sans padding.
- L'``issuerAuth`` est un COSE Sign1 (tag 18) dont la signature est vérifiable.
- La clé device du wallet (proof EC P-256) est embarquée dans la MSO
  (``deviceKeyInfo``).

## Limites (tranche 1)

- La PKI mdoc (IACA + document signer) est générée à la volée, en mémoire :
  elle n'est pas persistée et la chaîne de confiance n'est pas encore servie
  pour qu'un verifier externe la valide (tranche suivante).
- Seule la courbe P-256 est supportée pour la clé device (exigence
  ISO 18013-5 courante).
