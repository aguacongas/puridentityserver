# Test manuel : flux pre-autorise OpenID4VCI (offre de credential)

Ce sample exerce le parcours **issuer-initiated** complet de
PurIdentityServer, sans interaction navigateur :

1. jeton machine (`client_credentials`, scope `openid4vci`) ;
2. `POST /credential-offer` : creation d une offre de credential ;
3. `GET <credential_offer_uri>` : dereferencement de l offre par le wallet ;
4. `POST /token` avec `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code`
   (et `tx_code` quand l offre en exige un) ;
5. `POST /credential` avec une preuve de possession ES256.

## Configuration

Activer le support OID4VCI et declarer un client machine, dans `config.toml` :

```toml
[server]
oid4vci_enabled = true
issuer = "http://127.0.0.1:8000"

[[settings.clients_seed]]
client_id = "sample-oid4vci-client"
scopes = "openid4vci"
client_type = "confidential"
client_secret = "oid4vci-demo-secret"
```

Le scope `openid4vci` est necessaire pour creer une offre ; le client est
confidentiel pour s authentifier au token endpoint.

## Lancement

```bash
uv run python -m puridentityserver.cli --port 8000
BASE_URL=http://127.0.0.1:8000 uv run python samples/oid4vci-preauth-client/smoke_test.py
```

Variables optionnelles : `CLIENT_ID`, `CLIENT_SECRET`, `SUBJECT`
(titulaire du credential, `alice@example.com` par defaut) et `USE_TX_CODE`
(`true` par defaut ; `false` pour une offre sans code de transaction).

## Resultat attendu

```
1. jeton client obtenu
2. offre creee : http://127.0.0.1:8000/credential-offer/<id>
3. offre dereferencee (tx_code annonce : True)
4. code pre-autorise echange contre un access token
5. credential emis : typ=dc+sd-jwt cnf=sample-oid4vci-key
```

Points a verifier :

- `credential_offer.grants` contient
  `urn:ietf:params:oauth:grant-type:pre-authorized_code` avec
  `pre-authorized_code`, `authorization_server` et, si demande, un objet
  `tx_code` (`input_mode=numeric`, `length=6`) ;
- la reponse de creation porte `tx_code` **une seule fois** (canal separe,
  OID4VCI 1.0 §4.1.1) ; elle est absente des creations suivantes sans
  `tx_code` ;
- apres l echange, `GET <credential_offer_uri>` repond `404` : le code est a
  usage unique et l offre ne survit pas a sa consommation ;
- le credential emis est un SD-JWT (`typ=dc+sd-jwt`).

## Erreurs attendues

- offre creee sans `subject` par un jeton machine : `400 invalid_request` ;
- jeton sans scope `openid4vci` : `403 insufficient_scope` ;
- `tx_code` errone a l echange : `400 invalid_grant` ;
- code deja utilise : `400 invalid_grant`.

## DoD

- README pas-a-pas, configuration, resultat attendu.
- Le sample exerce les endpoints de la tranche : `/credential-offer`
  (creation + reference) et le grant pre-autorise au token endpoint.
