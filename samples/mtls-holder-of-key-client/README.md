# Test manuel : mTLS holder-of-key RFC 8705 (issue #127)

Script de démonstration de la **liaison mTLS forcée des jetons**
(`tls_client_certificate_bound_access_tokens`, RFC 8705 §3.1/§3.3) de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8118`, client confidential `sample-hok-client` à clé RSA statique
et `token_endpoint_auth_method = private_key_jwt`) puis joue le scénario
complet en 8 étapes.

Particularités de ce sample :

- le client est enregistré `tls_client_certificate_bound_access_tokens
  = true` : chaque appel au token endpoint (et à la ressource protégée)
  doit présenter un certificat client ;
- les noms d'en-têtes mTLS sont **personnalisés**
  (`client_certificate_header = "X-Proxy-Client-Cert"`) pour montrer
  l'adaptation à n'importe quel proxy de terminaison TLS (Cloudflare
  Transform Rules RFC 9440, nginx, Envoy, HAProxy…) sans toucher au
  code ;
- le PEM est envoyé au format `\n`-échappé, comme un proxy l'envoie
  réellement dans un en-tête HTTP (le serveur normalise).

Le scénario vérifie :

1. le discovery publie `tls_client_certificate_bound_access_tokens` ;
2. `POST /token` (`client_credentials`) **sans** en-tête certificat →
   `400 invalid_client` (« Certificat client mTLS requis ») ;
3. idem **avec** le certificat → `200` : l'access token porte
   `cnf.x5t#S256` (empreinte SHA-256 du DER, RFC 8705 §2.1.2) ;
4. `GET /protected-resource` (Bearer + bon certificat) → `200` ;
5. idem avec un **autre** certificat → `401` (liaison opposée) ;
6. idem **sans** certificat → `401` ;
7. flow `authorization_code` (démo sans login) : `/authorize` émet un
   code, `/token` l'échange avec le certificat → `200` : access token
   lié **et** refresh token lié au certificat d'émission ;
8. `grant_type=refresh_token` : même certificat → `200` (jetons rotés) ;
   autre certificat → `400 invalid_grant` ; sans certificat →
   `400 invalid_client` (RFC 8705 §3.3).

## Lancement

```bash
uv run python samples/mtls-holder-of-key-client/smoke_test.py
```

Sortie attendue (8 × `OK`, 5 à 10 s) :

```text
OP mTLS démarré sur http://127.0.0.1:8118 (en-tête certificat X-Proxy-Client-Cert)
étape 1/8  discovery : tls_client_certificate_bound_access_tokens  OK
…
étape 8/8  refresh : même cert 200, autre 400, aucun 400          OK
=== PARCOURS mTLS HOLDER-OF-KEY OK en 6.1s ===
```

## Configuration côté serveur (proxy de terminaison)

En production, le certificat client n'est pas présenté directement à
uvicorn : un proxy (Cloudflare, nginx, HAProxy…) termine le mTLS et
transmet le PEM dans un en-tête. Les noms d'en-têtes sont réglables
dans `config.toml` (ou variables d'environnement
`PURIDENTITYSERVER_CLIENT_CERTIFICATE_HEADER` /
`PURIDENTITYSERVER_CLIENT_CERTIFICATE_DN_HEADER`) :

```toml
[settings]
client_certificate_header = "X-SSL-Client-Cert"   # PEM du certificat
client_certificate_dn_header = "X-SSL-Client-S-DN" # sujet RFC 4514 (repli)
```

Exemple Cloudflare (Transform Rules RFC 9440) : activer mTLS sur le
hostname, puis poser `cf.tls_client_auth.cert` dans
`client_certificate_header` (gate `cert_verified`). Exemple nginx :

```nginx
proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
```

Quand le serveur reçoit directement la connexion TLS (sans proxy),
le certificat est lu dans le contexte SSL d'uvicorn — les en-têtes ne
sont alors pas consultés.

## À quoi sert la liaison mTLS (RFC 8705) ?

Un access token lié (`cnf.x5t#S256`) n'est utilisable qu'avec le même
certificat client que celui présentés à l'émission : voler le jeton ne
suffit pas, il faut aussi la clé privée du certificat. Le refresh token
est lié au certificat d'émission — un autre certificat reçoit
`invalid_grant`. C'est une exigence des profils bancaires FAPI 1.0
(mTLS profile) et des API Santé (HL7 FHIR / SMART App Launch) : le flag
se règle **par client** (`tls_client_certificate_bound_access_tokens`
dans `config.toml` ou à l'enregistrement dynamique), les autres clients
continuent sans certificat.
