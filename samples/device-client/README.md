# Test manuel : Device Authorization Grant (RFC 8628)

Script de démonstration/test manuel du **Device Authorization Grant**
(RFC 8628) : le flow OAuth 2.0 conçu pour des appareils à entrées
limitées (TV, CLI, bornes…).

## Principes

1. le client demande un `device_code` + `user_code` au endpoint
   `/device_authorization` ;
2. l'utilisateur ouvre la `verification_uri` dans un navigateur, saisit
   le `user_code`, se connecte et autorise l'appareil sur la page
   `/device` ;
3. le client boucle en poll sur `/token` (grant
   `urn:ietf:params:oauth:grant-type:device_code`) jusqu'à obtenir
   les jetons (ou un refus/expiry) ;
4. le serveur retourne un `access_token` (+ `id_token` si le scope
   `openid` est accordé) — pas de `refresh_token` pour ce flow par
   défaut (ajoutez `offline_access` au scope du client si nécessaire).

## Prérequis

- Serveur PurIdentityServer lancé sur `http://127.0.0.1:8000` avec le
  client `sample-device-client` enregistré (présent dans `config.toml`
  racine par défaut) ;
- **alice@example.com / password** créé dans `identity_seed_users`.

```sh
python -m puridentityserver
```

## Exécution du client

```sh
cd samples/device-client
python client.py
```

Le client affichera le code à saisir et la page de vérification à ouvrir.
Après validation dans le navigateur, les jetons s'affichent dans le
terminal.

> Pour tests, les défauts sont : `DEVICE_ISSUER=http://127.0.0.1:8000`,
> `DEVICE_CLIENT_ID=sample-device-client`.

## Smoke test

Le smoke test enchaîne le flow complet de façon automatique (port dédié
8103, aucun impact sur le serveur courant) :

```sh
cd samples/device-client
python smoke_test.py
```

Cinq étapes sont vérifiées : discovery, device_authorization, login,
approval, tokens.
