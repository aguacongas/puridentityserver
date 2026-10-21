# Test manuel : migration OpenID 2.0 vers OpenID Connect (spec finale)

Script de démonstration de la spec **« OpenID 2.0 to OpenID Connect
Migration 1.0 »** (OIDF, version finale) dans PurIdentityServer. Il lance un
serveur en sous-processus avec une configuration **spécifique à ce test**
(générée par `smoke_common.py` : port `8124`, un client demandant le scope
`openid2`, la **migration activée**) puis joue le parcours complet.

Le scénario vérifie :

1. `checkid_setup` : le RP ouvre une authentification OpenID 2.0, l'agent
   utilisateur est redirigé vers la page de connexion de l'OP ;
2. connexion puis `/openid20/continue` : le RP reçoit le fragment de réponse
   OpenID 2.0 (`openid.assoc_handle`, `openid.claimed_id`) ;
3. `check_authentication` : le RP obtient l'assertion OpenID 2.0 de
   l'utilisateur (`claimed_id`) ;
4. flux OpenID Connect avec `scope=openid openid2` et `openid2_realm` :
   l'`id_token` porte le claim `openid2_id` (spec §4) ;
5. vérification d'autorité (spec §6) : un `GET` sur l'identifiant OpenID 2.0
   avec `Accept: application/json` renvoie le même `iss` que l'`id_token` ;
6. export des associations : l'API d'administration liste l'identifiant migré
   du compte.

## Lancement

```bash
uv run python samples/openid20-migration-client/smoke_test.py
```

## Résultat attendu

Sortie pas-à-pas se terminant par :

```text
  [1/6] checkid_setup : l'agent utilisateur est redirigé vers /login
  [2/6] fragment OpenID 2.0 reçu (claimed_id=http://127.0.0.1:8124/openid20/id/...)
  [3/6] check_authentication : l'assertion OpenID 2.0 est valide
  [4/6] id_token : le claim openid2_id porte l'identifiant 2.0
  [5/6] autorité vérifiée (spec §6) : iss identique à l'id_token
  [6/6] export d'administration : l'identifiant migré est listé

=== SCENARIO OK en X.Xs ===
```

## Comment ça marche ?

La spec permet à un RP OpenID 2.0 de relier l'identifiant historique d'un
utilisateur à son `sub` OpenID Connect. Côté OP :

- **le scope `openid2`** (spec §2) demande l'identifiant OpenID 2.0 de
  l'utilisateur ; le claim `openid2_id` de l'`id_token` le porte quand un
  identifiant est associé au compte (spec §4) ;
- **le paramètre `openid2_realm`** (spec §2) désigne le `openid.realm` : il
  est vérifié contre les URI de redirection enregistrées du client (spec §3,
  OpenID 2.0 §9.2) ;
- **le rôle OpenID 2.0 de l'OP** (`checkid_setup` / `check_authentication`)
  permet à un parc OpenID 2.0 existant de s'authentifier *auprès de
  l'OP* : l'OP délivre un `claimed_id` qu'elle héberge ;
- **la preuve d'autorité** (spec §6) : l'identifiant servi est une URL de
  l'OP qui répond `{"iss": "..."}` — le RP vérifie ainsi que l'OP est bien
  l'autorité de cet identifiant ;
- **l'export** : `GET /openid20-identifiers` (API d'administration) liste les
  associations compte ↔ identifiant OpenID 2.0.

## Prérequis

- **Le support est désactivé par défaut** : le sample l'active via le
  réglage `openid20_migration_enabled = true` (variable d'environnement
  `PURIDENTITYSERVER_OPENID20_MIGRATION_ENABLED`). Sans lui, le scope
  `openid2` est refusé comme inconnu, aucune route OpenID 2.0 n'est
  exposée et le claim `openid2_id` n'est jamais émis.
- Les réglages sont documentés dans `docs/configuration.md` et le parcours
  RP est détaillé dans `docs/openid20-migration.md`.
