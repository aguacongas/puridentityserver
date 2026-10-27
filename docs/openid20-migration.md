# Migration OpenID 2.0 vers OpenID Connect

PurIdentityServer implémente la spec **« OpenID 2.0 to OpenID Connect
Migration 1.0 »** (OpenID Foundation, version finale du 16 avril 2015).

La spec permet à un RP OpenID 2.0 de **relier l'identifiant historique**
(`openid2_id`) d'un utilisateur à son identifiant OpenID Connect (`sub`), afin
de continuer à servir les comptes d'un parc OpenID 2.0 existant.

> **Le support est désactivé par défaut.** Il s'active avec le réglage
> `PURIDENTITYSERVER_OPENID20_MIGRATION_ENABLED=true` (ou
> `openid20_migration_enabled = true` dans la table `[settings]` du fichier de
> configuration). Sans lui, aucun chemin n'est actif : le scope `openid2` est
> refusé en `invalid_scope`, les routes OpenID 2.0 répondent `404` et le claim
> `openid2_id` n'est jamais émis.

## Ce que fait l'OP

| Exigence de la spec |_implémentation PurIdentityServer |
| --- | --- |
| §2 — scope `openid2` | `/authorize` (et `/par`) accepte le scope `openid2` quand le support est actif ; le client doit le déclarer dans ses scopes. |
| §2 — paramètre `openid2_realm` | Porté par la demande, mémorisé avec le code d'autorisation et utilisé pour retrouver l'identifiant associé. |
| §3 — vérification du RP | Le `openid2_realm` doit être un préfixe d'au moins une URI de redirection enregistrée du client (OpenID 2.0 §9.2) ; sinon la demande est refusée en `invalid_request`. |
| §4 — claim `openid2_id` | L'`id_token` porte `openid2_id` (chaîne JSON) **si et seulement si** le scope `openid2` a été accordé **et** qu'un identifiant OpenID 2.0 est associé au compte. |
| §6 — autorité de l'OP | L'identifiant servi est une URL de l'OP (`{base_url}/openid20/id/{id}`) qui répond `{"iss": "..."}` — la valeur `iss` est identique à celle de l'`id_token`. |
| §2/§4 — rôle OpenID 2.0 de l'OP | `checkid_setup` (ouverture du flux), `/openid20/continue` (fragment de réponse 2.0) et `check_authentication` (assertion OpenID 2.0). |

Les associations **compte ↔ identifiant OpenID 2.0** sont conservées dans un
store dédié (`openid20_identifiers`, mémoire ou SQL selon
`STORAGE_TYPE`) et administrables via l'API d'administration :

- `GET /openid20-identifiers` : export de consultation des associations ;
- `POST /openid20-identifiers` : liaison d'un identifiant à un compte
  (`{"subject": "...", "identifier": "...", "realm": "..."}`).

## Parcours du RP

### 1. Authentification OpenID 2.0 auprès de l'OP

Pour un parc qui conserve son OP OpenID 2.0 historique **dans** PurIdentityServer,
le RP suit le flux OpenID 2.0 classique :

```text
RP  ──▶  GET /openid20/checkid_setup?openid.ns=…&openid.mode=id_2
                                    &openid.realm=…&openid.return_to=…
OP  ──▶  302 /login?next=/openid20/continue?state=…      (connexion de l'utilisateur)
OP  ──▶  302 https://rp.example/cb#openid.ns=…&openid.mode=id_2
            &openid.claimed_id=https://op.example/openid20/id/…
            &openid.identity=…&openid.assoc_handle=…
RP  ──▶  GET /openid20/check_authentication?checkid_handle=…
OP  ──▶  claimed_id:https://op.example/openid20/id/…
            identity:…&expired:false
```

L'état du flux et le `assoc_handle` sont des jetons **signés** par l'OP : ils
ne sont ni falsifiables ni expirables par le tiers (10 minutes de validité).
Le `checkid_handle` reçu n'est pas renvoyé dans l'assertion (c'est une donnée
fournie par l'appelant : la refléter ouvrirait une faille d'injection) ; le
RP connaît déjà le handle qu'il a transmis.

### 2. Demande de l'identifiant OpenID 2.0 en OpenID Connect

```text
RP  ──▶  GET /authorize?response_type=code&scope=openid%20openid2
            &openid2_realm=https://rp.example&…
OP  ──▶  302 https://rp.example/cb?code=…
RP  ──▶  POST /token  (grant_type=authorization_code)
OP  ──▶  id_token : { …, "openid2_id": "https://op.example/openid20/id/…" }
```

Le claim `openid2_id` est **absent** si aucun identifiant n'est associé au
compte : c'est le comportement normal tant que la liaison n'a pas été faite.

### 3. Vérification de l'autorité (obligatoire pour le RP)

```text
RP  ──▶  GET https://op.example/openid20/id/…   (Accept: application/json)
OP  ──▶  { "iss": "https://op.example" }
```

Le RP compare la valeur `iss` reçue à celle de l'`id_token` : elles doivent
être **exactement** identiques, sinon l'identifiant OpenID 2.0 est rejeté
(spec §6, §10).

### 4. Liaison des comptes (côté RP)

Une fois l'identité corrélée, le RP **associe** le compte OpenID 2.0 à son
compte OpenID Connect (spec §7). Cette liaison est locale au RP : côté OP,
l'association est matérialisée par la ligne `openid20_identifiers` (posée par
l'API d'administration ou par le flux `checkid_setup` ci-dessus).

## Modèle de données

| Colonne | Rôle |
| --- | --- |
| `subject` | Le `sub` interne du compte OpenID Connect (l'identifiant de la migration). |
| `realm` | Le `openid.realm` (spec §2) : vide si le parc n'en utilise pas. |
| `identifier` | L'identifiant OpenID 2.0 (`openid2_id`) servi dans l'`id_token`. |
| `created_at` | Date de la liaison. |

La recherche d'un identifiant pour un compte est **exacte** sur le couple
`(subject, realm)` : un `openid2_realm` absent ne retrouve donc pas une
association faite pour un realm donné (et réciproquement).

## Exemple complet

Le sample `samples/openid20-migration-client/` joue le parcours intégral
(`checkid_setup` → connexion → `check_authentication` → `/authorize` avec
`scope=openid openid2` → claim `openid2_id` → vérification d'autorité →
export d'administration) :

```bash
uv run python samples/openid20-migration-client/smoke_test.py
```

## Limites connues

- La spec est une **spec de niche** (parc OpenID 2.0 marginal) : le support
  reste **désactivé par défaut** et n'est pas couvert par les plans de
  certification OIDF (en configuration standard). Le chemin flag ON est toutefois
  **couvert manuellement** avant toute release concernée : cf.
  `certification/README.md` (« Rejeu avec OpenID 2.0 migration active »,
  run local `certification-local` avec `openid20_migration_enabled = true`,
  11 plans stricts verts, 475 modules, 0 hors ALLOWED).
- L'OP ne joue le rôle d'OP OpenID 2.0 que pour **son propre** parc : la
  signature OpenID 2.0 classique (`openid.signed`) n'est pas produite ; la
  preuve d'autorité repose sur la signature RS256 des jetons internes et sur
  l'endpoint `/openid20/id/{id}` (spec §6).
- Le claim `openid2_id` n'est pas repris par `/userinfo` : la spec le place
  dans l'`id_token`.
