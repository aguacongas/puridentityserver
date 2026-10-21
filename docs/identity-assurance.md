# Identité assurance (OpenID for Identity Assurance)

PurIdentityServer implémente le claim **`verified_claims`** de la spec
**« OpenID Identity Assurance Schema Definition 1.0 incorporating errata set 1 »**
(version finale, 1er juillet 2026), avec le schéma de requête et les claims
d'enregistrement de l_identity assurance.

La spec permet à un RP de recevoir, **sur demande**, les claims d'un
utilisateur **vérifiés** (par opposition aux claims ordinaires, qui ne portent
aucune métadonnée de niveau de vérification) : le membre `verified_claims`
contient à la fois les claims vérifiés et les métadonnées du processus de
vérification (`trust_framework`, `assurance_level`, `evidence`…).

> **La feature est data-driven, sans drapeau.** Les claims vérifiés sont un
> membre du profil utilisateur (`users_seed`) ; sans profil vérifié, l'OP
> n'expose aucune capacité eKYC (metadata absente du discovery) et ne rend
> jamais le membre. Aucun réglage n'est à activer.

## Ce que rend l'OP

| Élément | Origine |
| --- | --- |
| Membre `verified_claims` de l'`id_token` | demandé via le member `id_token` du paramètre `claims` |
| Membre `verified_claims` du corps du `/userinfo` | demandé via le member `userinfo` du paramètre `claims` |
| `trust_frameworks_supported`, `claims_in_verified_claims_supported`, `evidence_supported`, `documents_supported`, `documents_check_methods_supported` (discovery) | dérivés des profils vérifiés connus |

La **localisation demandée fait foi** : un membre demandé dans `id_token` n'apparaît
pas dans le `/userinfo`, et réciproquement. Le profil **brut** n'est jamais
servi : seule la version **résolue** (filtrée par la demande) est rendue.

## Modèle

```json
{
  "verified_claims": {
    "verification": {
      "trust_framework": "de_aml",
      "assurance_level": "substantial",
      "verification_process": "513645-e44b-4951-942c-7091cf7d891d",
      "time": "2012-04-23T18:25Z",
      "evidence": [
        {
          "type": "document",
          "check_details": [{ "check_method": "pvp", "time": "2012-04-22T11:30Z" }],
          "document_details": { "type": "de_erp_replacement_idcard" }
        }
      ]
    },
    "claims": {
      "given_name": "Max",
      "family_name": "Meier",
      "birthdate": "1956-01-28"
    }
  }
}
```

- `verification` et `claims` sont **obligatoires** ; `claims` peut être **vide**
  (spec §5.3) ;
- `verification.trust_framework` est **obligatoire** et doit être une chaîne
  non vide ;
- `evidence` est une liste d'objets typés (`document`, `electronic_record`,
  `vouch`, `electronic_signature`).

Le profil stocké est **validé strictement** (structure, `trust_framework`,
`assurance_level`, types d'evidence) : un profil non conforme est rejeté, pas
servi tel quel.

## Règles de résolution

| Demande | Réponse |
| --- | --- |
| claim demandé, présent au profil | le claim est rendu |
| claim demandé, **inconnu** de l'OP | **omis**, sans erreur |
| claim demandé avec une `value` **non satisfaite** | **omis** ; le membre reste présent avec un élément `claims` éventuellement vide (IA-5.7.4) |
| claim demandé `essential: false` | peut être omis, sans erreur |
| `trust_framework` demandé et non satisfait | le membre `verified_claims` est **entièrement omis** (le RP ne peut pas traiter un framework qu'il ne comprend pas) |
| aucun profil vérifié | le membre est omis |

> L'omission silencieuse est le comportement retenu (la spec OIDC Core 1.0
> prévoit `claims_requested_unfulfilled` pour un claim *essentiel* non
> satisfait, mais la suite de certification n'exige pas ce code et la
> compliance eKYC impose l'omission du membre plutôt qu'une erreur).

## Parcours du RP

```text
RP  ──▶  GET /authorize?...&claims={"id_token":{"verified_claims":{"claims":{"given_name":null}}}}
OP  ──▶  302 https://rp.example/cb?code=…
RP  ──▶  POST /token  (grant_type=authorization_code)
OP  ──▶  id_token : { …, "verified_claims": { "verification": {…}, "claims": {…} } }
```

La même demande dans le member `userinfo` rend le membre dans le corps du
`/userinfo` (et **pas** dans l'`id_token`).

La requête eKYC est mémorisée avec l'access token : le `/userinfo` la rejoue
pour appliquer les contraintes de valeur à l'endroit où le membre est rendu.

## Seed

```toml
[settings.users_seed.alice.verified_claims.verification]
trust_framework = "de_aml"
assurance_level = "substantial"

[[settings.users_seed.alice.verified_claims.verification.evidence]]
type = "document"

[[settings.users_seed.alice.verified_claims.verification.evidence.check_details]]
check_method = "pvp"

[settings.users_seed.alice.verified_claims.verification.evidence.document_details]
type = "de_erp_replacement_idcard"

[settings.users_seed.alice.verified_claims.claims]
given_name = "Alice"
family_name = "Martin"
```

Le profil est stocké dans la colonne JSON `users.claims` (SQL) ou en mémoire ;
il est exportable par le store utilisateur.

## Certification

Le plan **`ekyc-test-plan-oidccore`** (12 modules, **hors programme officiel**
de certification — à confirmer auprès de l'OIDF) est rejoué par le harnais
local :

```bash
bash certification/local/run-plan.sh ekyc
```

La configuration de certification (`certification/config.render.toml`) sème un
profil `verified_claims` conforme, sans quoi l'OP ne publierait pas la
metadata eKYC et la suite échouerait sur `claims_in_verified_claims_supported`.

## Exemple

Le sample `samples/identity-assurance-client/` joue le parcours complet
(metadata, `id_token`, `/userinfo`, omissions) :

```bash
uv run python samples/identity-assurance-client/smoke_test.py
```
