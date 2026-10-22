# Fédération (OpenID Federation 1.1)

PurIdentityServer implémente la spec **« OpenID Federation 1.1 »** (version
finale, 5 mai 2026) : l'OP peut publier une **entity configuration** (son
*entity statement* auto-signé) et vérifier la **chaîne de confiance** d'une
entité qui lui fait confiance.

> **Le support est désactivé par défaut** : il s'active avec
> `PURIDENTITYSERVER_FEDERATION_ENABLED=true` (ou `federation_enabled = true`
> dans la table `[settings]` du fichier de configuration). Sans lui, aucune
> route de Fédération n'est exposée et le discovery ne publie aucun membre de
> Fédération.

## État de l'implémentation

La feature est livrée **par tranches** (issue #170) :

| Tranche | Contenu | État |
| --- | --- | --- |
| 1 | Entity statement de l'OP, résolution de chaîne de confiance, clés dédiées, metadata de discovery | **livrée** (PR #203) |
| 2 | Enregistrement automatique (`client_id` = Entity Identifier du RP) | **livrée** (PR #203) |
| 3 | Enregistrement explicite (§12.2) | **livrée** (PR #203) |
| 4 | Endpoints de l'OP comme supérieur (`fetch`, `list`, `resolve`), plan de certification, sample | à venir |

## Le modèle

Un **entity statement** est un JWT signé décrivant une entité (spec §3) :

```json
{
  "iss": "https://op.example.com",
  "sub": "https://op.example.com",
  "iat": 1760000000,
  "exp": 1760003600,
  "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "…" } ] },
  "metadata": {
    "openid_provider": { "issuer": "https://op.example.com", "…": "…" },
    "federation_entity": {
      "federation_fetch_endpoint": "https://op.example.com/federation/fetch",
      "federation_list_endpoint": "https://op.example.com/federation/list",
      "federation_resolve_endpoint": "https://op.example.com/federation/resolve"
    }
  },
  "authority_hints": ["https://ta.example.com"]
}
```

Points structurants :

- `iss`, `sub`, `iat`, `exp` et `jwks` sont **obligatoires** (§3.1.1) ;
- l'entity statement est **auto-signé** : `iss == sub` et sa signature se
  vérifie avec le `jwks` qu'il porte lui-même (§3.2, étape 10) ;
- l'en-tête JWS porte `typ: entity-statement+jwt` et un `kid` non vide — sans
  eux, le statement est rejeté (§3) ;
- `authority_hints` liste les supérieurs immédiats ; il est absent sur une
  ancre de confiance (§3.1.2) ;
- les types d'entité des metadata sont limités aux types standard
  (`federation_entity`, `openid_provider`, `openid_relying_party`, …) (§5.1).

## Clés de signature

Les entity statements sont signés par des clés **dédiées**
(`KeyUse.FEDERATION`), distinctes des clés `sig` publiées au JWKS OIDC : la
spec §2.1 recommande que les clés de fédération ne servent à aucun autre
protocole. L'algorithme est configurable (`federation_signing_alg`, ES256 par
défaut — la suite de certification accepte RSA ≥ 2048 et EC ≥ 256).

## Résolution de chaîne de confiance

L'OP résout la chaîne d'une entité (un RP fédéré) :

1. il lit l'entity configuration du sujet (`<entity_id>/.well-known/openid-federation`)
   et la vérifie (auto-signature, `iss`/`sub`, expiration) ;
2. il remonte les `authority_hints` du sujet, en validant chaque supérieur ;
3. pour chaque supérieur, il récupère le *subordinate statement* (spec §8.1)
   qui atteste l'entité, et le vérifie contre les clés du supérieur ;
4. il s'arrête sur l'ancre de confiance configurée.

Une chaîne incomplète, expirée ou mal signée est **rejetée** (aucune chaîne
retournée). Deux contrôles supplémentaires s'appliquent (spec §10.2) :

- la signature de l'entity configuration du sujet est re-vérifiée avec les
  clés que le supérieur lui a attestées dans le *subordinate statement*
  (étape 6) : un tiers ne peut pas substituer sa propre configuration à celle
  du sujet ;
- toute chaîne aboutissant hors des `trust_anchors` configurés est rejetée :
  cette liste est le périmètre de confiance de l'OP.

## Enregistrement automatique (§12.1)

Avec `federation_enabled`, un RP n'a **rien à enregistrer** auprès de l'OP
(mode `automatic`, spec §12.1) : il s'identifie par son **Entity Identifier**
en `client_id` et l'OP déduit son client de l'entity statement :

1. un `client_id` inconnu du registre déclenche la résolution de chaîne de
   confiance de cette entité (le registre reste la source de vérité : un
   client enregistré l'emporte) ;
2. les metadata `openid_relying_party` de l'entity configuration du RP
   (spec §5.1) fournissent les `redirect_uris` et le `jwks` **inline**
   (`jwks_uri` non résolu) ;
3. le client dérivé est **public**, actif, limité au scope `openid`, et
   s'authentifie en `private_key_jwt` avec ses clés de fédération — les
   clés de la chaîne étant déjà validées, l'assertion client se vérifie
   contre le `jwks` du RP ;
4. le client n'est **pas persisté** : il est re-dérivé à chaque demande,
   une rotation des clés ou des `redirect_uris` du RP est donc effective
   immédiatement.

Un RP hors de toute chaîne acceptée, sans `openid_relying_party`, sans
`redirect_uris` ou sans `jwks` inline est refusé (`client_id` inconnu).

## Enregistrement explicite (§12.2)

L'OP expose aussi `POST /federation/register` (publié en
`federation_registration_endpoint` au discovery) pour le mode `explicit` :
le RP soumet son **entity configuration** et reçoit une registration signée.

### Demande (§12.2.1)

Le corps est l'entity configuration du RP en
`application/entity-statement+jwt`, ou une chaîne de confiance JSON
(`application/trust-chain+json`, dont le premier statement est retenu).
L'en-tête `trust_chain` n'est pas exploité : la demande est alors traitée à
partir de l'entity configuration de son corps, ce que la spec autorise
explicitement (§12.2.2, étape 5).

L'entity configuration doit satisfaire toutes les règles d'un entity statement
(§3.2) et porter :

- `iss` = `sub` = l'Entity Identifier du RP ;
- `aud` = l'Entity Identifier de l'OP, sans autre valeur ;
- `jwks` — le RP s'authentifiera avec ces clés ;
- `authority_hints` — l'ancre par laquelle la chaîne sera résolue.

### Traitement (§12.2.2)

1. la signature de l'entity configuration est vérifiée avec son propre
   `jwks`, puis **avec les clés que l'ancre lui a attestées** dans le
   *subordinate statement* (§10.2, étape 6) : c'est ce lien qui interdit à un
   tiers de se faire passer pour le RP ;
2. la chaîne de confiance est résolue à partir des `authority_hints` reçus,
   selon les mêmes règles que la résolution standard ;
3. le client est dérivé des metadata `openid_relying_party` de l'entity
   configuration **reçue** (`derive_client`, cf. enregistrement automatique) :
   `redirect_uris` et `jwks` inline y sont exigés.

Aucune donnée n'est persistée (pas de `registration_access_token` — la spec
déconseille d'en délivrer un, §12.2.2) : la registration est re-dérivée à
chaque demande, sa durée de vie étant bornée par l'expiration de la chaîne
(§12.3).

### Réponse (§12.2.3)

La réponse `200` est un JWT en `application/explicit-registration-response+jwt`
(`typ: explicit-registration-response+jwt`) portant :

- `iss` = l'Entity Identifier de l'OP, `sub` = celui du RP, `aud` = le RP ;
- `trust_anchor` (l'ancre sélectionnée) et `authority_hints` (l'immédiat
  supérieur du RP) ;
- `exp` : le minimum des expirations des statements de la chaîne (§12.3) ;
- `metadata.openid_relying_party` : les metadata du RP avec le `client_id`
  provisionné (= l'Entity Identifier) et la méthode effective
  (`private_key_jwt`) ;
- `jwks` : copie verbatim du `jwks` de l'entity configuration reçue (§12.2.3).

### Erreurs (§12.2.4, §8.9)

Les refus répondent `{"error": …, "error_description": …}` :

| Code | Statut | Cause |
| --- | --- | --- |
| `invalid_request` | 400 | Content-Type ou corps non exploitable |
| `invalid_client` | 401 | Entity configuration illisible ou mal signée ; `iss`/`sub` ou `aud` incorrects |
| `invalid_trust_chain` | 400 | `authority_hints` absents, chaîne non résoluble ou ancre hors `trust_anchors` |
| `invalid_client_metadata` | 400 | `openid_relying_party` incomplet (`redirect_uris`, `jwks` inline) |

> **Limite actuelle** : aucune substitution n'est appliquée aux metadata
> reçues ni à leur `jwks` (§12.2.2, étapes 1 et 5) — les metadata sont celles
> signées par le RP.

## Configuration

| Variable | Défaut | Description |
| --- | --- | --- |
| `PURIDENTITYSERVER_FEDERATION_ENABLED` | `false` | Active le support de la Fédération (entity statement, routes, metadata de discovery). |
| `PURIDENTITYSERVER_FEDERATION_ENTITY_IDENTIFIER` | *(issuer)* | Entity Identifier de l'OP (URL `https` sans query ni fragment). |
| `PURIDENTITYSERVER_FEDERATION_TRUST_ANCHORS` | *(vide)* | Ancres de confiance acceptées pour la résolution ; vide = n'importe quelle ancre (développement). |
| `PURIDENTITYSERVER_FEDERATION_STATEMENT_TTL_SECONDS` | `3600` | Durée de vie de l'entity statement. |
| `PURIDENTITYSERVER_FEDERATION_SIGNING_ALG` | `ES256` | Algorithme de signature des entity statements. |

## Certification

La suite publie deux plans federation ; celui qui correspond au rôle de notre
OP — l'OP **rejoint** une fédération — est
`openid-federation-entity-joined-to-test-federation-op-test-plan` : la suite
héberge le trust anchor et joue le RP, ce qui le rend rejouable dans le
harnais local. Le plan « deployed »
(`openid-federation-deployed-entity-test-plan`) suppose un trust anchor
déployé externe, connu de l'OP : il reste jouable **par paramétrage** (la
configuration du plan porte `federation.entity_identifier`,
`federation.de_trust_anchor` et `federation.de_trust_anchor_jwks`).
