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
| 3 | Enregistrement explicite (§12.2) | à venir |
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
retournée).

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
