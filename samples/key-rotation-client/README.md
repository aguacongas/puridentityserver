# Test manuel : rotation des clés de signature (OIDC Core 1.0 §10.1)

Script de démonstration de la **rotation des clés de signature** de
PurIdentityServer. Il lance un serveur en sous-processus avec une
configuration **spécifique à ce test** (générée par `smoke_common.py` :
port `8122`, une seule famille de clés `RS256` en RSA 2048, une **rotation
proactive** d'une seconde) puis joue le scénario complet.

Le scénario vérifie :

1. le discovery annonce le `jwks_uri` ;
2. premier relevé du JWKS : la clé de signature courante ;
3. login + `/authorize` + `/token` : un `id_token` est signé par la clé
   courante ;
4. après la période de rotation, second relevé du JWKS : une **nouvelle** clé
   de signature est publiée et l'ancienne est **conservée** (transition en
   douceur) ;
5. l'`id_token` obtenu avant la rotation reste vérifiable avec le JWKS
   publié ;
6. troisième relevé : le magasin de clés reste borné (les clés retirées
   au-delà de la rétention sont purgées) ;
7. **rotation à la demande** : `POST /signing-keys/rotate` (endpoint
   d'administration, protégé par un jeton d'administration) fait pivoter les
   clés immédiatement — l'ancienne reste publiée.

## Lancement

```bash
uv run python samples/key-rotation-client/smoke_test.py
```

## Résultat attendu

Sortie pas-à-pas se terminant par :

```text
  [1/7] discovery OK (jwks_uri=http://127.0.0.1:8122/.well-known/jwks.json)
  [2/7] premier relevé du JWKS : 1 clé(s) publiée(s)
  [3/7] id_token obtenu (signé par la clé de signature courante)
  [4/7] rotation : nouvelle clé publiée, ancienne clé conservée (OIDC Core 1.0 §10.1)
  [5/7] l'id_token signé avant la rotation reste vérifiable
  [6/7] le JWKS reste borné (2 clé(s) publiée(s))
  [7/7] rotation à la demande (POST /signing-keys/rotate) : 1 clé(s) pivotée(s), ancienne conservée
=== SCÉNARIO OK en X.Xs ===
```

## Comment ça marche ?

OIDC Core 1.0 §10.1 : *the JWK Set document at the `jwks_uri` SHOULD retain
recently decommissioned signing keys for a reasonable period of time to
facilitate a smooth transition*. PurIdentityServer applique cette
recommandation :

- **rotation proactive** (`jwks_rotation_seconds`) : au-delà de cet âge, la
  clé de signature est remplacée. La rotation est *paresseuse* : elle est
  déclenchée par la publication du JWKS, et non par une tâche de fond —
  aucune clé n'est générée si personne ne consulte le JWKS ;
- **rotation à la demande** (`POST /signing-keys/rotate`) : l'endpoint
  d'administration force la rotation de toutes les familles de clés gérées.
  Le magasin de clés est partagé entre l'OP et le serveur d'administration :
  la nouvelle clé est publiée au JWKS à la publication suivante, l'ancienne
  reste publiée pendant la rétention ;
- **rétention** (`jwks_retained_keys`) : les clés retirées restent publiées au
  JWKS (et restent stockées) pendant la rétention ; au-delà, elles sont
  purgées, le magasin de clés reste donc borné ;
- **validation** : un jeton signé par une clé retirée reste vérifiable
  pendant la rétention (la clé est résolue par `kid` sur toutes les clés
  conservées, pas seulement les clés actives).

Les réglages sont documentés dans `docs/configuration.md` (paragraphes
`PURIDENTITYSERVER_JWKS_ROTATION_SECONDS` et
`PURIDENTITYSERVER_ADMIN_REQUIRED_CLAIM`). Par défaut la rotation
proactive est **désactivée** : la rotation journalière
(`jwks_rotation_days` / `jwks_grace_period_days`) s'applique, comme
jusqu'ici.
