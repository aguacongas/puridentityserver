# Test manuel : fédération (OpenID Federation 1.1) — l'OP en supérieur

Script de démonstration du rôle de **supérieur** de PurIdentityServer dans une
fédération OpenID Federation 1.1 : l'OP est l'autorité des entités fédérées
qu'il a enregistrées comme clients (Entity Identifier `https` + `jwks` inline)
et publie les trois endpoints de la spec §8 — `fetch`, `list`, `resolve`.

Le test lance un serveur en sous-processus avec une configuration **spécifique
à ce test** (générée par `smoke_common.py` : port `8126`, `federation_enabled`,
un client seedé fédéré `https://rp.example` et un client classique) puis joue
le parcours.

Le scénario vérifie :

1. l'entity statement de l'OP (`/.well-known/openid-federation`) : `typ`
   `entity-statement+jwt`, `iss` = `sub` = l'issuer, `jwks` de signature,
   `metadata.openid_provider` et `metadata.federation_entity` publiant les
   trois endpoints (§5.1.1) — la signature se vérifie avec les clés publiées ;
2. le discovery publie `federation_registration_endpoint` et
   `client_registration_types_supported` (§5.1.3) ;
3. `GET /federation/list` rend les Entity Identifier des seuls clients
   fédérés (§8.2.2) ;
4. `GET /federation/fetch?sub=…` rend le subordinate statement signé par
   l'OP : `iss`/`sub`, `jwks` attestés du subordonné et metadata
   `openid_relying_party` résolues (§8.1) ;
5. les contrats d'erreur du fetch (§8.9) : `sub` manquant ou valant l'identité
   de l'OP → 400 `invalid_request` ; subordonné inconnu → 404 `not_found` ;
6. `GET /federation/resolve` sans `sub`/`trust_anchor` → 400
   `invalid_request` (§8.3) ;
7. resolve vers une ancre injoignable → 404 `not_found` (aucune chaîne de
   confiance ne peut être construite, §10.1) ;
8. `GET /authorize` avec un request object refusable (`HS256`, non supporté)
   dont la `redirect_uri` correspond à celle enregistrée du client → 302
   `invalid_request_object` **redirigé vers la callback du RP** (issue #211 :
   le RP fédéré ne place sa `redirect_uri` que dans le request object,
   §12.1.1.1 — l'OP la lit comme candidat et la valide au registre) ;
9. même demande avec une `redirect_uri` absente du registre → page 400,
   **aucune redirection** (jamais de cible choisie hors registre/trust chain).

## Lancement

```bash
uv run python samples/federation-client/smoke_test.py
```

## Résultat attendu

Sortie pas-à-pas se terminant par :

```text
  [1/9] entity statement de l'OP verifie (§5.1.1, §9)
  [2/9] discovery : registration federation + types publies (§5.1.3)
  [3/9] liste des subordonnes : seul le client federe est rendu (§8.2.2)
  [4/9] subordinate statement signe par l'OP, cles attestees (§8.1, §3.1.3)
  [5/9] fetch : contrats d'erreur (400 invalid_request, 404 not_found, §8.9)
  [6/9] resolve : parametres obligatoires manquants -> 400 (§8.3)
  [7/9] resolve : ancre injoignable -> 404, aucune chaine (§10.1)
  [8/9] JAR refuse -> redirection d'erreur vers la callback du RP (issue #211)
  [9/9] redirect_uri du JAR hors registre -> page 400, aucune redirection

=== SCENARIO OK ===
```

## Comment ça marche ?

Dans OpenID Federation 1.1, une entité devient **subordonné** d'un supérieur
lorsque le supérieur émet un *subordinate statement* à son sujet. Côté OP,
les clients enregistrés qui sont des entités fédérées — `client_id` est un
Entity Identifier https et le client porte des `jwks` inline — forment la
liste des subordonnés immédiats (réglage `clients_seed` ou enregistrement
fédéré §12.1/§12.2).

- `GET /federation/list` (§8.2) rend triés les Entity Identifier de ces
  clients ; les clients ordinaires en sont exclus.
- `GET /federation/fetch?sub=…` (§8.1) rend le subordinate statement signé
  avec la clé de fédération de l'OP : `jwks` attestés du sujet et metadata
  `openid_relying_party` copiées du registre. Un chain-builder distant
  vérifie cette signature avec les clés publiées dans l'EC de l'OP.
- `GET /federation/resolve?sub=…&trust_anchor=…` (§8.3) reconstruit et signe
  la chaîne de confiance complète ; il exige une ancre joignable configurée
  (`federation_trust_anchors`) — sans ancre, la résolution répond 404
  `not_found`, comme vérifie l'étape 7.

L'entity statement de l'OP (§9) et le discovery (§5.1.3) publient ces
endpoints ; tout est actif via le réglage `federation_enabled` (désactivé par
défaut).

Pour rejouer le parcours complet côté certification (RP test rattaché à une
ancre réelle, enregistrement automatique, fetch/list/resolve), voir
`certification/plans/federation.json` et `certification/README.md`.
