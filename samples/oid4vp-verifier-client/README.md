# Test manuel : OID4VP 1.0 HAIP (profil verifier/RP)

Ce repertoire est un **squelette** d un client verifier pour le plan
oid4vp-1final-verifier-haip-test-plan de la suite de certification
OpenID organisateur.

Le plan correspond au scenario RP-side, c est-a-dire que le PurIdentityServer
(par OP) n est par lui-meme pas executeur de ce plan. Notre application ne
fournit que l identite numerique (OP) pour etre verifiee par un verifier tiers.

## Statut (maj)

Ce client est au stade **squelette** : il lance en sous-processus une
application verifier de demonstration (port 8308) et expose un flux minimal
VP (dcql) par note/tente pas une capture echidence.

## Lancement (provisionnel)

`
uv run python samples/oid4vp-verifier-client/smoke_test.py
`

## Suite complete

Le parcours complet se rejoue via la vraie suite de certification docker
(harness local, plan oid4vp) deja documente dans certification/README.md.

## DoD

- README pas-a-pas, lancement, config, resultat attendu.
- Coherent avec samples/fapi2-client.

C est essentiellement un placeholder pour la DoD d issuance, qui demande un
echantillon exercable : un scenario OID4VP bout en bout n est pas encore
livrable sans deploiement complet de l infrastructure verifier.
