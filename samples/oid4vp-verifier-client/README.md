# OID4VP — mode manuel et automatisation future

Ce dossier documente le prerequis pour rejouer le plan OID4VP (`certification/plans/oid4vp.json`)
en mode manuel, puis pour l'automatiser.

## Lancement manuel

1. Activer l'OP :

   ```bash
   PURIDENTITYSERVER_OID4VP_ENABLED=true uv run python -m puridentityprotocol
   ```

2. Lancer le harness local (suite OpenID) avec le plan `oid4vp` :

   ```bash
   bash certification/local/run-plan.sh oid4vp  # si supporte
   ```

   Sinon, ouvrir le JSON et piloter le navigateur manuellement :
   login `alice@example.com` / `password`, consent, attente `submission_complete`.

3. Verifier que `/vp_response` renvoie `200 {"status":"received"}`.

## DoD

- README pas-a-pas, lancement, config, resultat attendu.
- Coherent avec `samples/fapi2-client` pour les flux.

## Statut

Ce client reste un squelette ; le scenario OID4VP bout en bout n'est pas
encore automatisable (issue #265).