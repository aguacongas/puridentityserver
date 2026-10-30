# OpenID for Verifiable Presentations (OID4VP 1.0)

PurIdentityServer implémente un slice initial de la capacité **verifier** (issue #172), désactivé
par défaut : l'endpoint `/vp_response` n'est exposé qu'avec le réglage

```toml
oid4vp_enabled = true
```

ou `PURIDENTITYSERVER_OID4VP_ENABLED=true`.

Dans cet état, l'OP monte `POST /presentation_requests` (request object signé) et
`POST /vp_response`, qui renvoie `501` en attente de la validation complète de la
présentation (sous-issue #223).

Validation de la reponse direct_post implementee (vp_token, nonce).

Verification cryptographique du `vp_token` (signature auto-portee, audience, expiration, nonce) implementee pour `direct_post`.

Verification cryptographique du `vp_token` (JWK embarque, signature, audience, nonce) implementee.

Support DCQL : `create_presentation_request` accepte `dcql_query`, et `/vp_response`
accepte un `vp_token` scalaire, tableau ou objet DCQL (mappage id -> vp_token).


## Mode manuel (plan OID4VP 1.0)

1. Activer la capacite :

   ```toml
   oid4vp_enabled = true
   ```

2. Lancer l'OP :

   ```bash
   uv run python -m puridentityprotocol
   ```

3. Rejouer `certification/plans/oid4vp.json` via le harness local (navigateur) :
   - login avec `alice@example.com` / `password` ;
   - consentir (bouton "Autoriser") ;
   - attendre `submission_complete`.

4. Observer les logs `/vp_response` et la reponse JSON `{"status":"received"}`.

5. Noter tout warning/erreur de la suite pour alimentation de l'automatisation.

## Preparation de l'automatisation

- Deployer l'OP sur un host TLS (Render/Oracle) avec reverse proxy mTLS.
- Piper le harness OIDF en mode non interactif (TODO, issue #265).
