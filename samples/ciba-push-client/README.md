# Test manuel : CIBA en mode push

Demonstration du mode **push** de CIBA (OIDC CIBA 1.0) : le client
initie une demande, l'utilisateur approuve, puis le serveur envoie une
notification **signee en JWT** au `client_notification_endpoint` du
client. Les jetons (`id_token`, `access_token`) figurent dans ce JWT.

## Prerequis

- Serveur PurIdentityServer lance sur `http://127.0.0.1:8000` avec :
  `ciba_enabled = true`, `ciba_approval_enabled = true` ;
- client seed `sample-ciba-push-client` (mode push) ;
- profil `alice` (`alice.martin@example.com`).

```sh
python -m puridentityserver
```

## Execution

```sh
cd samples/ciba-push-client
python client.py
```

Le client demarre un listener local sur le port 8119
(`http://127.0.0.1:8119/notify`), envoie la demande, puis attend la
notification push. Approuvez la demande dans un autre terminal avec la
commande affichee (`curl ... /ciba/approve?token=...&type=allow`).

La notification recue est un JWT signe par l'OP : le client l'affiche
decode (sans verification de signature pour la demonstration) et les
jetons y figurent.

> Variables d'environnement : `CIBA_ISSUER`, `CIBA_CLIENT_ID`,
> `CIBA_CLIENT_SECRET`, `CIBA_LOGIN_HINT`, `CIBA_NOTIFY_PORT`.
"""
path = pathlib.Path(r"C:\Projects\Perso\PurIdentityServer\samples\ciba-push-client\README.md")
path.write_text(content, encoding="utf-8")
print("done")
EOF