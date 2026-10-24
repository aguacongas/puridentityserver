# Runbook — reverse proxy TLS mTLS gratuit devant Render (Oracle Cloud Always Free + OCI)

> Issue associée : #133 (bloquait en attente d'un compte cloud gratuit). Procédure de mise en place du proxy **nginx** avec `ssl_verify_client optional_no_ca` devant l'instance Render de certification (`puridentityserver-certification`), pour terminer la liaison mTLS (#127) sans casser les flux navigateur (`/authorize` sans cert) et sans toucher au pipeline de déploiement Render.

## Pourquoi Oracle Cloud Always Free

Compte GCP refusé (pb carte) ; fallback validé sur **Oracle Cloud Infrastructure (OCI) — Always Free**, qui ne demande qu'une carte de crédit à la création du compte (pas de débit, palier gratuit pérenne) :

- **Compute** : `VM.Standard.A1.Flex` (Ampere ARM) — jusqu'à 4 OCPU / 24 GB RAM en gratuit, ou `VM.Standard.E2.1.Micro` (AMD, 1 OCPU / 1 GB) ;
- **Réseau** : VCN + subnet public + **IP publique réservée** (gratuite tant qu'attachée) ;
- **Stockage** : volume de démarrage 50 GB gratuit.
- **OCID** : identifiants OCI (`ocid1.tenancy...`, `ocid1.user...`) disponibles dans le tableau de bord.

Stack cible : **Oracle Linux 9** (ou Ubuntu 22.04) + nginx + certbot (RSA) + DuckDNS.

## 1. Compte OCI et réseau (une fois)

1. Créer le compte sur <https://cloud.oracle.com> (carte Visa/MC requise pour la vérification, aucun prélèvement).
2. Console → **Networking → Virtual Cloud Networks → Create VCN** :
   - nom `puridentity-proxy-vcn`, CIDR `10.0.0.0/16` ;
   - créer un **subnet public** `10.0.0.0/24` avec **Route Table** → Internet Gateway ;
   - **Security List** (ou NSG) : ingress TCP 22 (admin, IP source restreinte) + TCP 443 (0.0.0.0/0) ; egress tout autorisé.
3. Réserver une IP publique : **Networking → IP Management → Reserved Public IPs → Create** (free), l'attacher à l'instance ci-dessous.

## 2. VM (une fois)

1. **Compute → Instances → Create Instance** :
   - nom `puridentity-mtls-proxy` ;
   - image **Oracle Linux 9** (ou Ubuntu 22.04) ;
   - shape `VM.Standard.A1.Flex` (1 OCPU / 6 GB) — à adapter, rester dans le palier Always Free (somme des A1 ≤ 4 OCPU / 24 GB) ;
   - VCN/subnet public choisis, IP publique réservée attachée ;
   - clé SSH (générer ou coller la vôtre).
2. Se connecter : `ssh opc@<IP>` (utilisateur par défaut `opc` sur Oracle Linux ; `ubuntu` sur Ubuntu).

## 3. DNS — DuckDNS (gratuit, dynamique)

1. Compte <https://www.duckdns.org>, sous-domaine ex. `puridentity-op-cert.duckdns.org`.
2. Sur la VM, installer le client de mise à jour (cron) :
   ```bash
   mkdir -p ~/duckdns && cd ~/duckdns
   cat > duck.sh <<'EOF'
   #!/bin/bash
   TOKEN="VOTRE_TOKEN_DUCKDNS"
   DOMAIN="puridentity-op-cert"
   echo url="https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=" | curl -k -o ~/duckdns/duck.log -K -
   EOF
   chmod 700 duck.sh
   (crontab -l 2>/dev/null; echo "*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1") | crontab -
   ~/duckdns/duck.sh && cat ~/duckdns/duck.log
   ```
3. Vérifier : `dig +short puridentity-op-cert.duckdns.org` → IP de la VM.

> Si l'IP est réservée (recommandé), DuckDNS reste utile comme alias DNS stable et comme filet de sécurité.

## 4. nginx + certbot (RSA obligatoire)

```bash
sudo dnf install -y nginx certbot python3-certbot-nginx   # Oracle Linux
# ou : sudo apt install -y nginx certbot python3-certbot-nginx  (Ubuntu)
sudo systemctl enable --now nginx

# Certificat Let's Encrypt RSA (la suite FAPI1 ne négocie que des suites
# TLS 1.2 RSA ; un cert ECDSA reproduirait le plafond DisallowInsecureCipher)
sudo certbot certonly --standalone --key-type rsa \
    -d puridentity-op-cert.duckdns.org \
    --agree-tos -m votre@email.example -n
```

## 5. nginx.conf (prêt à coller)

Fichier complet : [`certification/proxy/nginx-oracle.conf`](../certification/proxy/nginx-oracle.conf). À copier dans `/etc/nginx/conf.d/puridentity.conf` (ou `/etc/nginx/sites-available/` + symlink selon la distro), en remplaçant `{HOSTNAME}` par le sous-domaine DuckDNS.

Points clés (identiques au proxy local de certification) :
- `ssl_verify_client optional_no_ca` : demande le cert au handshake **sans bloquer** les navigateurs de la suite (`/authorize` sans cert) ; accepte les certs auto-signés de la suite.
- Transfert du PEM via `X-SSL-Client-Cert` (URL-encodé, `%0A`) — l'OP normalise dans `infrastructure/client_tls.py` (`_normalize_header_value`).
- TLS 1.2 RSA au edge (`ssl_ciphers` incluant `RSA-AES128-GCM-SHA256`) pour éviter `DisallowInsecureCipher`.
- `trust_proxy_headers = true` côté OP (déjà activé dans `config.render.toml`) pour reconstruire l'URL publique (claim `htu` DPoP, RFC 9449 §4.3).

```bash
sudo cp certification/proxy/nginx-oracle.conf /etc/nginx/conf.d/puridentity.conf
sudo sed -i 's/{HOSTNAME}/puridentity-op-cert.duckdns.org/g' /etc/nginx/conf.d/puridentity.conf
sudo nginx -t && sudo systemctl reload nginx
```

## 6. Tests de bout en bout

```bash
HOST=puridentity-op-cert.duckdns.org
# sans cert -> 200
curl -fsS "https://${HOST}/.well-known/openid-configuration" >/dev/null && echo "OK sans cert"
# handshake mTLS actif (cert demande)
openssl s_client -connect "${HOST}:443" -cipher AES128-SHA256 </dev/null 2>&1 | grep -E "Protocol|Cipher|Verify"
# cert auto-signe -> 200
openssl req -x509 -newkey rsa:2048 -keyout /tmp/client.key -out /tmp/client.pem -days 1 -nodes -subj "/CN=test"
curl --cert /tmp/client.pem --key /tmp/client.key -fsS "https://${HOST}/.well-known/openid-configuration" >/dev/null && echo "OK avec cert"
```

## 7. Côté repo (PR dédiée, ordre)

1. Variable GitHub `CERTIFICATION_OP_URL` = `https://puridentity-op-cert.duckdns.org` (le workflow, les captures Playwright et la suite passent par le proxy ; le deploy hook Render reste direct).
2. PR flip seeds : `certification/config.render.toml` — `tls_client_certificate_bound_access_tokens = true` sur les 2 clients FAPI1 statiques **uniquement après** le proxy live (sinon tout `/token` fapi1 casse). FAPI2 reste sans flag (DPoP).
3. Rejeu `certification.yml` (plan=all) : objectif 6 plans verts. Si `DisallowInsecureCipher` échoue encore, déclarer les blocs résiduels en `--expected-failures-file` (issue dédiée).
4. Follow-up #132 (rejeu des plans à chaque run) une fois le vert obtenu.

## Critères d'acceptation

- Discovery public joignable sans cert ; handshake mTLS actif (cert demandé) ;
- Suite de certification : modules `fapi1-holder-of-key` / `refresh-token` verts (cert transféré, flag actif) ;
- 6 plans de certification en succès (ou résidus couverts par `expected_failures` documentés) ;
- Rien à changer au pipeline Render (deploy hook inchangé).

## Sécurité

- Le certificat client n'est **jamais vérifié contre une CA** (`optional_no_ca`) : la suite présente des certs auto-signés que l'OP accepte tels quels (transfert via `X-SSL-Client-Cert`, RFC 8705).
- Le secret admin (`CERTIFICATION_ADMIN_CLIENT_SECRET`) reste géré côté Render et GitHub Actions — jamais dans la VM.
- Renouvellement Let's Encrypt : cron `certbot renew` (installé par défaut par certbot sur Oracle Linux/Ubuntu).
- Port 22 restreint à l'IP d'administration.
