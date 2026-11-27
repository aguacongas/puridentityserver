#!/usr/bin/env python3
"""Initiateur OpenID4VCI pour la suite de certification (issue #306).

Les modules `vci10issuer` du plan HAIP en variante
`issuer_initiated` s'arrêtent en état WAITING : ils exposent leur endpoint
`/test/a/{alias}/credential_offer` et attendent qu'une offre de credential
leur soit LIVRÉE (query `credential_offer` ou `credential_offer_uri`).
Ce script joue le rôle de l'émetteur : il obtient un jeton client portant le
scope `openid4vci`, crée l'offre auprès de PurIdentityServer
(`POST /credential-offer`) puis la livre au module en attente, déclenchant
ainsi le cycle complet (validation de l'offre → demande d'autorisation →
token → credential → verdict).

Le driver (`run-test-plan.py`) l'invoque une fois, à l'état WAITING d'un
module `oid4vci-1_0-issuer-*`, via le patch
`certification/conformance-oid4vci-initiator.patch`. Deux garde-fous
encadrent ensuite les livraisons :

- **porte d'entrée** : le module n'est servi que s'il attend réellement une
  offre — état `WAITING` (`GET /api/info/{id}`), `credential_offer_endpoint`
  exposé (`GET /api/runner/{id}`) et entrée « Waiting for call to credential
  offer endpoint » en tête du journal (`GET /api/log/{id}`). Exclus : les
  modules qui n'attendent aucune offre (ex. `issuer-metadata-test`, qui
  valide les métadonnées puis se termine sans jamais attendre) et
  l'attente transitoire de finalisation de `fireTestFinished()` (le module
  passe par WAITING avant FINISHED, endpoint encore exposé) — livrer dans
  ces cas produirait un changement d'état illégal et ferait échouer le
  module ;
- **boucle de relivraison** : après chaque livraison, l'initiateur reste
  attaché au module et livre une NOUVELLE offre à chaque retour en
  `WAITING` + exposé + journal (cas du second client de
  `happy-flow-multiple-clients`, que le driver n'invoque qu'une seule fois),
  jusqu'à `FINISHED` / `INTERRUPTED` ou délai total dépassé.

Sorties : 0 si le module est terminé, n'attendait pas d'offre, ou si toutes
les livraisons ont réussi ; non nul sinon (erreur dure : OP injoignable,
livraison en 404) — le module échoue alors par son propre état.

Usage (appelé par le driver, mais autonome) :
    python oid4vci_initiator.py --module oid4vci-1_0-issuer-happy-flow
        --module-id abc123 --alias puridentityserver-oid4vci-issuer-initiated
        --credential-configuration-id puridentityserver-sdjwt-vc
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_LOGGER = logging.getLogger("oid4vci_initiator")

# Délais (secondes) : obtention du jeton + création de l'offre côté OP, puis
# livraison — le module enchaîne dans la même requête (validation, demande
# d'autorisation, échange du code, émission du credential) avant de répondre.
CREATE_TIMEOUT = 60
DELIVER_TIMEOUT = 600
# Relevé d'état du module : la porte d'entrée laisse30 s au module pour
# s'installer en WAITING (le hook du driver l'invoque déjà en WAITING, la
# marge ne sert qu'aux courses) ; la boucle de relivraison est bornée par un
# délai total couvrant deux livraisons pleines — au-delà, on rend la main au
# driver, qui applique alors son propre CONFORMANCE_MODULE_TIMEOUT.
GATE_TIMEOUT = 30
POLL_INTERVAL = 2
LOOP_TIMEOUT = 1200
# États terminaux (TestModule.Status) au-delà desquels plus rien n'est livré.
TERMINAL_STATUSES = ("FINISHED", "INTERRUPTED")
# Clé exposée par waitForCredentialOffer() (AbstractVCIIssuerTestModule).
OFFER_EXPOSED_KEY = "credential_offer_endpoint"
# Entrée de journal posée par VCIWaitForCredentialOffer juste avant l'état
# WAITING : distingue une vraie attente d'offre de l'attente transitoire de
# finalisation (fireTestFinished), dont le journal se termine sur les entrées
# de fin de flux. On relit la fin du journal (3 entrées) pour absorber les
# lignes de cadre éventuelles après l'entrée du module.
OFFER_WAIT_MARKER = "Waiting for call to credential offer endpoint"
LOG_TAIL = 3


def _build_ssl_context() -> ssl.SSLContext | None:
    """Contexte SSL : vérification désactivée seulement en mode dev.

    La suite locale sert un certificat auto-signé ; le mode dev est signalé
    par ``CONFORMANCE_DEV_MODE`` ou ``DISABLE_SSL_VERIFY`` (les deux
    harnesss locaux le positionnent). En hébergé, le certificat est public :
    le contexte par défaut du système fait foi.

    Returns:
        Un contexte sans vérification si le mode dev est actif, sinon
        ``None`` (contexte par défaut d'``urlopen``).
    """
    if not (os.environ.get("CONFORMANCE_DEV_MODE") or os.environ.get("DISABLE_SSL_VERIFY")):
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _post_form(
    url: str,
    payload: dict[str, str],
    *,
    timeout: int,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    """POST formulaire (authentification client) vers l'OP.

    Args:
        url: Endpoint à appeler.
        payload: Corps formulaire (encodé ``application/x-www-form-urlencoded``).
        timeout: Délai maximal en secondes.
        headers: En-têtes additionnels (ex. ``Authorization``).

    Returns:
        Le dictionnaire JSON décodé.

    Raises:
        SystemExit: En cas d'échec HTTP ou de corps invalide.
    """
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(payload).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})},
        method="POST",
    )
    return _send_json(request, timeout=timeout, label="appel POST")


def _post_json(
    url: str,
    payload: dict[str, object],
    *,
    token: str,
    timeout: int,
) -> dict[str, object]:
    """POST JSON authentifié vers l'OP.

    Args:
        url: Endpoint à appeler.
        payload: Corps JSON.
        token: Access token porteur (en-tête ``Authorization``).
        timeout: Délai maximal en secondes.

    Returns:
        Le dictionnaire JSON décodé.

    Raises:
        SystemExit: En cas d'échec HTTP ou de corps invalide.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    return _send_json(request, timeout=timeout, label="création de l'offre")


def _send_json(
    request: urllib.request.Request,
    *,
    timeout: int,
    label: str,
) -> dict[str, object]:
    """Exécute une requête JSON et décode la réponse.

    Args:
        request: Requête à exécuter.
        timeout: Délai maximal en secondes.
        label: Libellé du point d'appel pour les messages d'erreur.

    Returns:
        Le dictionnaire JSON décodé.

    Raises:
        SystemExit: En cas d'échec HTTP ou de corps invalide.
    """
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            body = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read(500) if hasattr(error, "read") else b""
        raise SystemExit(
            f"[oid4vci-initiator] {label} refusé : HTTP {error.code} {detail!r}"
        ) from error
    except (urllib.error.URLError, OSError) as error:
        raise SystemExit(
            f"[oid4vci-initiator] {label} impossible ({request.full_url}) : {error}"
        ) from error
    if not 200 <= status < 300:
        raise SystemExit(f"[oid4vci-initiator] {label} refusé : HTTP {status} {body[:300]!r}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as error:
        raise SystemExit(f"[oid4vci-initiator] {label} : corps non JSON {body[:300]!r}") from error
    if not isinstance(data, dict):
        raise SystemExit(f"[oid4vci-initiator] {label} : corps inattendu {body[:300]!r}")
    return data


def _get_json(
    url: str,
    *,
    timeout: int,
    ssl_ctx: ssl.SSLContext | None,
    label: str,
) -> object:
    """GET JSON vers la suite de certification.

    Args:
        url: Endpoint à appeler.
        timeout: Délai maximal en secondes.
        ssl_ctx: Contexte SSL (``None`` = défaut système).
        label: Libellé du point d'appel pour les messages d'erreur.

    Returns:
        Le corps JSON décodé ; les appelants le réduisent (dictionnaire ou
        liste). ``None`` si la ressource est absente (HTTP 404, test retiré
        du runner).

    Raises:
        SystemExit: En cas d'échec HTTP autre que 404, de connexion ou de
        corps invalide.
    """
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        detail = error.read(500) if hasattr(error, "read") else b""
        raise SystemExit(
            f"[oid4vci-initiator] {label} refusé : HTTP {error.code} {detail!r}"
        ) from error
    except (urllib.error.URLError, OSError) as error:
        raise SystemExit(f"[oid4vci-initiator] {label} impossible ({url}) : {error}") from error
    try:
        return json.loads(body)
    except json.JSONDecodeError as error:
        raise SystemExit(f"[oid4vci-initiator] {label} : corps non JSON {body[:300]!r}") from error


def _client_token(op_base: str) -> str:
    """Obtient un access token machine portant le scope ``openid4vci``.

    Le client `certification-admin` (secret jamais committé :
    ``CERTIFICATION_ADMIN_CLIENT_SECRET``) est le seul seed dont la méthode
    d'authentification est un simple secret partagé — les seeds oid4vci sont
    en ``attest_jwt_client_auth``.

    Args:
        op_base: URL de base de l'OP (boucle locale claire).

    Returns:
        L'access token.

    Raises:
        SystemExit: Si le jeton est refusé ou absent.
    """
    client_secret = os.environ.get("CERTIFICATION_ADMIN_CLIENT_SECRET", "")
    if not client_secret:
        raise SystemExit(
            "[oid4vci-initiator] CERTIFICATION_ADMIN_CLIENT_SECRET absent de l'environnement"
        )
    data = _post_form(
        f"{op_base}/token",
        {
            "grant_type": "client_credentials",
            "client_id": "certification-admin",
            "client_secret": client_secret,
            "scope": "openid4vci",
        },
        timeout=CREATE_TIMEOUT,
    )
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        raise SystemExit(f"[oid4vci-initiator] jeton client refusé : {data!r}")
    return token


def _create_offer(
    op_base: str,
    token: str,
    credential_configuration_id: str,
) -> dict[str, object]:
    """Crée une offre de credential auprès de l'OP.

    Args:
        op_base: URL de base de l'OP.
        token: Access token portant le scope ``openid4vci``.
        credential_configuration_id: Configuration de credential à émettre.

    Returns:
        L'objet ``credential_offer`` de la réponse (l'OP y joint aussi un
        ``credential_offer_uri``, non utilisé : la livraison se fait par
        valeur).

    Raises:
        SystemExit: Si l'offre n'est pas créée.
    """
    created = _post_json(
        f"{op_base}/credential-offer",
        {
            "subject": "alice@example.com",
            "credential_configuration_ids": [credential_configuration_id],
        },
        token=token,
        timeout=CREATE_TIMEOUT,
    )
    offer = created.get("credential_offer")
    if not isinstance(offer, dict):
        raise SystemExit(f"[oid4vci-initiator] offre absente de la réponse : {created!r}")
    return offer


def _deliver_credential_offer(
    url: str,
    offer: dict[str, object],
    *,
    timeout: int,
    ssl_ctx: ssl.SSLContext | None,
) -> None:
    """Livraison synchrone de l'offre au module en attente.

    Le module traite la requête de bout en bout (validation de l'offre,
    demande d'autorisation, échange du code, émission du credential,
    verdict) puis répond 200.

    Args:
        url: URL de base de l'endpoint émulated (alias compris).
        offer: Objet ``credential_offer`` à livrer par valeur.
        timeout: Délai maximal en secondes.
        ssl_ctx: Contexte SSL (``None`` = défaut système).

    Raises:
        SystemExit: En cas d'échec de connexion ou de refus (404).
    """
    query = urllib.parse.urlencode({"credential_offer": json.dumps(offer, separators=(",", ":"))})
    request = urllib.request.Request(f"{url}?{query}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ssl_ctx) as response:
            status = response.status
            body = response.read(500)
    except urllib.error.HTTPError as error:
        # 404 = alias inconnu ou module déjà terminé : la livraison a raté
        # -> sortie non nule. Les autres erreurs viennent du module après
        # traitement : son propre état fait foi, on se contente de tracer.
        if error.code == 404:
            raise SystemExit(
                f"[oid4vci-initiator] livraison refusée : HTTP 404 pour {url}"
            ) from error
        detail = error.read(500) if hasattr(error, "read") else b""
        _LOGGER.error("livraison refusée : HTTP %s %r", error.code, detail)
        return
    except (urllib.error.URLError, OSError) as error:
        raise SystemExit(f"[oid4vci-initiator] livraison impossible ({url}) : {error}") from error
    if not 200 <= status < 300:
        _LOGGER.error("livraison : HTTP %s %r", status, body)


def _module_status(suite_base: str, module_id: str, ssl_ctx: ssl.SSLContext | None) -> str | None:
    """Lit l'état courant du module via l'API d'information de la suite.

    Args:
        suite_base: URL de base de la suite (``CONFORMANCE_SERVER``).
        module_id: Identifiant d'instance du module.
        ssl_ctx: Contexte SSL.

    Returns:
        L'état (ex. ``WAITING``), ou ``None`` si le relevé est inaccessible
        ou vide.
    """
    data = _get_json(
        f"{suite_base}/api/info/{module_id}",
        timeout=30,
        ssl_ctx=ssl_ctx,
        label="info du module",
    )
    if not isinstance(data, dict):
        return None
    status = data.get("status")
    return status if isinstance(status, str) else None


def _module_exposes_offer(suite_base: str, module_id: str, ssl_ctx: ssl.SSLContext | None) -> bool:
    """Vérifie que le module expose son endpoint d'offre de credential.

    Args:
        suite_base: URL de base de la suite.
        module_id: Identifiant d'instance du module.
        ssl_ctx: Contexte SSL.

    Returns:
        ``True`` si ``credential_offer_endpoint`` figure dans les valeurs
        exposées du module ; ``False`` sinon ou si le module n'est plus
        suivi par le runner (HTTP 404).
    """
    data = _get_json(
        f"{suite_base}/api/runner/{module_id}",
        timeout=30,
        ssl_ctx=ssl_ctx,
        label="runner du module",
    )
    if not isinstance(data, dict):
        return False
    exposed = data.get("exposed")
    return isinstance(exposed, dict) and OFFER_EXPOSED_KEY in exposed


def _log_shows_offer_wait(suite_base: str, module_id: str, ssl_ctx: ssl.SSLContext | None) -> bool:
    """Vérifie que le journal du module se termine sur une attente d'offre.

    Args:
        suite_base: URL de base de la suite.
        module_id: Identifiant d'instance du module.
        ssl_ctx: Contexte SSL.

    Returns:
        ``True`` si l'une des dernières entrées du journal porte le marqueur
        de ``VCIWaitForCredentialOffer`` ; ``False`` sinon ou si le journal
        est inaccessible.
    """
    data = _get_json(
        f"{suite_base}/api/log/{module_id}",
        timeout=60,
        ssl_ctx=ssl_ctx,
        label="journal du module",
    )
    if not isinstance(data, list):
        return False
    for entry in data[-LOG_TAIL:]:
        if not isinstance(entry, dict):
            continue
        msg = entry.get("msg")
        if isinstance(msg, str) and OFFER_WAIT_MARKER in msg:
            return True
    return False


def _is_deliverable(
    status: str | None, suite_base: str, module_id: str, ssl_ctx: ssl.SSLContext | None
) -> bool:
    """Décide si le module attend réellement une offre à ce moment.

    Args:
        status: État relevé (``None`` si le relevé est inaccessible).
        suite_base: URL de base de la suite.
        module_id: Identifiant d'instance du module.
        ssl_ctx: Contexte SSL.

    Returns:
        ``True`` si le module est en ``WAITING``, expose l'endpoint d'offre
        et que son journal se termine sur l'attente d'offre.
    """
    if status != "WAITING":
        return False
    if not _module_exposes_offer(suite_base, module_id, ssl_ctx):
        return False
    return _log_shows_offer_wait(suite_base, module_id, ssl_ctx)


def _wait_ready_for_delivery(
    suite_base: str, module_id: str, ssl_ctx: ssl.SSLContext | None
) -> bool:
    """Porte d'entrée : attend que le module attende réellement une offre.

    Args:
        suite_base: URL de base de la suite.
        module_id: Identifiant d'instance du module.
        ssl_ctx: Contexte SSL.

    Returns:
        ``True`` si une offre peut être livrée, ``False`` si le module est
        terminé ou n'a pas exposé d'attente d'offre dans le délai (le module
        échoue alors par son propre état, jamais par une livraison parasite).
    """
    deadline = time.monotonic() + GATE_TIMEOUT
    while True:
        status = _module_status(suite_base, module_id, ssl_ctx)
        if status in TERMINAL_STATUSES:
            _LOGGER.info(
                "module id=%s : terminé (%s) avant livraison, rien à livrer", module_id, status
            )
            return False
        if _is_deliverable(status, suite_base, module_id, ssl_ctx):
            return True
        if time.monotonic() >= deadline:
            _LOGGER.warning(
                "module id=%s : pas d'attente d'offre sous %ss, livraison sautée",
                module_id,
                GATE_TIMEOUT,
            )
            return False
        time.sleep(POLL_INTERVAL)


def _wait_next_delivery(
    suite_base: str,
    module_id: str,
    ssl_ctx: ssl.SSLContext | None,
    deadline: float,
) -> bool:
    """Boucle interne : attend la prochaine livraison ou l'issue du module.

    Args:
        suite_base: URL de base de la suite.
        module_id: Identifiant d'instance du module.
        ssl_ctx: Contexte SSL.
        deadline: Instant (``time.monotonic``) au-delà duquel on rend la main.

    Returns:
        ``True`` si une nouvelle offre doit être livrée, ``False`` si le
        module est terminé, injoignable ou si le délai total est dépassé.
    """
    while True:
        if time.monotonic() >= deadline:
            _LOGGER.warning(
                "module id=%s : délai total de %ss dépassé, rend la main au driver",
                module_id,
                LOOP_TIMEOUT,
            )
            return False
        time.sleep(POLL_INTERVAL)
        status = _module_status(suite_base, module_id, ssl_ctx)
        if status is None:
            _LOGGER.warning("module id=%s : statut injoignable, rend la main au driver", module_id)
            return False
        if status in TERMINAL_STATUSES:
            _LOGGER.info("module id=%s : terminé (%s)", module_id, status)
            return False
        if _is_deliverable(status, suite_base, module_id, ssl_ctx):
            return True


def _deliver_offer(
    op_base: str,
    suite_base: str,
    *,
    alias: str,
    credential_configuration_id: str,
    module: str,
    module_id: str,
    offer_index: int,
    ssl_ctx: ssl.SSLContext | None,
) -> None:
    """Crée une offre côté OP puis la livre au module en attente.

    Args:
        op_base: URL de base de l'OP.
        suite_base: URL de base de la suite.
        alias: Alias réservé par le module.
        credential_configuration_id: Configuration de credential du plan.
        module: Nom complet du module (journal).
        module_id: Identifiant d'instance du module (journal).
        offer_index: Rang de la livraison pour le journal (1 = première).
        ssl_ctx: Contexte SSL (livraison vers la suite).

    Raises:
        SystemExit: Si le jeton, la création de l'offre ou la livraison
        échouent durement.
    """
    token = _client_token(op_base)
    offer = _create_offer(op_base, token, credential_configuration_id)
    url = suite_base.rstrip("/") + f"/test/a/{urllib.parse.quote(alias)}/credential_offer"
    _LOGGER.info(
        "module=%s id=%s livraison=%s (offre #%d)",
        module,
        module_id,
        url,
        offer_index,
    )
    _deliver_credential_offer(url, offer, timeout=DELIVER_TIMEOUT, ssl_ctx=ssl_ctx)


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : livre l'offre puis relit à chaque nouvel état d'attente.

    Args:
        argv: Arguments de ligne de commande (défaut : ``sys.argv[1:]``).

    Returns:
        0 si le module est terminé, n'attendait pas d'offre ou si toutes les
        livraisons ont réussi, 1 sinon.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Initiateur OpenID4VCI de la suite de certification"
    )
    parser.add_argument(
        "--module",
        required=True,
        help="Nom complet du module (ex. oid4vci-1_0-issuer-happy-flow)",
    )
    parser.add_argument(
        "--module-id",
        required=True,
        help="Identifiant d'instance du module dans la suite",
    )
    parser.add_argument("--alias", required=True, help="Alias réservé par le module")
    parser.add_argument(
        "--credential-configuration-id",
        required=True,
        help="Configuration de credential du fichier de plan (vci.credential_configuration_id)",
    )
    args = parser.parse_args(argv)

    # CONFORMANCE_SERVER se termine par un slash (SUITE_URL du harness) : sans
    # normalisation, les appels API formeraient « //api/... » et la suite
    # répondrait 400 — sortie non nulle et module déclaré en échec par le driver.
    suite_base = (os.environ.get("CONFORMANCE_SERVER") or "").rstrip("/")
    if not suite_base:
        raise SystemExit("[oid4vci-initiator] CONFORMANCE_SERVER absent de l'environnement")
    op_base = os.environ.get("OID4VCI_INITIATOR_OP_URL", "http://127.0.0.1:8000").rstrip("/")

    ssl_ctx = _build_ssl_context()

    # Porte d'entrée : le module doit réellement attendre une offre ; les
    # modules sans attente et les WAITING transitoires de finalisation sont
    # écartés sans livraison.
    if not _wait_ready_for_delivery(suite_base, args.module_id, ssl_ctx):
        return 0

    # Boucle : après chaque livraison on reste attaché au module et on
    # relivre à chaque nouvel état d'attente (second client du module
    # multiple-clients), jusqu'au terme du module ou du délai total.
    deadline = time.monotonic() + LOOP_TIMEOUT
    offer_index = 1
    while True:
        _deliver_offer(
            op_base,
            suite_base,
            alias=args.alias,
            credential_configuration_id=args.credential_configuration_id,
            module=args.module,
            module_id=args.module_id,
            offer_index=offer_index,
            ssl_ctx=ssl_ctx,
        )
        offer_index += 1
        if not _wait_next_delivery(suite_base, args.module_id, ssl_ctx, deadline):
            return 0


if __name__ == "__main__":
    sys.exit(main())
