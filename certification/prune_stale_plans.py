#!/usr/bin/env python3
"""Prune stale (unpublished) test plans on the OpenID Foundation conformance server.

Issue #132 : chaque run cree des plans frais (1 run = 1 plan). On garde les N
plans les plus recents par planName et on supprime les plus anciens, sans
jamais toucher un plan publie (l'API renvoie 405 Method Not Allowed).
Les plans publies (immutable) sont conserves quoi qu'il arrive.

Variables d'environnement (heritees du workflow certification.yml) :
  CONFORMANCE_SERVER   base URL de la suite (defaut https://www.certification.openid.net/)
  CONFORMANCE_TOKEN    Bearer token admin (requis)
  KEEP_PLANS           nombre de plans recents a conserver par planName (defaut 3)
  PLAN_NAME_PREFIX     prefixe de nom a considerer (defaut puridentityserver-)
"""
from __future__ import annotations

import json
import os
import sys

import httpx

KEEP = int(os.environ.get("KEEP_PLANS", "3"))
PREFIX = os.environ.get("PLAN_NAME_PREFIX", "puridentityserver-")
BASE = os.environ.get("CONFORMANCE_SERVER", "https://www.certification.openid.net/")
TOKEN = os.environ.get("CONFORMANCE_TOKEN", "")

if not BASE.endswith("/"):
    BASE += "/"
TOKEN = (TOKEN or "").strip()
if not TOKEN:
    print("prune_stale_plans: CONFORMANCE_TOKEN absent - purge ignoree.")
    sys.exit(0)

headers = {"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"}
api = BASE + "api/plan"


def _client() -> httpx.Client:
    return httpx.Client(verify=True, timeout=60.0, headers=headers)


def _is_published(plan: dict) -> bool:
    # La suite marque les plans publies via 'published' (bool) ou
    # 'publicationStatus'. On reste defensif : tout ce qui n'est pas clairement
    # non publie est conserve (jamais de suppression douteuse).
    if plan.get("published") is True:
        return True
    status = str(plan.get("publicationStatus") or plan.get("status") or "").lower()
    if "publish" in status:
        return True
    # champs alternatifs observes dans certains builds OIDF
    for key in ("immutable", "locked"):
        if plan.get(key) is True:
            return True
    return False


def main() -> int:
    with _client() as client:
        # 1. lister tous les plans du user
        plans = []
        start = 0
        length = 500
        while True:
            r = client.get(api, params={"start": start, "length": length})
            if r.status_code != 200:
                print("prune: GET {} -> HTTP {} : {}".format(api, r.status_code, r.text[:200]))
                return 1
            data = r.json()
            rows = data.get("data") or data.get("plans") or []
            if not isinstance(rows, list) or not rows:
                break
            plans.extend(rows)
            if len(rows) < length:
                break
            start += length

        # 2. garder uniquement les plans de notre alias
        ours = [pl for pl in plans if str(pl.get("planName", "")).startswith(PREFIX)]
        print("prune: {} plan(s) total, {} de prefixe '{}'".format(len(plans), len(ours), PREFIX))

        # 3. grouper par planName, trier par started (ISO, desc)
        groups: dict[str, list[dict]] = {}
        for pl in ours:
            groups.setdefault(pl.get("planName", ""), []).append(pl)

        to_delete: list[tuple[str, str]] = []
        for name, group in groups.items():
            published = [p for p in group if _is_published(p)]
            unpublished = [p for p in group if not _is_published(p)]
            unpublished.sort(key=lambda p: str(p.get("started") or p.get("_id") or ""), reverse=True)
            keep = unpublished[:KEEP]
            drop = unpublished[KEEP:]
            print("prune: {:<55s} total={:3d} publies={:2d} gardes={:2d} a_supprimer={:2d}".format(
                name, len(group), len(published), len(keep), len(drop)))
            for pl in drop:
                to_delete.append((pl.get("_id"), name))

        # 4. supprimer (jamais un plan publie)
        deleted = 0
        skipped = 0
        for pid, name in to_delete:
            if not pid:
                continue
            durl = "{}/{}".format(api, pid)
            r = client.delete(durl)
            if r.status_code in (200, 202, 204):
                deleted += 1
                print("prune: supprime {} ({})".format(pid, name))
            elif r.status_code in (403, 404, 405, 409):
                # 405 : plan publie/immutable (l'API refuse deja). 404 : deja parti.
                skipped += 1
                print("prune: ignore {} ({}) - HTTP {} (plan conserve)".format(pid, name, r.status_code))
            else:
                print("prune: echec suppression {} ({}) - HTTP {} {}".format(
                    pid, name, r.status_code, r.text[:120]))
        print("prune: {} supprime(s), {} conserve(s) (publies/immuables).".format(deleted, skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
