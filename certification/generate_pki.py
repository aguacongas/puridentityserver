#!/usr/bin/env python3
"""Genere les PKI commises dans le depot pour les plans oid4vci (issue #304).

Deux fichiers JSON (PEM) sont produits dans ``certification/pki/`` :

- ``mdoc-iaca.json`` : l'IACA seule du format ``mso_mdoc`` (profil ISO
  18013-5 Table B.1), contact de documentation fixe et invariable d'un
  environnement a l'autre - c'est cette IACA qui devient
  ``credential.trust_anchor_pem`` du plan ``oid4vci-mdoc.json`` et qui est
  rechargee au boot par ``mdoc_pki_path`` (le document signer est reminte
  a chaque demarrage avec le contact de l'emetteur courant) ;
- ``credential-pki.json`` : la PKI d'emission SD-JWT (racine RSA + leaf),
  dont la racine devient ``credential.trust_anchor_pem`` du plan
  ``oid4vci.json`` et est rechargee au boot par ``credential_pki_path``.

Les PEM affiches sur stdout servent a alimenter les deux plans (champs
``credential.trust_anchor_pem`` et ``credential.status_list_trust_anchor_pem``,
ce dernier en simple presence : aucun claim ``status`` n'est emis).

Usage (depuis la racine du depot) :

    uv run python certification/generate_pki.py           # genere ce qui manque
    uv run python certification/generate_pki.py --force   # regenere tout

Un fichier deja present n'est jamais regenere sans ``--force`` : son PEM est
celui qui figure dans les plans, il doit donc rester stable.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.serialization import Encoding

from puridentityserver.infrastructure.credential_pki import (
    FileCredentialPKIRepository,
    generate_credential_pki,
)
from puridentityserver.infrastructure.mdoc import generate_mdoc_iaca
from puridentityserver.infrastructure.mdoc_storage import FileMdocPKIRepository

#: Contact de documentation de l'IACA commise : valeur fixe, identique en
#: local et sur l'instance hebergee, pour que le PEM des plans corresponde
#: exactement a l'ancre rechargee par ``mdoc_pki_path``.
MDOC_IACA_CONTACT = "https://op.puridentityserver.example.org"

#: Dossier des artefacts PKI commis.
PKI_DIR = Path(__file__).resolve().parent / "pki"


def _write(path: Path, content: str, force: bool) -> bool:
    """Ecrit un fichier s'il manque (ou si ``force``) ; ``True`` si ecrit."""
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def main(argv: list[str] | None = None) -> int:
    """Genere les PKI de certification absentes et affiche leurs PEM.

    Args:
        argv: arguments de ligne de commande (defaut : ``sys.argv``).

    Returns:
        Code retour du processus (0).
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="regenere meme les fichiers existants (a reboucher dans les plans)",
    )
    args = parser.parse_args(argv)

    PKI_DIR.mkdir(parents=True, exist_ok=True)

    iaca_path = PKI_DIR / "mdoc-iaca.json"
    iaca_repo = FileMdocPKIRepository(iaca_path)
    iaca = iaca_repo.load()
    if iaca is None or args.force:
        iaca = generate_mdoc_iaca(MDOC_IACA_CONTACT)
        iaca_repo.save(iaca)
        print(f"IACA mdoc generee : {iaca_path}", file=sys.stderr)
    else:
        print(f"IACA mdoc deja presente : {iaca_path}", file=sys.stderr)
    iaca_pem = iaca.certificate.public_bytes(cast(Encoding, Encoding.PEM)).decode("ascii")
    _write(PKI_DIR / "mdoc-iaca.pem", iaca_pem, args.force)

    credential_path = PKI_DIR / "credential-pki.json"
    credential_repo = FileCredentialPKIRepository(credential_path)
    credential_pki = credential_repo.load()
    if credential_pki is None or args.force:
        credential_pki = generate_credential_pki()
        credential_repo.save(credential_pki)
        print(f"PKI credential generee : {credential_path}", file=sys.stderr)
    else:
        print(f"PKI credential deja presente : {credential_path}", file=sys.stderr)
    root_pem = credential_pki.trust_anchor_pem
    _write(PKI_DIR / "credential-root.pem", root_pem, args.force)

    print("credential.trust_anchor_pem du plan oid4vci-mdoc.json (IACA) :")
    print(iaca_pem)
    print("credential.trust_anchor_pem du plan oid4vci.json (racine credential) :")
    print(root_pem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
