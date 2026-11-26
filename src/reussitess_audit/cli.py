"""Ligne de commande : reussitess-audit --path MON_PROJET."""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from .audit import ReussitessSecurityAudit


def construire_parser():
    p = argparse.ArgumentParser(
        prog="reussitess-audit",
        description="Audit de sécurité d'un projet (secrets exposés, permissions, injections, npm...).",
    )
    p.add_argument("--path", default=".", help="Dossier à auditer (défaut : dossier courant).")
    p.add_argument("--output-dir", default=".", help="Dossier où écrire le rapport JSON (défaut : dossier courant).")
    p.add_argument("--json", action="store_true", help="Affiche un résumé JSON à la fin.")
    return p


def main(argv=None):
    """Retourne 0 si le score est >= 80, 2 s'il est entre 60 et 79, 1 s'il est < 60, 3 si le dossier est introuvable."""
    args = construire_parser().parse_args(argv)
    cible = Path(args.path).resolve()
    if not cible.is_dir():
        print(f"Dossier introuvable : {cible}", file=sys.stderr)
        return 3
    sortie = Path(args.output_dir).resolve()
    sortie.mkdir(parents=True, exist_ok=True)

    avant = set(cible.glob("security_audit_*.json"))
    origine = Path.cwd()
    auditeur = ReussitessSecurityAudit()
    os.chdir(cible)
    try:
        score = auditeur.run_full_audit()
    finally:
        os.chdir(origine)

    if sortie != cible:
        for rapport in set(cible.glob("security_audit_*.json")) - avant:
            shutil.move(str(rapport), str(sortie / rapport.name))

    if args.json:
        r = auditeur.results
        print(json.dumps({
            "score": score,
            "critique": r["critical_count"],
            "haute": r["high_count"],
            "moyenne": r["medium_count"],
            "basse": r["low_count"],
        }, ensure_ascii=False))

    if score < 60:
        return 1
    if score < 80:
        return 2
    return 0


def run():
    sys.exit(main())
