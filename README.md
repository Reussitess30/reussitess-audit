# reussitess-audit

Outil en ligne de commande qui audite un projet web ou Node.js et donne un score de sécurité sur 100.

## Ce qu'il vérifie (10 contrôles)

Processus exposés, secrets écrits en clair, permissions de fichiers, injections de code, vulnérabilités npm, journaux sensibles, endpoints d'API, protection des appels à l'IA, sécurité des bases de données, CORS et en-têtes HTTP.

## Installation

    python3 -m venv .venv && . .venv/bin/activate
    pip install -e ".[dev]"

## Utilisation

    reussitess-audit --path MON_PROJET --output-dir rapports --json

Un rapport `security_audit_AAAAMMJJ_HHMMSS.json` est écrit dans le dossier de sortie.

## Score et code de sortie

Score = 100 − (10 × critiques + 5 × hautes + 2 × moyennes + 1 × basses), minimum 0.

| Score | Code de sortie |
|---|---|
| 80 ou plus | 0 |
| 60 à 79 | 2 |
| moins de 60 | 1 |
| dossier introuvable | 3 |

Le code de sortie permet de faire échouer une chaîne d'intégration continue quand le score est trop bas.

## Limites

La détection repose sur des motifs de recherche : elle peut signaler de faux positifs et ne remplace pas un audit humain. À utiliser sur vos propres projets.

## Tests

    python -m pytest -q
