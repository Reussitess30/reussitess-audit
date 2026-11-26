import json
from pathlib import Path

import pytest

from reussitess_audit import cli
from reussitess_audit.audit import ReussitessSecurityAudit


def test_etat_initial():
    a = ReussitessSecurityAudit()
    assert a.results["vulnerabilities"] == []
    assert a.results["critical_count"] == 0


@pytest.mark.parametrize("gravite,cle", [
    ("CRITICAL", "critical_count"),
    ("HIGH", "high_count"),
    ("MEDIUM", "medium_count"),
    ("LOW", "low_count"),
])
def test_add_vulnerability_compte_par_gravite(gravite, cle):
    a = ReussitessSecurityAudit()
    a.add_vulnerability("Titre", gravite, "Description", file="x.py")
    assert a.results[cle] == 1
    assert a.results["vulnerabilities"][0]["file"] == "x.py"


def test_score_et_rapport_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    a = ReussitessSecurityAudit()
    a.add_vulnerability("A", "CRITICAL", "d")
    a.add_vulnerability("B", "HIGH", "d")
    assert a.generate_report() == 85  # 100 - (10 + 5)
    rapports = list(tmp_path.glob("security_audit_*.json"))
    assert len(rapports) == 1
    contenu = json.loads(rapports[0].read_text(encoding="utf-8"))
    assert contenu["critical_count"] == 1


def test_score_ne_descend_pas_sous_zero(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    a = ReussitessSecurityAudit()
    for _ in range(20):
        a.add_vulnerability("X", "CRITICAL", "d")
    assert a.generate_report() == 0


def test_secret_en_clair_detecte(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.py").write_text('PASSWORD = "unfauxmotdepasse123"\n', encoding="utf-8")
    a = ReussitessSecurityAudit()
    a.test_secrets_exposure()
    assert len(a.results["vulnerabilities"]) >= 1


def test_dossier_propre_sans_secret(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "propre.py").write_text("print('bonjour')\n", encoding="utf-8")
    a = ReussitessSecurityAudit()
    a.test_secrets_exposure()
    assert a.results["vulnerabilities"] == []


@pytest.mark.parametrize("score,code", [(95, 0), (80, 0), (79, 2), (60, 2), (59, 1), (0, 1)])
def test_codes_de_sortie(tmp_path, monkeypatch, score, code):
    monkeypatch.setattr(ReussitessSecurityAudit, "run_full_audit", lambda self: score)
    assert cli.main(["--path", str(tmp_path), "--output-dir", str(tmp_path / "out")]) == code


def test_dossier_inexistant(tmp_path):
    assert cli.main(["--path", str(tmp_path / "absent")]) == 3


def test_revient_au_dossier_courant(tmp_path, monkeypatch):
    monkeypatch.setattr(ReussitessSecurityAudit, "run_full_audit", lambda self: 100)
    avant = Path.cwd()
    cli.main(["--path", str(tmp_path)])
    assert Path.cwd() == avant
