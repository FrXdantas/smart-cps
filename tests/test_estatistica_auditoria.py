"""E4 (07/11/2026): testes estatísticos e auditoria dupla, conferidos contra valores de referência."""

import csv
import importlib.util
from pathlib import Path

T = Path(__file__).resolve().parent.parent / "tools"


def _mod(nome):
    spec = importlib.util.spec_from_file_location(nome, T / f"{nome}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


est = _mod("estatistica_experimento")
aud = _mod("auditoria_experimento")


def test_clopper_pearson_referencia():
    lo, hi = est.clopper_pearson(5, 10)
    assert round(lo, 4) == 0.1871 and round(hi, 4) == 0.8129
    assert round(est.clopper_pearson(0, 20)[1], 4) == 0.1684


def test_mcnemar_exato_referencia():
    assert round(est.mcnemar_exato(10, 2), 4) == 0.0386
    assert est.mcnemar_exato(0, 0) == 1.0


def test_wilcoxon_com_empates():
    assert abs(est.wilcoxon_pareado([1] * 8 + [-1, 0]) - 0.0233) < 0.001


def test_holm():
    assert est.holm({"a": 0.01, "b": 0.04, "c": 0.03}) == {"a": 0.03, "c": 0.06, "b": 0.06}


def test_kappa_referencia():
    assert aud.kappa_cohen(["a", "a", "b", "b"], ["a", "b", "b", "b"]) == 0.5


def _csv(p, cols, linhas):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(linhas)


def test_rq1_rq4_contam_pares_b_c(tmp_path):
    r = lambda a, s: {"arquivo": a, "status": s}  # noqa: E731
    _csv(tmp_path / "C_aritmetica" / "B.csv", ["arquivo", "status"],
         [r("x", "NOT_REPAIRED"), r("y", "REPAIRED")])
    _csv(tmp_path / "C_aritmetica" / "C.csv", ["arquivo", "status"],
         [r("x", "REPAIRED"), r("y", "REPAIRED")])
    _csv(tmp_path / "A2_corrida" / "B.csv", ["arquivo", "status"], [r("z", "REPAIRED")])
    _csv(tmp_path / "A2_corrida" / "C.csv", ["arquivo", "status"], [r("z", "NOT_REPAIRED")])
    assert est.pares_bc(tmp_path) == dict(so_C=1, so_B=1, ambos=1, nenhum=0)
    assert est.pares_bc(tmp_path, "ponto_fixo") == dict(so_C=1, so_B=0, ambos=1, nenhum=0)


def test_auditoria_gera_e_calcula(tmp_path):
    s = tmp_path
    (s / "trabalho" / "C_aritmetica" / "A" / "com_bug").mkdir(parents=True)
    (s / "trabalho" / "C_aritmetica" / "A" / "com_bug" / "p.c").write_text("a\n")
    (s / "C_aritmetica" / "patches" / "C" / "com_bug").mkdir(parents=True)
    (s / "C_aritmetica" / "patches" / "C" / "com_bug" / "p.c").write_text("b\n")
    _csv(s / "C_aritmetica" / "C.csv", ["arquivo", "status", "patch", "bug"],
         [{"arquivo": "com_bug/p.c", "status": "REPAIRED",
           "patch": "C_aritmetica/patches/C/com_bug/p.c", "bug": "Overflow"}])
    assert aud.gerar(s) == 1
    planilha = s / "auditoria" / "auditoria.csv"
    linhas = list(csv.DictReader(open(planilha, encoding="utf-8")))
    assert "+b" in (s / "auditoria" / linhas[0]["diff"]).read_text()
    for nome, cl in (("a1.csv", "reparo_real"), ("a2.csv", "reparo_real")):
        _csv(s / "auditoria" / nome, aud.COLS, [{**linhas[0], "classificacao": cl}])
    assert aud.kappa(s / "auditoria" / "a1.csv", s / "auditoria" / "a2.csv") == 1.0
    fin = list(csv.DictReader(open(s / "auditoria" / "auditoria_final.csv", encoding="utf-8")))
    assert fin[0]["final"] == "reparo_real"


def test_auditoria_cega_e_solo(tmp_path):
    linhas = [dict(id=str(i), conjunto="X", arquivo=f"com_bug/p{i}.c", bug="Overflow",
                   braco=b, diff=f"diffs/{i:03d}.diff", classificacao="", observacao="")
              for i, b in enumerate("BBCC", 1)]
    orig = tmp_path / "auditoria.csv"
    _csv(orig, aud.COLS, linhas)
    copia = tmp_path / "autor.csv"
    assert aud.cega(orig, copia) == 4
    lidas = list(csv.DictReader(open(copia, encoding="utf-8")))
    assert "braco" not in lidas[0]
    for r, cl in zip(lidas, ("contorno", "reparo_real", "reparo_real", "")):
        r["classificacao"] = cl
    _csv(copia, list(lidas[0].keys()), lidas)
    res = aud.solo(orig, copia)
    assert res["B"][:2] == (1, 2) and res["C"][:2] == (0, 1) and res["total"][:2] == (1, 3)
    assert 0.0 < res["total"][2] < res["total"][3] < 1.0
