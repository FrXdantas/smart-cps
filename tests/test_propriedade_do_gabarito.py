"""RC4 dos corpora (frente 1 do plano da semana 5): verificar só a propriedade do gabarito."""

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.orchestrator import run_verification
from smart_jbmc.core.sarif import _esbmc_cmd_template
from smart_jbmc.core.verifiers.esbmc import checagens, concurrency_flags

needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")


def test_todas_e_o_comportamento_de_sempre():
    assert checagens(None) == checagens("todas") == ["--overflow", "--memory-leak-check"]
    assert concurrency_flags(True, True, "todas") == concurrency_flags(True, True)


def test_so_assercao_desliga_o_resto_e_a_corrida():
    f = checagens("assercao")
    assert "--no-standard-checks" in f and "--overflow" not in f and "--memory-leak-check" not in f
    assert "--no-assertions" not in f
    assert "--data-races-check" not in concurrency_flags(True, True, "assercao")


def test_so_corrida_liga_a_busca_sem_impasse_e_sem_assercoes():
    assert "--no-assertions" in checagens("corrida")
    fl = concurrency_flags(False, False, "corrida")
    assert "--data-races-check" in fl and "--deadlock-check" not in fl and "--sleep-sets" in fl


def test_so_estouro():
    assert checagens("estouro") == ["--no-standard-checks", "--no-assertions", "--overflow"]


def test_propriedade_invalida():
    with pytest.raises(ValueError):
        checagens("tudo")


def test_sarif_registra_as_flags_da_propriedade():
    cmd = _esbmc_cmd_template({"unwind": 3, "timeout": 60, "propriedade": "corrida",
                               "concurrency": True, "race_check": True})
    assert "--no-assertions" in cmd and "--data-races-check" in cmd and "--memory-leak-check" not in cmd


VAZA_E_FALHA = """#include <stdlib.h>
void reach_error(void){}
int nondet_int(void);
int main(void){
  int *p = malloc(sizeof(int));
  int x = nondet_int();
  if (x == 42) { reach_error(); __ESBMC_assert(0, "reach_error"); }
  return 0;
}
"""


@needs_esbmc
def test_vazamento_nao_esconde_a_assercao(tmp_path):
    """Caso do char_generic_nvram: em 'todas', o vazamento é achado e a run para nele;
    em 'assercao', aparece a falha que o gabarito espera."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "v.c").write_text(VAZA_E_FALHA, encoding="utf-8")
    kw = dict(unwind=2, timeout=60, jobs=1, concurrency=True, race_check=False)
    todas = run_verification(str(tmp_path / "src"), build_root=str(tmp_path / "b1"), **kw)
    so = run_verification(str(tmp_path / "src"), build_root=str(tmp_path / "b2"),
                          propriedade="assercao", **kw)
    assert todas.targets[0].bug == "Memory Leak"
    assert so.targets[0].status == "BUG" and so.targets[0].bug == "Assertion Failure"
    assert so.config["propriedade"] == "assercao"


def test_api_recusa_propriedade_invalida(tmp_path):
    from fastapi.testclient import TestClient

    from smart_jbmc.api.app import app
    r = TestClient(app).post("/api/runs", json={"folder": str(tmp_path), "propriedade": "tudo"})
    assert r.status_code == 400 and "propriedade" in r.json()["detail"]
