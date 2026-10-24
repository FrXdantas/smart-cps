"""R2 (caso FreeRTOS #1236, 24/10/2026): tempo esgotado do próprio ESBMC é TIMEOUT.

A ferramenta passa --timeout ao ESBMC. Quando ele estoura, imprime "ERROR: Timed out"
e saía ERROR, na verificação (run b86a8a376929) e no oráculo do reparo (20/10). Só o
corte externo ("TIMEOUT:") virava TIMEOUT. Defeito achado antes do tempo continua BUG.
"""

from smart_jbmc.core import classify as cl
from smart_jbmc.core.process import ToolResult
from smart_jbmc.core.repair import regression

# Final REAL da saída do ESBMC 8.6.0 com --timeout 180 (com_bug do caso, concorrência).
SAIDA_TIMEOUT = """\
Solving with solver Boolector 3.2.4
Runtime decision procedure: 0.000s
Slicing time: 0.001s (removed 62 assignments)
ERROR: Timed out
"""

BUG_E_DEPOIS_TIMEOUT = """\
** Results:
  FAILED       [main.division-by-zero.1]                                    line   5  division by zero
ERROR: Timed out
"""


def test_timeout_do_esbmc_e_timeout():
    assert cl.classify(SAIDA_TIMEOUT).status == "TIMEOUT"


def test_bug_achado_antes_do_tempo_continua_bug():
    assert cl.classify(BUG_E_DEPOIS_TIMEOUT).status == "BUG"


def test_erro_de_verdade_continua_error():
    assert cl.classify("ERROR: PARSING ERROR\n").status == "ERROR"


def test_oraculo_timeout_do_esbmc_e_timeout(monkeypatch, tmp_path):
    fonte = tmp_path / "x.c"
    fonte.write_text("int main(){return 0;}")
    monkeypatch.setattr(regression, "run_esbmc", lambda *a, **k: ToolResult(1, SAIDA_TIMEOUT, ""))
    r = regression.regression_check(str(fonte), "Division by Zero", unwind=3, timeout=10)
    assert r.verdict == "TIMEOUT"
