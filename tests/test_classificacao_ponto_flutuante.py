"""Incremento 2 de A e B: categorias próprias para ponto flutuante e truncamento.

Antes, o estouro em float saía como "Overflow"/CWE-190 (de inteiro) e o NaN como
"Unknown Failure"/CWE-Other. Os casos de inteiro não podem mudar.
"""

import pytest

from smart_jbmc.core import classify as C
from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.orchestrator import run_verification

needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")

ESTOURO_FLOAT = """float nondet_float(void);
int main(void) {
  float ganho = nondet_float();
  __ESBMC_assume(ganho > 1e30f && ganho < 1e38f);
  float u = ganho * 1e10f;
  return u > 0;
}
"""

NAN = """float nondet_float(void);
int main(void) {
  float n = nondet_float();
  __ESBMC_assume(n >= 0.0f && n <= 4.0f);
  float erro = 0.0f;
  float media = erro / n;
  return media > 1.0f;
}
"""

ESTOURO_INT = """int nondet_int(void);
int main(void) { int a = nondet_int(); return a + 1; }
"""


def test_categorias_novas_tem_cwe_e_regra_cert():
    assert C.CWE_INFO["Float Overflow"]["cwe_id"] == "CWE-682"
    assert C.CWE_INFO["Float NaN"]["cwe_id"] == "CWE-682"
    assert C.CWE_INFO["Numeric Truncation"]["cwe_id"] == "CWE-197"
    assert C.CWE_INFO["Float Overflow"]["cert_rule"].startswith("FLP03-C")
    assert C.CWE_INFO["Float NaN"]["cert_rule"].startswith("FLP32-C")
    assert C.CWE_INFO["Numeric Truncation"]["cert_rule"].startswith("INT31-C")
    assert C.CWE_INFO["Overflow"]["cwe_id"] == "CWE-190"


def _verifica(tmp_path, nome, codigo, **kw):
    (tmp_path / nome).write_text(codigo)
    rr = run_verification(str(tmp_path), unwind=2, timeout=60, jobs=1,
                          build_root=str(tmp_path / "build"), **kw)
    return rr.targets[0]


@needs_esbmc
def test_estouro_em_float_nao_e_mais_cwe_190(tmp_path):
    t = _verifica(tmp_path, "ganho.c", ESTOURO_FLOAT)
    assert (t.status, t.bug, t.cwe_id) == ("BUG", "Float Overflow", "CWE-682")


@needs_esbmc
def test_nan_tem_categoria_propria(tmp_path):
    t = _verifica(tmp_path, "media.c", NAN, nan_check=True)
    assert (t.status, t.bug, t.cwe_id) == ("BUG", "Float NaN", "CWE-682")
    assert t.violation and t.violation.get("line") == 6


@needs_esbmc
def test_estouro_de_inteiro_continua_cwe_190(tmp_path):
    t = _verifica(tmp_path, "soma.c", ESTOURO_INT)
    assert (t.status, t.bug, t.cwe_id) == ("BUG", "Overflow", "CWE-190")
