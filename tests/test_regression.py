"""Integração da Etapa 3: o ciclo verifica → corrige → re-verifica (regressão).

Determinístico com ESBMC real, usando o fixture de divisão por zero:
  • patch correto      → FIX_OK
  • patch que não muda → STILL_VULNERABLE
"""

import os
import tempfile
from pathlib import Path

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.repair.heuristic import FIX_HEADER, build_fixed_source
from smart_jbmc.core.repair.regression import _extract_diagnostics, regression_check
from smart_jbmc.core.scanner import read_text

FIXTURES = Path(__file__).parent / "fixtures"
needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")


@needs_esbmc
def test_regression_fix_ok():
    src = read_text(str(FIXTURES / "c" / "div_by_zero.c"))
    fixed = build_fixed_source("Division by Zero", src, ".c")  # patch real
    with tempfile.TemporaryDirectory() as tmp:
        fp = os.path.join(tmp, "div_by_zero_FIXED.c")
        Path(fp).write_text(fixed, encoding="utf-8")
        res = regression_check(fp, "Division by Zero", unwind=2, timeout=60)
        assert res.verdict == "FIX_OK", res


@needs_esbmc
def test_regression_still_vulnerable():
    src = read_text(str(FIXTURES / "c" / "div_by_zero.c"))
    # Apenas cabeçalho, sem corrigir o código -> bug permanece.
    not_fixed = FIX_HEADER.format(
        bug="Division by Zero", cwe="CWE-369", cert="INT33-C", sug="x") + src
    with tempfile.TemporaryDirectory() as tmp:
        fp = os.path.join(tmp, "div_by_zero_FIXED.c")
        Path(fp).write_text(not_fixed, encoding="utf-8")
        res = regression_check(fp, "Division by Zero", unwind=2, timeout=60)
        assert res.verdict == "STILL_VULNERABLE", res


def test_extract_diagnostics_keeps_actionable_error():
    """Em ERROR, a LLM deve receber o diagnóstico real (não 'erro do verificador'),
    para conseguir corrigir — ex.: o caso INT_MAX sem #include <limits.h>."""
    raw = (
        "ESBMC version 8.2.0\n"
        "Parsing patch.c\n"
        "patch.c:25:13: error: use of undeclared identifier 'INT_MAX'\n"
        "   25 |     if (i > INT_MAX - j) {\n"
        "      |             ^~~~~~~\n"
        "ERROR: PARSING ERROR\n"
    )
    diag = _extract_diagnostics(raw)
    assert "INT_MAX" in diag and "error:" in diag
    assert "ESBMC version" not in diag        # ruído fica de fora
    assert diag != "erro do verificador"


def test_extract_diagnostics_fallback_when_no_error_lines():
    """Sem linhas de erro reconhecíveis, cai nas últimas linhas (melhor que vazio)."""
    raw = "linha um\nlinha dois\nlinha tres\n"
    diag = _extract_diagnostics(raw)
    assert "linha tres" in diag
