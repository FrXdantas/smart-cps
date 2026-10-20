"""Testes do motor portado (Etapa 2): unitários + integração com verificadores.

Os testes de integração são pulados automaticamente se a ferramenta externa
não estiver disponível (resolvida via .env / tools/ / PATH).
"""

import tempfile
from pathlib import Path

import pytest

from smart_jbmc.core import classify as C
from smart_jbmc.core.compiler import compile_java
from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.scanner import scan
from smart_jbmc.core.verifiers import run_esbmc, run_jbmc

FIXTURES = Path(__file__).parent / "fixtures"


# ----------------------------------------------------------------------
# Unitários (sempre rodam)
# ----------------------------------------------------------------------

def test_cert_priority():
    assert C.cert_priority("Null Pointer") == (18, "L1")
    assert C.cert_priority("Division by Zero") == (9, "L2")
    assert C.cert_priority("Memory Leak") == (4, "L3")


@pytest.mark.parametrize("text,expected", [
    ("division by zero detected", "Division by Zero"),
    ("dereference failure: NULL", "Null Pointer"),
    ("array bounds violated in foo", "Array Out Of Bounds"),
    ("dynamic memory leak found", "Memory Leak"),
    ("use after free of pointer p", "Use After Free"),
    ("arithmetic overflow on add", "Overflow"),
    # direção B: textos reais do ESBMC 8.2.0 (20/10/2026)
    ("arithmetic overflow on floating-point ieee_mul", "Float Overflow"),
    ("arithmetic overflow on floating-point ieee_div", "Float Overflow"),
    ("NaN on ieee_div", "Float NaN"),
    ("fixed-point truncation: value does not fit in q15_t", "Numeric Truncation"),
])
def test_detect_bug(text, expected):
    assert C.detect_bug(text) == expected


def test_has_failure_and_error():
    assert C.has_failure("VERIFICATION FAILED")
    assert C.has_failure('"status": "failure"')
    assert not C.has_failure("VERIFICATION SUCCESSFUL")
    assert C.has_error("ERROR: parsing failed")
    assert not C.has_error("tudo certo")


def test_classify_bug_and_safe():
    bug = C.classify("VERIFICATION FAILED\nViolated property: division by zero")
    assert bug.status == "BUG"
    assert bug.bug == "Division by Zero"
    assert bug.cwe_info["cwe_id"] == "CWE-369"

    safe = C.classify("VERIFICATION SUCCESSFUL")
    assert safe.status == "SAFE"
    assert safe.bug is None


def test_classify_unknown_on_unwinding_only():
    """Modo sound: quando SÓ falham unwinding assertions (bound insuficiente),
    o veredito é UNKNOWN — nem SAFE vacuamente verdadeiro nem BUG falso."""
    only_unwind = (
        "✗ FAILED: 'unwinding assertion loop 3 at file x.c line 13'\n"
        "VERIFICATION FAILED\n"
    )
    v = C.classify(only_unwind)
    assert v.status == "UNKNOWN"
    assert v.bug is None


def test_classify_real_failure_wins_over_unwinding():
    """Falha real + unwinding assertion ⇒ BUG (o contraexemplo prevalece)."""
    mixed = (
        "✗ FAILED: 'dereference failure: NULL pointer at x.c line 5'\n"
        "✗ FAILED: 'unwinding assertion loop 3 at x.c line 13'\n"
        "VERIFICATION FAILED\n"
    )
    v = C.classify(mixed)
    assert v.status == "BUG"
    assert v.bug == "Null Pointer"


def test_split_failures_separates_unwinding():
    real, unwind = C._split_failures(
        "✗ FAILED: 'array bounds violated at a.c line 9'\n"
        "✗ FAILED: 'unwinding assertion loop 2 at a.c line 4'\n"
    )
    assert len(real) == 1 and len(unwind) == 1


def test_classify_explicit_unknown_verdict():
    """k-induction / incremental-bmc emitem veredito explícito de inconclusão."""
    assert C.classify("VERIFICATION UNKNOWN").status == "UNKNOWN"
    assert C.classify(
        "The forward condition is unable to prove the property\n"
        "Unable to prove or falsify the program, giving up.\n"
        "VERIFICATION UNKNOWN"
    ).status == "UNKNOWN"


def test_scan_finds_fixtures():
    java, kt, c = scan(str(FIXTURES))
    assert any(f.endswith("ArrayOob.java") for f in java)
    assert any(f.endswith("div_by_zero.c") for f in c)
    assert any(f.endswith("safe_sum.c") for f in c)


# ----------------------------------------------------------------------
# Integração (pula se a ferramenta não estiver disponível)
# ----------------------------------------------------------------------

needs_esbmc = pytest.mark.skipif(
    resolve_tool("esbmc") is None, reason="esbmc indisponível")
needs_jbmc = pytest.mark.skipif(
    resolve_tool("jbmc") is None or resolve_tool("javac") is None,
    reason="jbmc/javac indisponíveis")


@needs_esbmc
def test_esbmc_detects_div_by_zero():
    res = run_esbmc(str(FIXTURES / "c" / "div_by_zero.c"), unwind=2, timeout=60)
    verdict = C.classify(res.raw)
    assert verdict.status == "BUG"
    assert verdict.bug == "Division by Zero"


@needs_esbmc
def test_esbmc_safe_program():
    res = run_esbmc(str(FIXTURES / "c" / "safe_sum.c"), unwind=2, timeout=60)
    verdict = C.classify(res.raw)
    assert verdict.status == "SAFE"


@needs_esbmc
def test_esbmc_function_entry_havocs_args():
    """`--function`: verifica uma função SEM main como ponto de entrada, com os
    args havocados — acha a div-by-zero em `risky(x)` quando x==0."""
    res = run_esbmc(str(FIXTURES / "c" / "func_entry.c"), unwind=2, timeout=60,
                    function="risky")
    verdict = C.classify(res.raw)
    assert verdict.status == "BUG"
    assert verdict.bug == "Division by Zero"


@needs_jbmc
def test_jbmc_estrategias_bounded_vs_sound():
    """As estratégias da via JVM, no laço que NÃO cabe no bound.

    `bounded` (padrão) responde SAFE — garantia válida só até o bound; `sound`
    mantém as unwinding assertions e responde UNKNOWN em vez de SAFE vacuamente
    verdadeiro. Antes de 2026-07-26 a via JVM não tinha estratégia: rodava sempre
    com as unwinding assertions ligadas E classificava a assertion violada como
    BUG/Assertion Failure — falso positivo em programa correto.
    """
    with tempfile.TemporaryDirectory() as tmp:
        comp = compile_java([str(FIXTURES / "java" / "LoopBound.java")], tmp)
        assert comp.returncode == 0, comp.raw

        res = run_jbmc("LoopBound", classpath=tmp, unwind=2, timeout=60,
                       strategy="bounded")
        assert C.classify(res.raw, C.safe_json(res.raw)).status == "SAFE"

        res = run_jbmc("LoopBound", classpath=tmp, unwind=2, timeout=60,
                       strategy="sound")
        v = C.classify(res.raw, C.safe_json(res.raw))
        assert v.status == "UNKNOWN", f"esperado UNKNOWN, veio {v.status}/{v.bug}"

        # o bound suficiente resolve nas duas estratégias
        res = run_jbmc("LoopBound", classpath=tmp, unwind=15, timeout=60,
                       strategy="sound")
        assert C.classify(res.raw, C.safe_json(res.raw)).status == "SAFE"


@needs_jbmc
def test_jbmc_detects_array_oob():
    with tempfile.TemporaryDirectory() as tmp:
        comp = compile_java([str(FIXTURES / "java" / "ArrayOob.java")], tmp)
        assert comp.returncode == 0, comp.raw
        res = run_jbmc("ArrayOob", classpath=tmp, unwind=2, timeout=60)
        verdict = C.classify(res.raw)
        assert verdict.status == "BUG"
        assert verdict.bug == "Array Out Of Bounds"


# Resumo REAL do ESBMC 8.6.0 (--multi-property, concorrência) sobre sensor_atuador.c com
# corrida: o 8.6 lista também as propriedades APROVADAS, entre elas "array bounds" e
# "out of bounds" do modelo de pthread. Só as linhas FAILED podem decidir a categoria.
ESBMC_86_RESUMO_CORRIDA = """\
** Results:
sensor_atuador.c, function tarefa_atuador
  PASSED       [tarefa_atuador.data-race.1]                line  15  R/W data race on c:@leitura
  FAILED       [tarefa_atuador.data-race.3]                line  16  R/W data race on c:@amostras
  FAILED       [tarefa_atuador.data-race.4]                line  16  W/W data race on c:@amostras
  PASSED       [tarefa_atuador.arithmetic-overflow.2]      line  16  arithmetic overflow on add
/esbmc-vfs/libc/library/pthread_lib.c, function pthread_create
  PASSED       [pthread_create.object-out-of-bounds.1]     line 273  dereference failure: Access to object out of bounds
  PASSED       [soma_notas.array-bounds-violated.1]        line  15  dereference failure: array bounds violated

** 2 of 18 properties failed, 16 passed

VERIFICATION FAILED
"""


def test_esbmc_86_resumo_classifica_so_pelas_que_falharam():
    from smart_jbmc.core.classify import detect_bug, has_failure
    assert has_failure(ESBMC_86_RESUMO_CORRIDA)
    assert detect_bug(ESBMC_86_RESUMO_CORRIDA) == "Race Condition"
