"""Integração da Etapa 4: orquestração sobre uma pasta de fixtures."""

import tempfile
from pathlib import Path

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.orchestrator import run_verification

FIXTURES = Path(__file__).parent / "fixtures"

needs_tools = pytest.mark.skipif(
    resolve_tool("esbmc") is None or resolve_tool("jbmc") is None
    or resolve_tool("javac") is None,
    reason="esbmc/jbmc/javac indisponíveis",
)


def test_run_verification_cancel_early():
    """should_cancel=True para antes de compilar/verificar → cancelled, parcial.
    Não precisa de ferramentas (nenhuma compilação acontece)."""
    with tempfile.TemporaryDirectory() as build:
        rr = run_verification(str(FIXTURES), unwind=2, timeout=10, jobs=2,
                              build_root=build, should_cancel=lambda: True)
    assert rr.cancelled is True
    assert rr.targets == []
    assert rr.summary.get("total") == 0


@needs_tools
def test_run_verification_over_fixtures():
    with tempfile.TemporaryDirectory() as build:
        rr = run_verification(str(FIXTURES), unwind=2, timeout=60, jobs=2,
                              build_root=build)

    by_target = {t.target: t for t in rr.targets}

    # C: divisão por zero (BUG) e programa seguro (SAFE)
    assert by_target["div_by_zero.c"].status == "BUG"
    assert by_target["div_by_zero.c"].bug == "Division by Zero"
    assert by_target["div_by_zero.c"].explanation  # tem explicação
    assert by_target["safe_sum.c"].status == "SAFE"

    # Java: array fora dos limites (BUG)
    assert by_target["ArrayOob"].status == "BUG"
    assert by_target["ArrayOob"].bug == "Array Out Of Bounds"

    assert rr.summary["total"] == len(rr.targets)
    assert rr.summary["BUG"] >= 2


def _verifica_fonte(codigo: str, nome: str = "Main.java"):
    """Compila+verifica um único fonte em pasta e build isolados.

    Build isolado de propósito: `build_verify` é compartilhado entre execuções e
    já devolveu classes de runs anteriores (apareceram alvos que não estavam na
    pasta), o que poluiria a asserção.
    """
    with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as build:
        (Path(src) / nome).write_text(codigo, encoding="utf-8")
        rr = run_verification(src, unwind=5, timeout=120, jobs=1, build_root=build)
    return [t for t in rr.targets if t.source]


@needs_tools
def test_random_nextint_respeita_o_bound():
    """`java.util.Random` não é modelado pelo JBMC: `nextInt(5)` era havocado
    para um Int qualquer (o contraexemplo chegou a mostrar `r = 6`), e o
    verificador REJEITAVA o reparo correto `nextInt(arr.length)`."""
    alvos = _verifica_fonte("""
import java.util.Random;
public class Main {
  public static void main(String[] args) {
    int r = new Random().nextInt(5);
    assert r >= 0 && r < 5;
  }
}
""")
    assert [t.status for t in alvos] == ["SAFE"]


@needs_tools
def test_random_nextint_indexando_array_do_mesmo_tamanho():
    """O patch que o reparo propôs para o TC9 e que o BMC recusava."""
    alvos = _verifica_fonte("""
import java.util.Random;
public class Main {
  public static void main(String[] args) {
    int[] a = new int[5];
    a[new Random().nextInt(a.length)] = 1;
  }
}
""")
    assert [t.status for t in alvos] == ["SAFE"]


@needs_tools
def test_random_modelado_nao_esconde_bug_real():
    """Soundness: o modelo restringe a faixa, não silencia o defeito — índice
    de `nextInt(10)` num array de 5 continua estourando."""
    alvos = _verifica_fonte("""
import java.util.Random;
public class Main {
  public static void main(String[] args) {
    int[] a = new int[5];
    a[new Random().nextInt(10)] = 1;
  }
}
""")
    assert [t.status for t in alvos] == ["BUG"]
    assert alvos[0].bug == "Array Out Of Bounds"


@needs_tools
def test_random_bound_invalido_continua_lancando():
    """Fidelidade ao contrato: `nextInt(0)` lança IllegalArgumentException. Um
    `assume` incondicional no modelo tornaria este caminho inalcançável e
    esconderia o defeito — exatamente o tipo de 'reparo' que queremos barrar."""
    alvos = _verifica_fonte("""
import java.util.Random;
public class Main {
  public static void main(String[] args) {
    int n = 0;
    int r = new Random().nextInt(n);
  }
}
""")
    assert [t.status for t in alvos] == ["BUG"]
