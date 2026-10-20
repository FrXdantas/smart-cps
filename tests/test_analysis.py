"""Testes unitários da Etapa 3: contraexemplo, explicação, métricas, reparo heurístico."""

from pathlib import Path

from smart_jbmc.core import metrics as M
from smart_jbmc.core.classify import suggestion
from smart_jbmc.core.counterexample import (explain_counterexample, parse_esbmc_trace_text,
                                            parse_jbmc_trace_json)
from smart_jbmc.core.repair.heuristic import build_fixed_source, fixed_source

FIXTURES = Path(__file__).parent / "fixtures"
# Trace REAL do JBMC 6.9.0 (--json-ui --stop-on-fail) sobre fixtures/java/ArrayOob.java,
# capturado uma vez e versionado: o parser é testado contra o arquivo, sem invocar o
# JBMC (que constrói o trace consumindo memória sem limite — ver verifiers/jbmc.py).
JBMC_TRACE = FIXTURES / "traces" / "jbmc_arrayoob_trace.json"

ESBMC_SAMPLE = """\
State 1 file foo.c line 2 column 5 function main thread 0
----------------------------------------------------
  y = 0 (00000000 00000000 00000000 00000000)

State 2 file foo.c line 3 column 5 function main thread 0
----------------------------------------------------
Violated property:
  file foo.c line 3 column 5 function main
  division by zero
  y != 0

VERIFICATION FAILED
"""


def test_parse_esbmc_trace():
    steps, violations = parse_esbmc_trace_text(ESBMC_SAMPLE)
    assert any("y = 0" in a for st in steps for a in st["assigns"])
    assert violations
    assert violations[-1]["description"] == "division by zero"
    assert violations[-1]["condition"] == "y != 0"
    assert violations[-1]["line"] == 3


# Saída REAL do ESBMC (--multi-property --show-stacktrace) sobre exemplos/c/notas.c:
# o defeito está fora do `main`, então vem o bloco "Stack trace:" no meio.
ESBMC_STACKTRACE_SAMPLE = """\
State 1 file notas.c line 15 column 9 function soma_notas thread 0
----------------------------------------------------
Violated property:
  file notas.c line 15 column 9 function soma_notas
Stack trace:
  c:@F@soma_notas at file notas.c line 22 column 16 function main
  c:@F@main at file notas.c line 20 column 1
  dereference failure: array bounds violated
  !overflow("+", soma, notas[(signed long int)i])

Slicing time: 0.000s (removed 3 assignments)

State 1 file notas.c line 15 column 9 function soma_notas thread 0
----------------------------------------------------
Violated property:
  file notas.c line 15 column 9 function soma_notas
Stack trace:
  c:@F@soma_notas at file notas.c line 22 column 16 function main
  c:@F@main at file notas.c line 20 column 1
  arithmetic overflow on add

VERIFICATION FAILED
"""


def test_parse_esbmc_trace_com_stacktrace():
    _, violations = parse_esbmc_trace_text(ESBMC_STACKTRACE_SAMPLE)
    assert [v["line"] for v in violations] == [15, 15]
    assert violations[0]["description"] == "dereference failure: array bounds violated"
    assert violations[1]["description"] == "arithmetic overflow on add"
    assert violations[1]["condition"] == ""


# Saída REAL do ESBMC 8.6.0 (--nan-check --multi-property --show-stacktrace): a partir
# do 8.6 vem uma linha "CWE: ..." entre a descrição e a condição.
ESBMC_86_CWE_SAMPLE = """\
State 3 file nan.c line 2 column 63 function main thread 0
----------------------------------------------------
Violated property:
  file nan.c line 2 column 63 function main
Stack trace:
  c:@F@main at file nan.c line 2 column 1
  NaN on ieee_div
  CWE: CWE-681
  !(isnan(IEEE_DIV(0.000000, (float)n)))

BMC program time: 0.016s

VERIFICATION FAILED
"""


def test_parse_esbmc_86_linha_cwe_nao_vira_condicao():
    _, violations = parse_esbmc_trace_text(ESBMC_86_CWE_SAMPLE)
    v = violations[-1]
    assert v["description"] == "NaN on ieee_div"
    assert v["condition"] == "!(isnan(IEEE_DIV(0.000000, (float)n)))"
    assert v["cwe_esbmc"] == "CWE-681"


def test_parse_esbmc_82_sem_linha_cwe():
    _, violations = parse_esbmc_trace_text(ESBMC_SAMPLE)
    assert violations[-1]["cwe_esbmc"] == ""


def test_explain_prefere_violacao_do_bug():
    """Com várias violações, a explicação ancora na do bug classificado, não na última."""
    _, violations = parse_esbmc_trace_text(ESBMC_STACKTRACE_SAMPLE)
    text = explain_counterexample("Array Out Of Bounds", [], violations)
    assert "array bounds violated" in text
    assert "arithmetic overflow on add" not in text


def test_explain_counterexample():
    _, violations = parse_esbmc_trace_text(ESBMC_SAMPLE)
    text = explain_counterexample("Division by Zero", [], violations)
    assert "divisor vale 0" in text
    assert "Ponto exato da violação" in text
    assert "y != 0" in text


def test_parse_jbmc_trace():
    """O contraexemplo do JBMC chega parseado, na mesma forma do ESBMC."""
    steps, violations = parse_jbmc_trace_json(JBMC_TRACE.read_text())

    assert violations, "nenhuma violação extraída do trace do JBMC"
    v = violations[-1]
    assert v["file"] == "ArrayOob.java"
    assert v["line"] == 6                     # linha do acesso arr[i]
    assert v["description"] == "Array index should be < length"
    assert v["condition"] == "array-index-out-of-bounds-high"

    # os dois valores que explicam o bug: índice 5 sobre um array de tamanho 2
    assigns = [a for st in steps for a in st["assigns"]]
    assert "i = 5" in assigns
    assert any(a.endswith(".length = 2") for a in assigns)
    # ...e nada do plumbing do modelo da JVM
    assert not any("@class_identifier" in a or "nondet_" in a for a in assigns)
    assert all(st["file"] == "ArrayOob.java" for st in steps)


def test_parse_jbmc_trace_aceita_objeto_e_lixo():
    """Aceita objeto já parseado; entrada inválida degrada para vazio, não estoura."""
    import json
    obj = json.loads(JBMC_TRACE.read_text())
    steps, violations = parse_jbmc_trace_json(obj)
    assert steps and violations
    assert parse_jbmc_trace_json("saída que não é JSON") == ([], [])
    assert parse_jbmc_trace_json("") == ([], [])


def test_explain_counterexample_jvm_tem_valores():
    """A explicação da via JVM passa a ter ponto exato + valores (antes: só o
    parágrafo genérico da categoria)."""
    steps, violations = parse_jbmc_trace_json(JBMC_TRACE.read_text())
    text = explain_counterexample("Array Out Of Bounds", steps, violations)
    assert "Ponto exato da violação" in text
    assert "ArrayOob.java, linha 6" in text
    assert "Valores que levaram à violação" in text
    assert "i = 5" in text


def test_detect_bug_uncaught_exception():
    """`require()`/`check()` do Kotlin violam a propriedade 'no uncaught exception'.

    Antes caía em Unknown Failure/CWE-Other — sem CWE para a LLM citar no reparo.
    O assert explícito continua tendo prioridade quando as duas aparecem.
    """
    from smart_jbmc.core.classify import CWE_INFO, detect_bug
    assert detect_bug("no uncaught exception java::MainKt.main:()V.1") == "Uncaught Exception"
    assert CWE_INFO["Uncaught Exception"]["cwe_id"] == "CWE-248"
    # não sequestra os casos de assert (categoria ASF do Benchmark v4)
    assert detect_bug("assertion at file main.kt line 7 ... .assertion.1") == "Assertion Failure"
    assert detect_bug("assertion ... no uncaught exception ...") == "Assertion Failure"


def test_parse_jbmc_filtra_ruido_do_kotlin():
    """Artefatos do kotlinc não podem ocupar as poucas linhas de contraexemplo."""
    def passo(lhs, valor="0"):
        return {"stepType": "assignment", "hidden": False, "internal": False,
                "lhs": lhs, "value": {"data": valor},
                "sourceLocation": {"file": "main.kt", "line": "7"}}

    trace = {
        "status": "failed", "description": "no uncaught exception",
        "property": "java::MainKt.main:()V.1",
        "trace": [
            passo("$i$a$-require-MainKt$divide$1"),      # lambda inline
            passo("anonlocal::2a", "java.lang.String.Literal.x"),  # frame sem debug info
            passo("this", "java.lang.String.Literal.x"),
            passo("return_tmp2", "null"),
            passo("stub_ignored_arg1"),
            passo("d", "0"),                              # <- o único que importa
        ],
    }
    steps, _ = parse_jbmc_trace_json([trace])
    assigns = [a for st in steps for a in st["assigns"]]
    assert assigns == ["d = 0"], assigns


def test_castle_score():
    results = [
        {"oracle": "vuln", "bug": "Division by Zero", "n_findings": 1},  # TP
        {"oracle": "safe", "bug": None, "n_findings": 0},                # TN
        {"oracle": "safe", "bug": "Overflow", "n_findings": 1},          # FP
        {"oracle": "vuln", "bug": None, "n_findings": 0},                # FN
        {"oracle": None, "bug": "X"},                                    # ignorado
    ]
    m = M.castle_score(results)
    assert (m["tp"], m["tn"], m["fp"], m["fn"]) == (1, 1, 1, 1)
    assert m["castle_score"] == 7
    assert m["precision"] == 0.5 and m["recall"] == 0.5 and m["accuracy"] == 0.5


def test_aggregate_cwe_and_oracle():
    dist = M.aggregate_cwe([{"bug": "Division by Zero"}, {"bug": "Overflow"}, {"bug": None}])
    assert dist["CWE-369"] == 1 and dist["CWE-190"] == 1
    assert M.infer_oracle_from_path("/x/safe/a.c") == "safe"
    assert M.infer_oracle_from_path("/x/bug/a.c") == "vuln"
    assert M.infer_oracle_from_path("/x/a.c") is None


def test_oracle_convencao_pt_br():
    """Os corpora daqui usam com_bug//sem_bug/, não bug//safe/ — durante meses
    o gabarito existia no caminho e era ignorado, zerando a matriz de confusão."""
    assert M.infer_oracle_from_path("/u/codigo_java/com_bug/Foo.java") == "vuln"
    assert M.infer_oracle_from_path("/u/codigo_java/sem_bug/Foo.java") == "safe"
    assert M.infer_oracle_from_path("/u/com_bug/ClassCastException1/Main.java") == "vuln"
    assert M.infer_oracle_from_path("/u/codigo_java/common/Util.java") is None
    # "sem_bug" contém "bug": casar por substring inverteria o gabarito.
    assert M.infer_oracle_from_path("/u/sem_bug/a.java") != "vuln"
    # o nome do ARQUIVO não vale: quem manda é a pasta.
    assert M.infer_oracle_from_path("/u/com_bug/Foo_FIXED.java") == "vuln"


def test_metricas_sem_gabarito_sao_nulas():
    """Sem gabarito não há matriz: 0.0 seria lido como 'errou tudo'."""
    m = M.castle_score([{"oracle": None, "bug": "X"}, {"oracle": None, "bug": None}])
    assert m["n_avaliados"] == 0 and m["n_total"] == 2
    assert m["precision"] is None and m["recall"] is None
    assert m["accuracy"] is None and m["castle_score"] is None


def test_suggestion():
    assert "denominador" in suggestion("Division by Zero")


def test_heuristic_patches():
    div = fixed_source("Division by Zero", "int z = x / y;", ".c")
    assert "!= 0" in div and "?" in div

    arr = fixed_source("Array Out Of Bounds", "v = a[i];", ".c")
    assert ".length" in arr

    leak = build_fixed_source("Memory Leak", "int *p = malloc(4);", ".c")
    assert "TODO" in leak and "CWE-401" in leak
