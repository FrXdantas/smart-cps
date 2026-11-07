"""Grupos do experimento (07/11/2026): B (stack trace), D (LLM puro) e o executor.

Decisões de 07/11: B = ponto da falha + cadeia de chamadas, sem valores; D = a LLM
só vê o código, detecta e propõe correção numa chamada, conferida depois pelo BMC
só para registro; opções de verificação por conjunto, iguais em todos os braços.
"""

import csv
import importlib.util
import json
from pathlib import Path

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.counterexample import (cadeia_de_chamadas, explain_counterexample,
                                            stack_trace_text)
from smart_jbmc.core.repair import llm, llm_puro, repair_run
from smart_jbmc.core.repair.loop import _next_cex

needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")

STEPS = [
    {"state": 1, "file": "a.c", "line": 3, "function": "main", "assigns": ["n = 7"]},
    {"state": 2, "file": "a.c", "line": 9, "function": "media", "assigns": ["d = 0"]},
    {"state": 3, "file": "a.c", "line": 10, "function": "__ESBMC_main", "assigns": []},
    {"state": 4, "file": "a.c", "line": 12, "function": "divide", "assigns": ["b = 0"]},
]
VIOL = [{"file": "a.c", "line": 12, "description": "division by zero", "condition": "b != 0",
         "cwe_esbmc": ""}]


# ---------- B: stack trace ----------

def test_cadeia_mais_recente_primeiro_sem_internas():
    assert cadeia_de_chamadas(STEPS, VIOL) == ["divide", "media", "main"]


def test_stack_trace_sem_valores_e_sem_condicao():
    t = stack_trace_text("Division by Zero", STEPS, VIOL)
    assert "linha 12" in t and "em divide" in t and "em main" in t
    assert "b = 0" not in t and "d = 0" not in t       # nenhum valor
    assert "b != 0" not in t                           # nem a condição


def test_estruturado_tem_o_que_o_b_nao_tem():
    c = explain_counterexample("Division by Zero", STEPS, VIOL)
    assert "b = 0" in c and "b != 0" in c


class _Reg:
    verdict, reason = "STILL_VULNERABLE", None
    raw = ("State 4 file a.c line 12 column 3 function divide thread 0\n"
           "----------------------------------------------------\n  b = 0\n\n"
           "Violated property:\n  file a.c line 12 column 3 function divide\n"
           "  division by zero\n  b != 0\n")


def test_realimentacao_do_b_continua_sem_valores():
    b = _next_cex(_Reg(), ".c", "Division by Zero", "stack_trace")
    c = _next_cex(_Reg(), ".c", "Division by Zero", "estruturado")
    assert "b = 0" not in b and "em divide" in b
    assert "b = 0" in c


def test_repair_run_entrega_stack_trace_ao_b(tmp_path):
    src = tmp_path / "a.c"
    src.write_text("int main(void){int z=0; return 1/z;}\n", encoding="utf-8")
    vistos = []

    def fn(**kw):
        vistos.append(kw["counterexample"])
        return {"patch": "x", "usage": None, "model": "m", "ms": 0, "truncated": True}

    alvo = {"status": "BUG", "source": str(src), "bug": "Division by Zero",
            "explanation": "COM VALORES", "stack_trace": "SO A PILHA"}
    repair_run([alvo], unwind=2, timeout=5, max_iters=1, patch_fn=fn, cex_mode="stack_trace")
    repair_run([alvo], unwind=2, timeout=5, max_iters=1, patch_fn=fn)
    assert vistos == ["SO A PILHA", "COM VALORES"]


# ---------- D: LLM puro ----------

RESPOSTA_D = ('Análise.\n```json\n{"defeito": true, "cwe": "CWE-369", "linha": 1, '
              '"justificativa": "divisão por z=0"}\n```\n```c\nint main(void){int z=1; '
              'return 1/z;}\n```\n')


def test_d_interpreta_resposta():
    r = llm_puro.interpretar(RESPOSTA_D)
    assert r["defeito"] is True and r["cwe"] == "CWE-369" and r["linha"] == 1
    assert "z=1" in r["codigo"] and not r["formato_invalido"]


def test_d_sem_defeito_ignora_codigo():
    r = llm_puro.interpretar('```json\n{"defeito": false, "cwe": null, "linha": null}\n```')
    assert r["defeito"] is False and r["codigo"] is None


def test_d_formato_invalido_nao_explode():
    assert llm_puro.interpretar("acho que tem bug")["formato_invalido"] is True


def test_d_prompt_so_tem_o_codigo():
    msgs = llm_puro.mensagens("int main(void){return 0;}", "a.c")
    user = msgs[1]["content"]
    assert "1| int main" in user
    assert "CWE" not in user and "contraexemplo" not in user.lower()


def test_d_resposta_truncada_descarta_codigo(monkeypatch):
    monkeypatch.setattr(llm, "chat", lambda *a, **k: {
        "content": RESPOSTA_D, "usage": None, "model": "m", "ms": 1, "truncated": True})
    assert llm_puro.detectar_e_corrigir("int main(){}", api_key="k")["codigo"] is None


# ---------- executor ----------

def _executor():
    p = Path(__file__).resolve().parent.parent / "tools" / "executar_bracos.py"
    spec = importlib.util.spec_from_file_location("executar_bracos", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_criterio_estrito_igual_ao_do_delta4():
    ex = _executor()
    assert ex.classificar("BUG", "CWE-617", "com_bug", "CWE-617") == "TP"
    assert ex.classificar("BUG", "CWE-401", "com_bug", "CWE-617") == "TP_cwe_errada"
    assert ex.classificar("TIMEOUT", None, "sem_bug", "") == "INCONCLUSIVO"
    assert ex.classificar("BUG", "CWE-617", "sem_bug", "") == "FP"


def test_amostra_deterministica_e_balanceada():
    ex = _executor()
    linhas = [{"arquivo": f"com_bug/{i}.c", "gabarito": "com_bug"} for i in range(10)] + \
             [{"arquivo": f"sem_bug/{i}.c", "gabarito": "sem_bug"} for i in range(10)]
    a = ex.selecionar(linhas, 4, "0")
    assert a == ex.selecionar(linhas, 4, "0")
    assert sum(r["gabarito"] == "com_bug" for r in a) == 2 and len(a) == 4


@needs_esbmc
def test_executor_ponta_a_ponta_com_llm_falsa(tmp_path, monkeypatch):
    """A detecta, B e C reparam o mesmo alvo com contextos diferentes, D registra."""
    corp = tmp_path / "corpora" / "C_aritmetica"
    (corp / "com_bug").mkdir(parents=True)
    (corp / "sem_bug").mkdir()
    (corp / "com_bug" / "div.c").write_text(
        "int nondet_int(void);\nint main(void){int z = nondet_int();\n"
        "  if (z > 5) z = 0;\n  return 100 / z;\n}\n", encoding="utf-8")
    (corp / "sem_bug" / "ok.c").write_text("int main(void){int z=2; return 100/z;}\n",
                                           encoding="utf-8")
    with open(corp / "gabarito.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["arquivo", "gabarito", "categoria_esperada", "cwe_esperada", "origem",
                    "elo_cps", "observacao"])
        w.writerow(["com_bug/div.c", "com_bug", "Division by Zero", "CWE-369", "t", "t", ""])
        w.writerow(["sem_bug/ok.c", "sem_bug", "", "", "t", "t", ""])

    ex = _executor()
    monkeypatch.setitem(ex.CONFIG_POR_CONJUNTO, "C_aritmetica",
                        dict(unwind=2, timeout=60, jobs=1, concurrency=False, race_check=False))
    contextos = []
    correto = "int nondet_int(void);\nint main(void){int z = nondet_int();\n" \
              "  if (z > 5 || z == 0) z = 1;\n  return 100 / z;\n}\n"

    def fake_chat(messages, **kw):
        user = messages[-1]["content"]
        if "revisor de código C" in messages[0]["content"]:      # grupo D
            return {"content": '```json\n{"defeito": true, "cwe": "CWE-369", "linha": 4}\n```\n'
                               f"```c\n{correto}```\n" if "div" in user or "z > 5" in user else
                               '```json\n{"defeito": false, "cwe": null, "linha": null}\n```',
                    "usage": {"completion_tokens": 10}, "model": "m", "ms": 5,
                    "truncated": False}
        contextos.append(user)
        return {"content": correto, "usage": {"completion_tokens": 10}, "model": "m",
                "ms": 5, "truncated": False}

    monkeypatch.setattr(llm, "chat", fake_chat)
    monkeypatch.setenv("SMART_LLM_API_KEY", "k")
    saida = tmp_path / "saida"
    ex.main(["--corpora", str(tmp_path / "corpora"), "--saida", str(saida),
             "--conjuntos", "C_aritmetica"])

    def ler(n):
        with open(saida / "C_aritmetica" / n, newline="", encoding="utf-8") as f:
            return {r["arquivo"]: r for r in csv.DictReader(f)}

    a = ler("A.csv")
    assert a["com_bug/div.c"]["estrito"] == "TP" and a["sem_bug/ok.c"]["estrito"] == "TN"
    assert ler("B.csv")["com_bug/div.c"]["status"] == "REPAIRED"
    assert ler("C.csv")["com_bug/div.c"]["status"] == "REPAIRED"
    d = ler("D.csv")
    assert d["com_bug/div.c"]["deteccao"] == "TP" and d["com_bug/div.c"]["bmc_registro"] == "FIX_OK"
    assert d["sem_bug/ok.c"]["deteccao"] == "TN"
    # B recebeu a pilha, C recebeu os valores: só o contexto muda entre os braços
    assert len(contextos) == 2
    assert "Pilha de chamadas" in contextos[0] and "Valores que levaram" not in contextos[0]
    assert "Pilha de chamadas" not in contextos[1]
    meta = json.loads((saida / "meta.json").read_text(encoding="utf-8"))
    assert meta["conjuntos"]["C_aritmetica"]["programas"] and "fim" in meta
    assert "api_key" not in json.dumps(meta)                 # chave não gravada
    # retomada: rodar de novo não duplica linhas
    ex.main(["--corpora", str(tmp_path / "corpora"), "--saida", str(saida),
             "--conjuntos", "C_aritmetica"])
    assert len(ler("B.csv")) == 1 and len(contextos) == 2


SAIDA_ESBMC86 = """[Counterexample]

State 1 file st.c line 4 column 18 function main thread 0
----------------------------------------------------
  n = 0 (00000000 00000000 00000000 00000000)

State 2 file st.c line 2 column 28 function divide thread 0
----------------------------------------------------
Violated property:
  file st.c line 2 column 28 function divide
Stack trace:
  c:@F@divide at file st.c line 3 column 34 function media
  c:@F@media at file st.c line 4 column 65 function main
  c:@F@main at file st.c line 4 column 1
  division by zero
  CWE: CWE-369
  b != 0


VERIFICATION FAILED
"""


def test_b_usa_a_pilha_real_do_esbmc():
    """--show-stacktrace traz a pilha com o local de cada chamada; a função `media`
    nem aparece como estado do traço, e a aproximação a perderia."""
    from smart_jbmc.core.counterexample import parse_esbmc_trace_text
    steps, viol = parse_esbmc_trace_text(SAIDA_ESBMC86)
    assert viol[0]["description"] == "division by zero" and viol[0]["condition"] == "b != 0"
    assert [q["funcao"] for q in viol[0]["pilha"]] == ["divide", "media", "main"]
    t = stack_trace_text("Division by Zero", steps, viol)
    assert "em divide, chamada por media na linha 3" in t
    assert "em media, chamada por main na linha 4" in t
    assert "n = 0" not in t and "b != 0" not in t
