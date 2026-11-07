"""RR4 (07/11/2026): reparo por função quando o arquivo não cabe no teto de saída."""

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.repair import llm, repair_target
from smart_jbmc.core.repair import trecho as t

needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")

CODIGO = """#include <stdint.h>
/* comentario com { chave } */
static const char *msg = "texto com { chave";
struct par { int a; int b; };

int soma(int a, int b)
{
    return a + b;
}

int divide(int a,
           int b)
{
    if (a > 0) {
        return a / b;
    }
    return 0;
}

int main(void) { return divide(4, soma(0, 0)); }
"""


def test_acha_a_funcao_da_linha():
    linha = CODIGO.split("\n").index("        return a / b;") + 1
    ini, fim, nome = t.funcao_que_contem(CODIGO, linha)
    assert nome == "divide"
    trecho = t.extrair(CODIGO, ini, fim)
    assert trecho.startswith("int divide(int a,") and trecho.rstrip().endswith("}")
    assert "soma" not in trecho


def test_linha_fora_de_funcao():
    assert t.funcao_que_contem(CODIGO, 4) is None      # struct, não função


def test_recolocar_troca_so_a_funcao():
    linha = CODIGO.split("\n").index("        return a / b;") + 1
    ini, fim, _ = t.funcao_que_contem(CODIGO, linha)
    nova = "int divide(int a, int b)\n{\n    return b ? a / b : 0;\n}"
    out = t.recolocar(CODIGO, ini, fim, nova)
    assert "b ? a / b : 0" in out and "int soma(int a, int b)" in out and "int main" in out
    assert out.count("int divide") == 1


def test_precisa_trecho_pelo_teto(monkeypatch):
    assert not t.precisa_trecho(CODIGO)
    monkeypatch.setattr(llm, "MAX_TOKENS_CAP", 100)
    assert t.precisa_trecho(CODIGO)


@needs_esbmc
def test_arquivo_grande_vai_por_funcao(tmp_path, monkeypatch):
    src = tmp_path / "g.c"
    src.write_text("int nondet_int(void);\n" + CODIGO.replace("divide(4, soma(0, 0))",
                                                              "divide(4, nondet_int())"),
                   encoding="utf-8")
    texto = src.read_text()
    linha = texto.split("\n").index("        return a / b;") + 1
    monkeypatch.setattr(llm, "MAX_TOKENS_CAP", 100)           # força "não cabe"
    pedidos = []

    def fn(**kw):
        pedidos.append(kw)
        return {"patch": "int divide(int a,\n           int b)\n{\n    if (a > 0 && b != 0) {"
                         "\n        return a / b;\n    }\n    return 0;\n}\n",
                "usage": None, "model": "m", "ms": 0, "truncated": False}

    res = repair_target(source_path=str(src), original_bug="Division by Zero",
                        counterexample="", unwind=2, timeout=60, max_iters=1, patch_fn=fn,
                        linha_defeito=linha)
    assert res.modo == "funcao"
    assert pedidos[0]["code"].startswith("int divide") and "int main" not in pedidos[0]["code"]
    assert "divide (linhas" in pedidos[0]["trecho"]
    assert res.status == "REPAIRED"
    assert "int main" in res.final_code and "b != 0" in res.final_code


def test_resposta_que_nao_e_uma_funcao_e_recusada(tmp_path, monkeypatch):
    src = tmp_path / "g.c"
    src.write_text(CODIGO, encoding="utf-8")
    linha = CODIGO.split("\n").index("        return a / b;") + 1
    monkeypatch.setattr(llm, "MAX_TOKENS_CAP", 100)
    monkeypatch.setattr("smart_jbmc.core.repair.loop.regression_check",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("não deveria verificar")))

    def fn(**kw):
        return {"patch": CODIGO, "usage": None, "model": "m", "ms": 0, "truncated": False}

    res = repair_target(source_path=str(src), original_bug="Division by Zero",
                        counterexample="", unwind=2, timeout=5, max_iters=1, patch_fn=fn,
                        linha_defeito=linha)
    assert res.attempts[0]["verdict"] == "INVALID_PATCH"


def test_prompt_do_trecho():
    m = llm._messages("Overflow", {}, "", "int f(void){}", "cex", "C", None, None, None,
                      file_name="a.c", trecho="f (linhas 3 a 5 de 900)")
    assert "Devolva SOMENTE esta função" in m[1]["content"]


INVOLUCRO = """void reach_error(void){}
void __VERIFIER_assert(int cond)
{
    if (!cond) { reach_error(); }
}
int filtro(int x)
{
    int y = x * 2;
    __VERIFIER_assert(y < 100);
    return y;
}
int main(void) { return filtro(70); }
"""


def test_rr4_sobe_do_involucro_de_assert_pela_pilha():
    pilha = [{"funcao": "__VERIFIER_assert", "linha": 9, "chamador": "filtro"},
             {"funcao": "filtro", "linha": 12, "chamador": "main"},
             {"funcao": "main", "linha": 12, "chamador": None}]
    assert t.funcao_que_contem(INVOLUCRO, 4)[2] == "__VERIFIER_assert"
    assert t.funcao_do_defeito(INVOLUCRO, 4, pilha)[2] == "filtro"
    assert t.funcao_do_defeito(INVOLUCRO, 4, None)[2] == "__VERIFIER_assert"
