"""RR1-RR3 (07/11/2026): resposta da LLM cortada no max_tokens.

Caso real: run 68afac98f883 (CMSIS-DSP arm_pid_q31, unidade de 20.608 caracteres).
Com max_tokens = 8000 fixo, as 5 respostas vieram cortadas no meio do arquivo e
foram ao oráculo como patch: ERROR nas 5 iterações.
"""

from smart_jbmc.core.repair import llm, repair_target


class _Resp:
    def __init__(self, body):
        self.status_code, self._b, self.headers, self.text = 200, body, {}, ""

    def json(self):
        return self._b


def _corpo(finish):
    return {"choices": [{"message": {"content": "int main(){return 0;}"},
                         "finish_reason": finish}],
            "usage": {"completion_tokens": 100}, "model": "m"}


# ---------- RR2: max_tokens pelo tamanho do arquivo ----------

def test_max_tokens_piso_para_arquivo_pequeno():
    assert llm.max_tokens_for("int main(){}") == llm.MAX_TOKENS_MIN


def test_max_tokens_cobre_a_unidade_do_cmsis():
    # 20.608 caracteres pedia mais que os 8.000 antigos
    n = llm.max_tokens_for("x" * 20608)
    assert n > 8000
    assert n >= 20608 * 3 // 4


def test_max_tokens_respeita_o_teto():
    assert llm.max_tokens_for("x" * 1_000_000) == llm.MAX_TOKENS_CAP


def test_generate_patch_manda_max_tokens_calculado(monkeypatch):
    visto = {}

    def fake_post(url, json=None, **kw):
        visto["max_tokens"] = json["max_tokens"]
        return _Resp(_corpo("stop"))

    monkeypatch.setattr(llm.requests, "post", fake_post)
    code = "x" * 20608
    llm.generate_patch(bug="x", cwe_info={}, cert_rule="", code=code,
                       counterexample="", lang="C",
                       base_url="http://localhost:11434/v1", api_key="k")
    assert visto["max_tokens"] == llm.max_tokens_for(code)


# ---------- RR1: finish_reason ----------

def test_generate_patch_sinaliza_truncada(monkeypatch):
    monkeypatch.setattr(llm.requests, "post", lambda url, **kw: _Resp(_corpo("length")))
    out = llm.generate_patch(bug="x", cwe_info={}, cert_rule="", code="c",
                             counterexample="", lang="C",
                             base_url="http://localhost:11434/v1", api_key="k")
    assert out["truncated"] is True


def test_generate_patch_resposta_completa_nao_truncada(monkeypatch):
    monkeypatch.setattr(llm.requests, "post", lambda url, **kw: _Resp(_corpo("stop")))
    out = llm.generate_patch(bug="x", cwe_info={}, cert_rule="", code="c",
                             counterexample="", lang="C",
                             base_url="http://localhost:11434/v1", api_key="k")
    assert out["truncated"] is False


def _alvo(tmp_path):
    src = tmp_path / "a.c"
    src.write_text("int main(void){int z=0; return 1/z;}\n", encoding="utf-8")
    return str(src)


def test_resposta_truncada_nao_vai_ao_oraculo(tmp_path, monkeypatch):
    """TRUNCATED não chama o oráculo (antes dava ERROR de compilação)."""
    chamadas = []
    monkeypatch.setattr("smart_jbmc.core.repair.loop.regression_check",
                        lambda *a, **k: chamadas.append(1))

    def cortada(**kw):
        return {"patch": "int main(void){int z", "usage": {"completion_tokens": kw["max_tokens"]},
                "model": "m", "ms": 10, "truncated": True}

    res = repair_target(source_path=_alvo(tmp_path), original_bug="Division by Zero",
                        counterexample="", unwind=2, timeout=5, max_iters=5, patch_fn=cortada)
    assert chamadas == []
    assert res.attempts and all(a["verdict"] == "TRUNCATED" for a in res.attempts)
    assert res.final_code is None   # o código cortado não vira "última proposta"


# ---------- RR3: não repetir o mesmo pedido ----------

def test_truncada_dobra_o_teto_e_para_no_maximo(tmp_path, monkeypatch):
    monkeypatch.setattr("smart_jbmc.core.repair.loop.regression_check",
                        lambda *a, **k: None)
    pedidos = []

    def cortada(**kw):
        pedidos.append(kw["max_tokens"])
        return {"patch": "x", "usage": None, "model": "m", "ms": 0, "truncated": True}

    res = repair_target(source_path=_alvo(tmp_path), original_bug="Division by Zero",
                        counterexample="", unwind=2, timeout=5, max_iters=10, patch_fn=cortada)
    # 8000 -> 16000 -> 32000 -> 32768 (teto) e para: nenhum pedido repetido
    assert pedidos == [8000, 16000, 32000, llm.MAX_TOKENS_CAP]
    assert len(set(pedidos)) == len(pedidos)
    assert res.status == "LLM_TRUNCATED"
    assert res.iterations == 4


def test_truncada_depois_completa_segue_para_o_oraculo(tmp_path):
    """Depois de dobrar o teto, a resposta completa segue o caminho normal."""
    respostas = iter([
        {"patch": "int main(void){int z", "usage": None, "model": "m", "ms": 0, "truncated": True},
        {"patch": "int main(void){int z=1; return 1/z;}\n", "usage": None, "model": "m",
         "ms": 0, "truncated": False},
    ])
    pedidos = []

    def fn(**kw):
        pedidos.append(kw["max_tokens"])
        return next(respostas)

    from smart_jbmc.core.config import resolve_tool
    if resolve_tool("esbmc") is None:
        import pytest
        pytest.skip("esbmc indisponível")
    res = repair_target(source_path=_alvo(tmp_path), original_bug="Division by Zero",
                        counterexample="", unwind=2, timeout=30, max_iters=3, patch_fn=fn)
    assert pedidos == [8000, 16000]
    assert res.attempts[0]["verdict"] == "TRUNCATED"
    assert res.status == "REPAIRED"


def test_resumo_conta_truncados():
    from smart_jbmc.core.repair.loop import _aggregate
    r = [{"status": "LLM_TRUNCATED", "original_bug": "Overflow", "iterations": 4, "attempts": []},
         {"status": "REPAIRED", "original_bug": "Overflow", "iterations": 1, "attempts": []}]
    s = _aggregate(r, 2)["summary"]
    assert s["truncated"] == 1
    assert s["not_repaired"] == 1   # truncado conta como não reparado
