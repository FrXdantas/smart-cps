"""Etapa 6: loop de reparo guiado por contraexemplo.

- dry-run (stub devolve o código original) -> NOT_REPAIRED (exercita a realimentação).
- patch_fn 'fake' que aplica o fix heurístico correto -> REPAIRED (caminho de sucesso).
Ambos usam ESBMC real como oráculo.
"""

from pathlib import Path

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.repair import llm, repair_run, repair_target
from smart_jbmc.core.repair.heuristic import fixed_source

FIXTURES = Path(__file__).parent / "fixtures"
DIV = str(FIXTURES / "c" / "div_by_zero.c")
needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")


def test_repair_run_incremental_skips_repaired():
    """only_unrepaired reaproveita os já REPARADOS (sem tocar LLM/BMC) e faz
    checkpoint por alvo."""
    targets = [
        {"status": "BUG", "source": "/x/a.c", "bug": "Overflow"},
        {"status": "BUG", "source": "/x/b.c", "bug": "Division by Zero"},
    ]
    prior = [
        {"source": "/x/a.c", "status": "REPAIRED", "original_bug": "Overflow",
         "iterations": 1, "attempts": []},
        {"source": "/x/b.c", "status": "REPAIRED", "original_bug": "Division by Zero",
         "iterations": 2, "attempts": []},
    ]
    seen = []
    res = repair_run(targets, unwind=2, timeout=5, dry_run=True,
                     prior_results=prior, only_unrepaired=True,
                     on_checkpoint=lambda agg: seen.append(agg["summary"]["total"]))
    # ambos reaproveitados -> 2 REPAIRED sem reprocessar; checkpoint por alvo
    assert res["summary"]["repaired"] == 2
    assert res["summary"]["total"] == 2
    assert len(seen) == 2
    assert all(t["status"] == "REPAIRED" for t in res["targets"])


def test_repair_run_cancel_stops_early():
    """should_cancel=True para o laço antes de processar qualquer alvo e
    marca o agregado como cancelled (não precisa de ferramentas)."""
    targets = [
        {"status": "BUG", "source": "/x/a.c", "bug": "Overflow"},
        {"status": "BUG", "source": "/x/b.c", "bug": "Division by Zero"},
    ]
    res = repair_run(targets, unwind=2, timeout=5, dry_run=True,
                     should_cancel=lambda: True)
    assert res["cancelled"] is True
    assert res["summary"]["total"] == 2      # 2 bugs eram candidatos
    assert res["summary"]["repaired"] == 0   # nenhum chegou a ser processado
    assert res["targets"] == []


def test_repair_target_cancel_skips_verification(tmp_path):
    """Cancelamento DENTRO de um alvo (laço interno): após o LLM responder, pula
    a re-verificação BMC, marca cancelled e não precisa de ferramentas."""
    src = tmp_path / "a.c"
    src.write_text("int main(void){int y=0;return 1/y;}\n", encoding="utf-8")
    state = {"n": 0}

    def should_cancel():
        state["n"] += 1
        return state["n"] >= 2   # False no topo do iter1, True logo após o LLM

    def fake_fix(**kw):
        return {"patch": kw["code"], "usage": None, "model": "fake", "ms": 0}

    res = repair_target(source_path=str(src), original_bug="Division by Zero",
                        counterexample="", unwind=2, timeout=5, max_iters=3,
                        patch_fn=fake_fix, should_cancel=should_cancel)
    assert res.cancelled is True
    assert res.attempts == []     # quebrou antes de registrar/verificar a tentativa


def test_repair_run_incremental_progress_counts_remaining(tmp_path, monkeypatch):
    """No modo incremental, o progresso usa como denominador os alvos QUE FALTAM
    (não o total de bugs): 1 reaproveitado + 1 a fazer => total do progresso = 1."""
    done_f = tmp_path / "done.c"; done_f.write_text("int main(){return 0;}\n", encoding="utf-8")
    todo_f = tmp_path / "todo.c"; todo_f.write_text("int main(){return 1/0;}\n", encoding="utf-8")
    targets = [
        {"status": "BUG", "source": str(done_f), "bug": "X"},
        {"status": "BUG", "source": str(todo_f), "bug": "Division by Zero"},
    ]
    prior = [{"source": str(done_f), "status": "REPAIRED", "original_bug": "X",
              "iterations": 1, "attempts": [], "final_code": "int main(){return 0;}\n"}]

    def boom(**kw):   # evita precisar de ferramentas; o que importa é o denominador
        raise llm.LLMRateLimited("x")
    monkeypatch.setattr(llm, "generate_patch", boom)

    totals = []
    repair_run(targets, unwind=2, timeout=5, prior_results=prior, only_unrepaired=True,
               on_progress=lambda d, total, i, n, tok_s=None: totals.append(total))
    assert totals, "on_progress não foi chamado"
    assert set(totals) == {1}   # denominador = 1 (o que falta), não 2 (total de bugs)


def test_generate_patch_dry_run_offline():
    out = llm.generate_patch(bug="Division by Zero", cwe_info={}, cert_rule="INT33-C",
                             code="int main(){return 1/0;}", counterexample="y=0",
                             lang="C", dry_run=True)
    assert out["patch"] == "int main(){return 1/0;}"
    assert out["model"] == "dry-run"


class _Resp:
    def __init__(self, code, body=None, headers=None):
        self.status_code, self._b = code, body or {}
        self.headers, self.text = headers or {}, "rate limit"

    def json(self):
        return self._b


def test_generate_patch_retries_then_succeeds(monkeypatch):
    """429 transitório: retenta com backoff e tem sucesso (sem dormir de verdade)."""
    calls = {"n": 0}
    ok = {"choices": [{"message": {"content": "int main(){return 0;}"}}],
          "usage": {"completion_tokens": 5}, "model": "m"}

    def fake_post(url, **kw):
        calls["n"] += 1
        return _Resp(429) if calls["n"] < 3 else _Resp(200, ok)

    monkeypatch.setattr(llm.requests, "post", fake_post)
    monkeypatch.setattr("time.sleep", lambda *a: None)
    out = llm.generate_patch(bug="x", cwe_info={}, cert_rule="", code="c",
                             counterexample="", lang="C",
                             base_url="http://localhost:11434/v1", api_key="k")
    assert calls["n"] == 3          # 2 falhas (429) + 1 sucesso
    assert "int main" in out["patch"]


def test_generate_patch_raises_rate_limited_after_retries(monkeypatch):
    """429 persistente: esgota os retries e levanta LLMRateLimited (não genérico)."""
    monkeypatch.setattr(llm.requests, "post", lambda url, **kw: _Resp(429))
    monkeypatch.setattr("time.sleep", lambda *a: None)
    monkeypatch.setattr(llm, "DEFAULT_LLM_MAX_RETRIES", 2)
    with pytest.raises(llm.LLMRateLimited):
        llm.generate_patch(bug="x", cwe_info={}, cert_rule="", code="c",
                           counterexample="", lang="C",
                           base_url="http://localhost:11434/v1", api_key="k")


def test_repair_target_rate_limit_is_provider_error(tmp_path):
    """429 (após retries) vira status PROVIDER_ERROR no alvo — NÃO 'ERROR' de reparo."""
    src = tmp_path / "a.c"
    src.write_text("int main(void){return 1/0;}\n", encoding="utf-8")

    def boom(**kw):
        raise llm.LLMRateLimited("HTTP 429 (cota)")

    res = repair_target(source_path=str(src), original_bug="Division by Zero",
                        counterexample="", unwind=2, timeout=5, max_iters=3, patch_fn=boom)
    assert res.status == "PROVIDER_ERROR"
    assert res.attempts[0]["verdict"] == "PROVIDER_ERROR"


def test_repair_run_provider_errors_excluded_from_metrics(tmp_path, monkeypatch):
    """Erros de provedor (429) ficam FORA do denominador: não contam como não-reparado."""
    a = tmp_path / "a.c"; a.write_text("int main(void){return 1/0;}\n", encoding="utf-8")
    b = tmp_path / "b.c"; b.write_text("int main(void){return 2/0;}\n", encoding="utf-8")

    def boom(**kw):
        raise llm.LLMRateLimited("HTTP 429")

    monkeypatch.setattr(llm, "generate_patch", boom)
    targets = [{"status": "BUG", "source": str(a), "bug": "Division by Zero"},
               {"status": "BUG", "source": str(b), "bug": "Division by Zero"}]
    s = repair_run(targets, unwind=2, timeout=5)["summary"]
    assert s["provider_errors"] == 2
    assert s["repaired"] == 0
    assert s["not_repaired"] == 0     # rate-limit não polui as métricas de reparo
    assert s["attempted"] == 0


@needs_esbmc
def test_repair_dry_run_not_repaired():
    res = repair_target(source_path=DIV, original_bug="Division by Zero",
                        counterexample="divisor y = 0", unwind=2, timeout=30,
                        max_iters=2, dry_run=True)
    assert res.status == "NOT_REPAIRED"
    assert res.iterations == 2
    assert all(a["verdict"] == "STILL_VULNERABLE" for a in res.attempts)


@needs_esbmc
def test_repair_repaired_with_fake_patcher(tmp_path):
    def fake_fix(**kw):
        return {"patch": fixed_source(kw["bug"], kw["code"], ".c"),
                "usage": None, "model": "fake", "ms": 0}

    # Copia o fonte para tmp para que o _FIXED entregue ao lado caia em tmp,
    # não em tests/fixtures/ (e valida a opção A: entrega ao lado do original).
    src = tmp_path / "div_by_zero.c"
    src.write_text(Path(DIV).read_text(encoding="utf-8"), encoding="utf-8")

    res = repair_target(source_path=str(src), original_bug="Division by Zero",
                        counterexample="divisor y = 0", unwind=2, timeout=30,
                        max_iters=3, patch_fn=fake_fix)
    assert res.status == "REPAIRED"
    assert res.iterations == 1
    assert res.attempts[0]["verdict"] == "FIX_OK"
    assert res.fixed_path and Path(res.fixed_path).exists()
    # opção A: a cópia _FIXED foi gravada ao lado do original, sem sobrescrevê-lo
    assert res.origin_fixed_path == str(tmp_path / "div_by_zero_FIXED.c")
    assert Path(res.origin_fixed_path).exists()
    assert src.exists()  # original intacto


@needs_esbmc
def test_repair_attempt_reports_tok_s(tmp_path):
    """A velocidade de geração (tok/s) é calculada a partir de usage+ms do provedor."""
    def fake_fix(**kw):
        return {"patch": fixed_source(kw["bug"], kw["code"], ".c"),
                "usage": {"completion_tokens": 100}, "model": "fake", "ms": 500}

    src = tmp_path / "div_by_zero.c"
    src.write_text(Path(DIV).read_text(encoding="utf-8"), encoding="utf-8")
    res = repair_target(source_path=str(src), original_bug="Division by Zero",
                        counterexample="divisor y = 0", unwind=2, timeout=30,
                        max_iters=2, patch_fn=fake_fix)
    a = res.attempts[0]
    assert a["tokens"] == 100
    assert a["tok_s"] == 200.0   # 100 tokens / 0,5 s


# --- normalização de compilação: ensure_c_headers (opção 3) ---
from smart_jbmc.core.repair.loop import _write_beside_source, ensure_c_headers  # noqa: E402


def test_write_beside_source_keeps_original(tmp_path):
    """Grava <stem>_FIXED<ext> ao lado do fonte, sem tocar no original."""
    src = tmp_path / "alvo.c"
    src.write_text("original\n", encoding="utf-8")
    dest = _write_beside_source(str(src), "corrigido\n")
    assert dest == str(tmp_path / "alvo_FIXED.c")
    assert Path(dest).read_text(encoding="utf-8") == "corrigido\n"
    assert src.read_text(encoding="utf-8") == "original\n"  # original intacto


def test_ensure_c_headers_injects_limits():
    """INT_MAX sem <limits.h> -> o include é prepended (caso recorrente do 14B)."""
    code = "int main(){ if (x > INT_MAX - 1) return 1; return 0; }"
    out = ensure_c_headers(code)
    assert "#include <limits.h>" in out
    assert out.strip().startswith("#include <limits.h>")


def test_ensure_c_headers_idempotent():
    """Não duplica um include já presente."""
    code = "#include <limits.h>\nint main(){ return INT_MAX; }"
    out = ensure_c_headers(code)
    assert out.count("#include <limits.h>") == 1


def test_ensure_c_headers_skips_when_unused():
    """Sem símbolo da stdlib, nada é injetado."""
    code = "int main(){ return 0; }"
    assert ensure_c_headers(code) == code


def test_ensure_c_headers_respects_custom_bool():
    """Não injeta <stdbool.h> se o programa define o próprio bool (evita conflito)."""
    code = "typedef int bool;\nint main(){ bool b = 1; return b; }"
    assert "#include <stdbool.h>" not in ensure_c_headers(code)


# --- guardas contra patch que engana o oráculo em vez de reparar -------------
# Todos os casos REJEITADOS abaixo foram gerados de verdade pela LLM e ACEITOS
# como REPARADO antes destas guardas; os ACEITOS também são patches reais.

from smart_jbmc.core.repair.loop import _validate_patch  # noqa: E402


def test_guarda_rejeita_assercao_reescrita_para_passar():
    """`assert false` -> `assert true`: a guarda antiga contava asserções e
    deixava passar, porque a quantidade não mudou."""
    orig = "public class M {\n  void f() {\n    assert false;\n  }\n}"
    patch = "public class M {\n  void f() {\n    assert true; // corrigido\n  }\n}"
    assert _validate_patch(patch, orig, ".java", set()) is not None


def test_guarda_rejeita_invariante_ajustada_ao_codigo():
    """Mudar `== 44` para `== 43` conserta a especificação, não o programa."""
    orig = "fun main() {\n    val n = add(1)\n    assert(n == 44)\n}"
    patch = "fun main() {\n    val n = add(1)\n    assert(n == 43) // <--- corrigido\n}"
    assert _validate_patch(patch, orig, ".kt", set()) is not None


def test_guarda_rejeita_assume_novo():
    """`assume` encolhe o espaço de estados até o defeito sair dele — em
    SV-COMP é trapaça explícita."""
    orig = "int main(){ int n = nondet(); int a[n]; return 0; }"
    patch = "int main(){ int n = nondet(); assume_abort_if_not(n >= 0); int a[n]; return 0; }"
    assert _validate_patch(patch, orig, ".c", set()) is not None


def test_guarda_aceita_reparo_legitimo_da_logica():
    """A função se chama `fourty_two` e devolvia 41: o defeito é o código, e a
    asserção fica intacta."""
    orig = "fun fourty_two(): Int { return 41 }\nfun main(){ assert(fourty_two() == 42) }"
    patch = "fun fourty_two(): Int { return 42 }\nfun main(){ assert(fourty_two() == 42) }"
    assert _validate_patch(patch, orig, ".kt", set()) is None


def test_guarda_aceita_restricao_de_indice_na_origem():
    """O patch do TC9, que o BMC recusava por não modelar `Random.nextInt`."""
    orig = "fun main(){\n val a = IntArray(5)\n val i = Random().nextInt(100)\n a[i] = 2\n}"
    patch = "fun main(){\n val a = IntArray(5)\n val i = Random().nextInt(a.size) // corrigido\n a[i] = 2\n}"
    assert _validate_patch(patch, orig, ".kt", set()) is None


def test_guarda_ignora_comentario_do_reparo_na_linha_do_assert():
    """A LLM anota `// <--- corrigido aqui` na linha; isso não pode contar como
    asserção alterada."""
    orig = "fun main() {\n    assert(x == 1)\n}"
    patch = "fun main() {\n    assert(x == 1) // <--- corrigido aqui: nada mudou\n}"
    assert _validate_patch(patch, orig, ".kt", set()) is None


# --- guarda semântica: o ponto do defeito ainda executa? ---------------------

import os      # noqa: E402
import tempfile  # noqa: E402

from smart_jbmc.core.repair.loop import repair_target  # noqa: E402
from smart_jbmc.core.repair import reachability  # noqa: E402

needs_jvm = pytest.mark.skipif(
    resolve_tool("jbmc") is None or resolve_tool("javac") is None,
    reason="jbmc/javac indisponíveis",
)

_DIV_ZERO = """public class Main {
  public static void main(String[] args) {
    int x = 1;
    int y = 0;
    int z = x / y;
  }
}
"""


def _repara_com(patch: str, linha_defeito=5):
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "Main.java")
        with open(p, "w", encoding="utf-8") as f:
            f.write(_DIV_ZERO)
        return repair_target(
            source_path=p, original_bug="Division by Zero",
            counterexample="linha 5", unwind=5, timeout=120, solver="boolector",
            max_iters=1,
            patch_fn=lambda **kw: {"patch": patch, "ms": 1, "model": "fake"},
            work_dir=d, unit_sources=[p], entry_class="Main",
            linha_defeito=linha_defeito)


@needs_jvm
def test_rejeita_patch_que_torna_o_defeito_inalcancavel():
    """O BMC aprova código morto — e está certo, código morto não viola nada.
    Mas o programa perdeu o comportamento: não é reparo."""
    r = _repara_com("""public class Main {
  public static void main(String[] args) {
    int x = 1;
    int y = 0;
    if (y == 0) return; // <--- corrigido aqui: guard
    int z = x / y;
  }
}
""")
    assert r.status == "NOT_REPAIRED"
    assert [a["verdict"] for a in r.attempts] == ["INVALID_PATCH"]


@needs_jvm
def test_aceita_patch_que_mantem_o_ponto_executando():
    """Contraprova: mesmo defeito, patch que corrige o dado. A instrução do
    defeito continua executando, então a guarda não interfere."""
    r = _repara_com("""public class Main {
  public static void main(String[] args) {
    int x = 1;
    int y = 2; // <--- corrigido aqui
    int z = x / y;
  }
}
""")
    assert r.status == "REPAIRED"


def test_guarda_se_abstem_quando_a_linha_do_defeito_foi_reescrita():
    """Reparo legítimo costuma reescrever a própria linha do defeito. Sem
    correspondência única, a guarda devolve None e o patch segue aceito —
    falso positivo aqui rejeitaria reparo bom, o pior erro possível."""
    orig = "fun fourty_two(): Int\n{\n    return 41;\n}"
    patch = "fun fourty_two(): Int\n{\n    return 42; // corrigido\n}"
    assert reachability.localizar_no_patch(orig, patch, 3) is None


def test_guarda_se_abstem_sem_linha_do_defeito():
    """Runs antigas não têm `violation` gravada; a guarda não pode quebrá-las."""
    assert reachability.localizar_no_patch("a\nb\n", "a\nb\n", 0) is None
    assert reachability.localizar_no_patch("a\nb\n", "a\nb\n", 99) is None
