"""O oráculo do reparo re-verifica com a MESMA configuração da run que achou o bug.

Antes (rv. 1.10) só `unsigned_overflow` era herdado. Em C:
- sem `concurrency`, o patch de uma race era re-verificado SEM procurar race, e o
  código IDÊNTICO saía FIX_OK (confirmado em 09/10/2026 — ver o e2e abaixo);
- sem `strategy`, a re-verificação era sempre `bounded`, aceitando SAFE vacuamente
  verdadeiro mesmo quando a run tinha usado `sound`/`kinduction`;
- sem `function`/`include_dirs`, verificava outro ponto de entrada / nem compilava.
"""

import time

import pytest
from fastapi.testclient import TestClient

from smart_jbmc.api.app import app
from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.process import ToolResult
from smart_jbmc.core.repair import regression

client = TestClient(app)
needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")

RACE_C = """#include <pthread.h>
int x = 0;
void *t(void *a) { x++; return 0; }
int main() {
  pthread_t a, b;
  pthread_create(&a, 0, t, 0);
  pthread_create(&b, 0, t, 0);
  pthread_join(a, 0); pthread_join(b, 0);
  return 0;
}
"""


def test_regression_c_repassa_config_da_run(tmp_path, monkeypatch):
    visto = {}

    def falso_esbmc(target, **kw):
        visto.update(kw)
        return ToolResult(0, "VERIFICATION SUCCESSFUL\n", "")

    monkeypatch.setattr(regression, "run_esbmc", falso_esbmc)
    alvo = tmp_path / "a_FIXED.c"
    alvo.write_text("int main(){return 0;}\n")
    regression.regression_check(
        str(alvo), "Race Condition", 3, 30, "boolector",
        strategy="kinduction", concurrency=True,
        include_dirs=["/inc"], function="tarefa")
    assert visto["concurrency"] is True
    assert visto["strategy"] == "kinduction"
    assert visto["include_dirs"] == ["/inc"]
    assert visto["function"] == "tarefa"


def _espera(get, prazo=180):
    fim = time.time() + prazo
    while time.time() < fim:
        rec = get()
        if rec["status"] != "running":
            return rec
        time.sleep(1)
    return get()


@needs_esbmc
def test_race_com_codigo_identico_nao_sai_reparada(tmp_path):
    (tmp_path / "race.c").write_text(RACE_C)
    run_id = client.post("/api/runs", json={
        "folder": str(tmp_path), "concurrency": True, "jobs": 1, "timeout": 60}).json()["id"]
    run = _espera(lambda: client.get(f"/api/runs/{run_id}").json())
    alvos = run["result"]["targets"]
    assert [a["status"] for a in alvos] == ["BUG"]

    # dry-run devolve o código inalterado: a race continua lá
    r = client.post("/api/repair", json={"run_id": run_id, "max_iters": 1, "dry_run": True})
    assert r.status_code == 201
    rep = _espera(lambda: client.get(f"/api/repair/{run_id}").json())
    alvo = rep["result"]["targets"][0]
    assert alvo["status"] != "REPAIRED"
    assert [a["verdict"] for a in alvo["attempts"]] != ["FIX_OK"]


# --- Incremento 1 (A e B): a run com TODAS as opções ligadas chega igual ao oráculo ---

TODAS_AS_OPCOES = {
    "folder": "/tmp/proj", "unwind": 9, "timeout": 77, "jobs": 1, "solver": "z3",
    "strategy": "sound", "concurrency": True, "unsigned_overflow": True,
    "nan_check": True, "include_dirs": ["/inc"], "function": "tarefa",
}


def test_create_repair_herda_toda_a_config_da_run(tmp_path, monkeypatch):
    """Unwind, timeout e solver vinham da TELA no momento do reparo (padrão 5/60/
    boolector pela API). Agora vêm da run, como as demais opções."""
    from smart_jbmc.api import repair_store

    run = {"run_id": "r1", "status": "done", "config": dict(TODAS_AS_OPCOES),
           "result": {"targets": []}}
    enviados = {}
    monkeypatch.setattr(repair_store.store, "get_run", lambda rid, **kw: run)
    monkeypatch.setattr(repair_store, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(repair_store, "get_repair", lambda rid: None)
    monkeypatch.setattr(repair_store._executor, "submit",
                        lambda fn, rid, alvos, opts, *a: enviados.update(opts))
    repair_store.create_repair("r1", {"unwind": 5, "timeout": 60, "solver": "boolector",
                                      "max_iters": 1})
    for k in ("unwind", "timeout", "solver", "strategy", "concurrency",
              "unsigned_overflow", "nan_check", "include_dirs", "function"):
        assert enviados[k] == TODAS_AS_OPCOES[k], k


def test_create_repair_run_antiga_usa_o_pedido(tmp_path, monkeypatch):
    """Run gravada antes desta mudança, sem unwind no config: vale o pedido."""
    from smart_jbmc.api import repair_store

    run = {"run_id": "r2", "status": "done", "config": {"folder": "/x"},
           "result": {"targets": []}}
    enviados = {}
    monkeypatch.setattr(repair_store.store, "get_run", lambda rid, **kw: run)
    monkeypatch.setattr(repair_store, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(repair_store, "get_repair", lambda rid: None)
    monkeypatch.setattr(repair_store._executor, "submit",
                        lambda fn, rid, alvos, opts, *a: enviados.update(opts))
    repair_store.create_repair("r2", {"unwind": 4, "timeout": 30, "solver": "boolector",
                                      "max_iters": 1})
    assert (enviados["unwind"], enviados["timeout"], enviados["nan_check"]) == (4, 30, False)


def test_repair_run_leva_todas_as_opcoes_ate_o_esbmc(tmp_path, monkeypatch):
    """Do laço de reparo até a linha do ESBMC: cada opção da run chega ao oráculo."""
    from smart_jbmc.core.repair import loop

    fonte = tmp_path / "a.c"
    fonte.write_text("int main(){int z=0; return 1/z;}\n")
    vistos = []

    def falso_esbmc(target, **kw):
        vistos.append(kw)
        return ToolResult(0, "VERIFICATION SUCCESSFUL\n", "")

    def conserto(**kw):
        return {"patch": "int main(){int z=1; return 1/z;}\n", "usage": None,
                "model": "teste", "ms": 0}

    monkeypatch.setattr(regression, "run_esbmc", falso_esbmc)
    monkeypatch.setattr("smart_jbmc.core.verifiers.solver_available", lambda s: True)
    opc = TODAS_AS_OPCOES
    loop.repair_run(
        [{"status": "BUG", "source": str(fonte), "bug": "Division by Zero"}],
        unwind=opc["unwind"], timeout=opc["timeout"], solver=opc["solver"],
        max_iters=1, work_dir=str(tmp_path / "rep"), patch_fn=conserto,
        unsigned_overflow=True, nan_check=True, strategy="sound",
        concurrency=True, include_dirs=["/inc"], function="tarefa")
    assert vistos, "o oráculo não foi chamado"
    kw = vistos[0]
    assert (kw["unwind"], kw["timeout"], kw["solver"]) == (9, 77, "z3")
    assert kw["strategy"] == "sound" and kw["concurrency"] is True
    assert kw["unsigned_overflow"] is True and kw["nan_check"] is True
    assert kw["include_dirs"] == ["/inc"] and kw["function"] == "tarefa"


def test_run_esbmc_nan_check_vira_flag(monkeypatch):
    from smart_jbmc.core.verifiers import esbmc

    cmds = []
    monkeypatch.setattr(esbmc, "_require", lambda nome: nome)
    monkeypatch.setattr(esbmc, "run_cmd", lambda cmd, **kw: cmds.append(cmd) or ToolResult(0, "", ""))
    esbmc.run_esbmc("a.c")
    esbmc.run_esbmc("a.c", nan_check=True)
    assert "--nan-check" not in cmds[0]
    assert "--nan-check" in cmds[1]


def test_run_esbmc_concorrencia_usa_sleep_sets(monkeypatch):
    """ESBMC 8.6, rv. 2.4-cps: conjuntos de dormência com limite de 3 trocas de
    contexto. Sem limite (2.1) o defeito do FreeRTOS #1236 se perdia (opcao_b)."""
    from smart_jbmc.core.verifiers import esbmc

    cmds = []
    monkeypatch.setattr(esbmc, "_require", lambda nome: nome)
    monkeypatch.setattr(esbmc, "run_cmd", lambda cmd, **kw: cmds.append(cmd) or ToolResult(0, "", ""))
    esbmc.run_esbmc("a.c", concurrency=True)
    for flag in ("--data-races-check", "--deadlock-check", "--sleep-sets", "--context-bound"):
        assert flag in cmds[0], flag
    assert "--no-por" not in cmds[0]
