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
