"""Etapa 6: API REST de reparo (POST/GET /api/repair)."""

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from smart_jbmc.api.app import app
from smart_jbmc.core.config import resolve_tool

FIXTURES = Path(__file__).parent / "fixtures"
client = TestClient(app)
needs_tools = pytest.mark.skipif(
    resolve_tool("esbmc") is None or resolve_tool("jbmc") is None
    or resolve_tool("javac") is None,
    reason="esbmc/jbmc/javac indisponíveis",
)


def _wait(get, deadline=180):
    end = time.time() + deadline
    while time.time() < end:
        rec = get()
        if rec["status"] != "running":
            return rec
        time.sleep(1)
    return get()


def test_repair_run_not_found():
    # run inexistente (ou de outro dono) -> 404 no pré-check de posse; não vaza existência
    r = client.post("/api/repair", json={"run_id": "naoexiste"})
    assert r.status_code == 404
    assert client.get("/api/repair/naoexiste").status_code == 404


@needs_tools
def test_repair_lifecycle_dry_run():
    # 1) roda uma verificação sobre as fixtures
    run_id = client.post("/api/runs", json={
        "folder": str(FIXTURES), "unwind": 2, "timeout": 60, "jobs": 2}).json()["id"]
    run = _wait(lambda: client.get(f"/api/runs/{run_id}").json())
    assert run["status"] == "done"

    # 2) repara (dry-run: sem API/saldo)
    r = client.post("/api/repair", json={
        "run_id": run_id, "max_iters": 2, "unwind": 2, "timeout": 60, "dry_run": True})
    assert r.status_code == 201

    rep = _wait(lambda: client.get(f"/api/repair/{run_id}").json())
    assert rep["status"] == "done"
    summary = rep["result"]["summary"]
    assert summary["total"] >= 2          # há bugs (div-zero, ArrayOob)
    assert summary["repaired"] == 0       # dry-run não corrige
    assert "by_category" in rep["result"]
