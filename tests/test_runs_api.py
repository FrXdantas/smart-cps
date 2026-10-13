"""Integração da Etapa 4: API REST de runs (POST/GET via TestClient)."""

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


def test_create_run_invalid_folder():
    r = client.post("/api/runs", json={"folder": "/caminho/inexistente/xyz"})
    assert r.status_code == 400


@needs_tools
def test_run_lifecycle():
    # lança
    r = client.post("/api/runs", json={
        "folder": str(FIXTURES), "unwind": 2, "timeout": 60, "jobs": 2})
    assert r.status_code == 201
    run_id = r.json()["id"]

    # aparece na listagem
    assert any(x["id"] == run_id for x in client.get("/api/runs").json())

    # poll até concluir (máx ~120s)
    deadline = time.time() + 120
    status = "running"
    while time.time() < deadline:
        rec = client.get(f"/api/runs/{run_id}").json()
        status = rec["status"]
        if status != "running":
            break
        time.sleep(1)

    assert status == "done", rec.get("error")
    summary = rec["result"]["summary"]
    assert summary["BUG"] >= 2
    assert summary["total"] == len(rec["result"]["targets"])


def test_get_run_not_found():
    assert client.get("/api/runs/naoexiste123").status_code == 404
