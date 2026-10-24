"""Histórico: data do último reparo.

A linha do histórico mostra a data de criação da run. Um reparo feito dias
depois ficava sem data. `repair_model.at` traz o fim do reparo (ou o início,
se ainda roda), e a run sem reparo continua sem `repair_model`.
"""

import json
import shutil

import pytest
from fastapi.testclient import TestClient

from smart_jbmc.api import store
from smart_jbmc.api.app import app

from conftest import TEST_OWNER_ID

client = TestClient(app)


@pytest.fixture(autouse=True)
def _sem_worker(monkeypatch):
    monkeypatch.setattr(store._executor, "submit", lambda *a, **k: None)


def _criar_run() -> str:
    rec = store.create_run({"folder": "/tmp/nao-usada", "unwind": 2, "timeout": 10, "jobs": 1},
                           owner_id=TEST_OWNER_ID, owner_login="pytest")
    rec["status"] = "done"
    store._set(rec)
    return rec["id"]


def _gravar_reparo(run_id: str, **campos) -> None:
    d = store.RUNS_DIR / run_id
    d.mkdir(parents=True, exist_ok=True)
    rep = {"run_id": run_id, "status": "done", "options": {"model": "qwen3:8b", "provider": "local"},
           "result": {"targets": [{"attempts": [{"model": "qwen3:8b"}]}]}}
    rep.update(campos)
    (d / "repair.json").write_text(json.dumps(rep), encoding="utf-8")


def _linha(run_id: str) -> dict:
    r = client.get("/api/runs")
    assert r.status_code == 200, r.text
    return next(x for x in r.json() if x["id"] == run_id)


def test_historico_traz_data_do_fim_do_reparo():
    rid = _criar_run()
    try:
        _gravar_reparo(rid, created_at="2026-10-24T18:00:00+00:00",
                       finished_at="2026-10-24T18:05:00+00:00")
        rm = _linha(rid)["repair_model"]
        assert rm["model"] == "qwen3:8b"
        assert rm["at"] == "2026-10-24T18:05:00+00:00"
    finally:
        store.delete_run(rid)
        shutil.rmtree(store.RUNS_DIR / rid, ignore_errors=True)


def test_reparo_em_andamento_usa_a_data_de_inicio():
    rid = _criar_run()
    try:
        _gravar_reparo(rid, created_at="2026-10-24T18:00:00+00:00", finished_at=None)
        assert _linha(rid)["repair_model"]["at"] == "2026-10-24T18:00:00+00:00"
    finally:
        store.delete_run(rid)
        shutil.rmtree(store.RUNS_DIR / rid, ignore_errors=True)


def test_run_sem_reparo_continua_sem_repair_model():
    rid = _criar_run()
    try:
        assert _linha(rid)["repair_model"] is None
    finally:
        store.delete_run(rid)
