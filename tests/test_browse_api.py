"""Testes do navegador de diretórios (/api/browse)."""

from pathlib import Path

from fastapi.testclient import TestClient

from smart_jbmc.api.app import app

client = TestClient(app)
TESTS_DIR = Path(__file__).parent


def test_browse_lists_subdirs():
    r = client.get("/api/browse", params={"path": str(TESTS_DIR)})
    assert r.status_code == 200
    data = r.json()
    assert data["path"] == str(TESTS_DIR)
    assert "fixtures" in data["dirs"]
    assert data["parent"]  # tem diretório-pai


def test_browse_default_is_home():
    r = client.get("/api/browse")
    assert r.status_code == 200
    assert isinstance(r.json()["dirs"], list)


def test_browse_counts_source_files():
    # tests/fixtures/c contém arquivos .c
    r = client.get("/api/browse", params={"path": str(TESTS_DIR / "fixtures" / "c")})
    assert r.status_code == 200
    assert r.json()["source_files"] >= 2


def test_browse_invalid_path():
    r = client.get("/api/browse", params={"path": "/caminho/inexistente/xyz123"})
    assert r.status_code == 404
