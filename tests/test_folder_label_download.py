"""Rótulo da pasta na UI, download da pasta em .zip e exclusão de UMA run.

Três garantias:
  1. o histórico e o detalhe da run expõem `folder_label` ("pytest/QuixBugs"),
     nunca o caminho absoluto do servidor;
  2. `GET /api/runs/<id>/download` devolve a pasta zipada, com ou sem os
     `<nome>_FIXED.<ext>` que o reparo grava ao lado do original;
  3. `DELETE /api/runs/<id>` (a lixeira do histórico) leva junto a pasta enviada
     — mas só quando nenhuma outra run a usa, e nunca uma pasta local do admin.
"""

import io
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from smart_jbmc.api import store
from smart_jbmc.api.app import app
from smart_jbmc.api.uploads import clear_uploads, folder_label

from conftest import TEST_OWNER_ID

client = TestClient(app)


@pytest.fixture(autouse=True)
def _sem_worker(monkeypatch):
    """Não lançar a verificação de verdade: aqui só interessam rótulo, zip e
    exclusão. Sem isto a run nasce `running` e o DELETE responderia 409 ou não,
    dependendo de quem ganhasse a corrida."""
    monkeypatch.setattr(store._executor, "submit", lambda *a, **k: None)


def _criar_run(folder: str, owner_id: int = TEST_OWNER_ID, login: str = "pytest") -> str:
    rec = store.create_run({"folder": folder, "unwind": 2, "timeout": 10, "jobs": 1},
                           owner_id=owner_id, owner_login=login)
    rec["status"] = "done"     # como se tivesse terminado
    store._set(rec)
    return rec["id"]


def _upload(name: str = "QuixBugs") -> dict:
    files = [
        ("files", ("LIS.java", b"class LIS {}", "text/plain")),
        ("files", ("Main.java", b"class Main { public static void main(String[] a){} }", "text/plain")),
    ]
    data = {"paths": [f"{name}/LIS.java", f"{name}/Main.java"]}
    r = client.post("/api/uploads", files=files, data=data)
    assert r.status_code == 200, r.text
    return r.json()


def test_upload_devolve_rotulo_logico():
    try:
        up = _upload()
        assert up["name"] == "QuixBugs"
        assert up["label"] == "pytest/QuixBugs"
        # o rótulo derivado do caminho no disco bate com o do upload
        assert folder_label(up["folder"], "pytest") == "pytest/QuixBugs"
    finally:
        clear_uploads(owner_id=TEST_OWNER_ID)


def test_folder_label_de_pasta_fora_de_uploads():
    # admin apontando um benchmark local (Browse): só o nome do diretório
    assert folder_label("/opt/benchmarks/quixbugs", "franklin") == "franklin/quixbugs"
    assert folder_label(None) == ""


def test_historico_e_detalhe_nao_expoem_caminho_absoluto():
    try:
        up = _upload("MeuProjeto")
        run_id = _criar_run(up["folder"])

        brief = next(x for x in client.get("/api/runs").json() if x["id"] == run_id)
        assert brief["folder_label"] == "pytest/MeuProjeto"

        detail = client.get(f"/api/runs/{run_id}").json()
        assert detail["folder_label"] == "pytest/MeuProjeto"
    finally:
        store.clear_runs(owner_id=TEST_OWNER_ID)
        clear_uploads(owner_id=TEST_OWNER_ID)


def _zip_names(resp) -> list[str]:
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
        return sorted(z.namelist())


def test_download_com_e_sem_fix():
    try:
        up = _upload()
        # simula o que o reparo grava ao lado do fonte quando o alvo é REPAIRED
        (Path(up["folder"]) / "QuixBugs" / "LIS_FIXED.java").write_text(
            "class LIS { /* reparado */ }", encoding="utf-8")

        run_id = _criar_run(up["folder"])

        # o zip abre direto em QuixBugs/, sem o invólucro do upload nem nível duplo
        com_fix = _zip_names(client.get(f"/api/runs/{run_id}/download"))
        assert com_fix == [
            "QuixBugs/LIS.java",
            "QuixBugs/LIS_FIXED.java",
            "QuixBugs/Main.java",
        ]

        original = _zip_names(client.get(f"/api/runs/{run_id}/download?fixed=false"))
        assert not any(n.endswith("_FIXED.java") for n in original)
        assert len(original) == 2
    finally:
        store.clear_runs(owner_id=TEST_OWNER_ID)
        clear_uploads(owner_id=TEST_OWNER_ID)


def test_download_run_inexistente():
    assert client.get("/api/runs/naoexiste123/download").status_code == 404


def test_apagar_run_leva_a_pasta_enviada_junto():
    """A lixeira do histórico não pode deixar lixo no servidor."""
    try:
        up = _upload()
        pasta = Path(up["folder"])
        run_id = _criar_run(up["folder"])

        r = client.delete(f"/api/runs/{run_id}")
        assert r.status_code == 200, r.text
        assert r.json() == {"deleted": run_id, "upload_removed": True}
        assert not pasta.exists()
        assert not (pasta.parent / f"{pasta.name}.json").exists()   # sidecar do nome
        assert not any(x["id"] == run_id for x in client.get("/api/runs").json())
        assert client.get(f"/api/runs/{run_id}").status_code == 404
    finally:
        store.clear_runs(owner_id=TEST_OWNER_ID)
        clear_uploads(owner_id=TEST_OWNER_ID)


def test_apagar_run_preserva_pasta_usada_por_outra_run():
    """Duas runs sobre a mesma pasta (mudou o unwind e rodou de novo): apagar uma
    NÃO pode levar a pasta que a outra ainda usa."""
    try:
        up = _upload()
        a = _criar_run(up["folder"])
        b = _criar_run(up["folder"])

        assert client.delete(f"/api/runs/{a}").json()["upload_removed"] is False
        assert Path(up["folder"]).is_dir()
        assert client.get(f"/api/runs/{b}/download").status_code == 200

        # apagando a última, aí sim a pasta vai junto
        assert client.delete(f"/api/runs/{b}").json()["upload_removed"] is True
        assert not Path(up["folder"]).exists()
    finally:
        store.clear_runs(owner_id=TEST_OWNER_ID)
        clear_uploads(owner_id=TEST_OWNER_ID)


def test_apagar_run_nao_toca_pasta_local_fora_de_uploads(tmp_path):
    """Pasta local apontada pelo admin no Browse não é upload — a run some, a
    pasta do usuário no disco fica."""
    local = tmp_path / "benchmark_local"
    local.mkdir()
    (local / "a.c").write_text("int main(){return 0;}", encoding="utf-8")
    try:
        run_id = _criar_run(str(local))
        r = client.delete(f"/api/runs/{run_id}")
        assert r.status_code == 200
        assert r.json()["upload_removed"] is False
        assert (local / "a.c").is_file()
    finally:
        store.clear_runs(owner_id=TEST_OWNER_ID)


def test_apagar_run_de_outro_dono_da_404():
    try:
        run_id = _criar_run("/tmp", owner_id=4242, login="outro")
        assert client.delete(f"/api/runs/{run_id}").status_code == 404
        assert store.get_run(run_id) is not None   # continua lá
    finally:
        store.clear_runs(owner_id=4242)
