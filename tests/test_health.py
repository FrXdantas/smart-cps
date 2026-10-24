"""`/api/health`: prova de vida pública, detalhes só para quem está logado.

O endpoint continua aberto (monitoramento externo depende disso), mas parou de
entregar versão e caminhos absolutos dos binários a quem só abriu a URL — o
sistema está publicado na internet. Junto: `/api/docs` e `/api/openapi.json`,
que o FastAPI expõe públicos por padrão, agora exigem login.
"""

from fastapi.testclient import TestClient

from smart_jbmc.api.app import app
from smart_jbmc.auth.deps import optional_user

client = TestClient(app)


def test_health_logado_traz_ferramentas():
    res = client.get("/api/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert isinstance(body["tools"], dict)
    assert body["version"]
    # chave de LLM é de cada usuário: o servidor não anuncia chave própria
    assert "llm" not in body


def test_health_anonimo_so_prova_de_vida():
    app.dependency_overrides.pop(optional_user, None)   # derruba o login do conftest
    res = client.get("/api/health")
    assert res.status_code == 200                       # segue público
    body = res.json()
    assert body["status"] == "ok"
    # nada de versão, caminhos de binário ou estado da LLM do servidor
    assert body["version"] is None
    assert body["tools"] is None
    assert body["memoria"] is None                      # nem a RAM da máquina
    assert "/usr/" not in res.text


def test_docs_e_openapi_exigem_login():
    from smart_jbmc.auth.deps import current_user

    assert client.get("/api/docs").status_code == 200        # logado (conftest)
    assert client.get("/api/openapi.json").status_code == 200

    app.dependency_overrides.pop(current_user, None)
    assert client.get("/api/docs").status_code == 401
    r = client.get("/api/openapi.json")
    assert r.status_code == 401
    assert "0.1.0" not in r.text


def test_health_logado_traz_memoria_da_maquina():
    mem = client.get("/api/health").json()["memoria"]
    assert mem["total_mb"] > 0 and 0 <= mem["usado_mb"] <= mem["total_mb"]
    assert mem["nivel"] in ("ok", "atencao", "alerta")


def test_memoria_maquina_niveis(tmp_path):
    from smart_jbmc.core.process import memoria_maquina

    def com(disponivel_kb):
        f = tmp_path / "meminfo"
        f.write_text(f"MemTotal: 1000000 kB\nMemFree: 1000 kB\nMemAvailable: {disponivel_kb} kB\n")
        return memoria_maquina(str(f))

    assert com(800000)["nivel"] == "ok"          # 20% em uso
    assert com(250000)["nivel"] == "atencao"     # 75%
    assert com(100000)["nivel"] == "alerta"      # 90%
    # MemAvailable conta o cache que o kernel devolve; MemFree sozinho não
    assert com(800000)["pct"] == 20
    assert memoria_maquina(str(tmp_path / "nao_existe")) is None


def test_ferramentas_em_uso_le_proc(tmp_path):
    """Verificador e compilador rodando aparecem com RAM e tempo; zumbi e
    processo comum, não. O kotlinc é um `java` com kotlin na linha de comando."""
    from smart_jbmc.core.process import ferramentas_em_uso

    (tmp_path / "uptime").write_text("1000.0 0.0\n")

    def proc(pid, comm, rss_kb, estado="R", cmdline=b""):
        d = tmp_path / str(pid)
        d.mkdir()
        (d / "comm").write_text(comm + "\n")
        (d / "cmdline").write_bytes(cmdline)
        (d / "status").write_text(f"Name:\t{comm}\nVmRSS:\t{rss_kb} kB\n")
        campos = [estado] + ["0"] * 18 + ["90000"]      # starttime = 900 s (100 Hz)
        (d / "stat").write_text(f"{pid} ({comm}) " + " ".join(campos) + "\n")

    proc(10, "esbmc", 2 * 1024 * 1024)
    proc(11, "java", 300 * 1024, cmdline=b"java\0-cp\0kotlin-compiler.jar\0org.jetbrains.kotlin.cli")
    proc(12, "java", 500 * 1024, cmdline=b"java\0-jar\0outra.jar")
    proc(13, "jbmc", 0, estado="Z")
    proc(14, "bash", 4 * 1024)
    achados = ferramentas_em_uso(str(tmp_path))
    assert [(a["nome"], a["papel"]) for a in achados] == [("esbmc", "verificador"), ("kotlinc", "compilador")]
    assert achados[0]["rss_mb"] == 2048
    assert achados[0]["tempo_s"] == 1000 - 90000 // __import__("os").sysconf("SC_CLK_TCK")
