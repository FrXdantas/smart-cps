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
    assert "configured" in body["llm"]


def test_health_anonimo_so_prova_de_vida():
    app.dependency_overrides.pop(optional_user, None)   # derruba o login do conftest
    res = client.get("/api/health")
    assert res.status_code == 200                       # segue público
    body = res.json()
    assert body["status"] == "ok"
    # nada de versão, caminhos de binário ou estado da LLM do servidor
    assert body["version"] is None
    assert body["tools"] is None
    assert body["llm"] is None
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
