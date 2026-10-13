"""Configuração compartilhada dos testes.

Os testes de API (`test_runs_api`, `test_browse_api`, `test_repair_api`) batem em
endpoints protegidos sem cookie de sessão nem `Authorization: Bearer`. Em vez de
montar um login real a cada requisição, sobrepomos a dependência `current_user`
por um usuário de teste (admin) usando `app.dependency_overrides` — o mecanismo
oficial do FastAPI para autenticação em testes. `require_admin` depende de
`current_user`, então o override também o satisfaz (role=admin).
"""

import pytest

from smart_jbmc.api.app import app
from smart_jbmc.auth.deps import current_user, optional_user

# Mesmas chaves que uma linha real da tabela users (id/login/role são as usadas
# pelos handlers para dono/permissão). O id é SINTÉTICO e propositalmente alto
# (999999) para JAMAIS colidir com um usuário real — assim os runs/uploads que os
# testes criam em data/ ficam isoláveis por esse owner_id e nunca se confundem
# com dados de gente real (franklin é id=1, ana=2, ...).
TEST_OWNER_ID = 999999
TEST_USER = {
    "id": TEST_OWNER_ID,
    "login": "pytest",
    "role": "admin",
    "api_key_prefix": None,
    "created_at": None,
    "last_login": None,
}


@pytest.fixture(autouse=True)
def _auth_override():
    """Autentica todo TestClient como o usuário de teste (admin).

    `optional_user` entra junto: é o que `/api/health` usa para decidir se
    responde completo ou só `status`. Teste que precise do caminho ANÔNIMO
    remove esse override (ver `test_health`).
    """
    app.dependency_overrides[current_user] = lambda: TEST_USER
    app.dependency_overrides[optional_user] = lambda: TEST_USER
    yield
    app.dependency_overrides.pop(current_user, None)
    app.dependency_overrides.pop(optional_user, None)
