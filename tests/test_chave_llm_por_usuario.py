"""Chave de LLM é de cada usuário.

O servidor não empresta chave própria: mesmo com DEEPSEEK_API_KEY no ambiente
(o antigo fallback do .env), um pedido de reparo sem a chave do usuário não
chama o provedor pago. O provedor local continua dispensando chave.
"""

import pytest

from smart_jbmc.core.repair import llm

ARGS = dict(bug="Division by Zero", cwe_info=None, cert_rule=None,
            code="int main(){return 0;}", counterexample="", lang="c")


def test_sem_chave_do_usuario_nao_usa_a_do_servidor(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-chave-do-servidor")
    chamou = []
    monkeypatch.setattr(llm.requests, "post", lambda *a, **k: chamou.append(k))
    with pytest.raises(llm.LLMUnavailable):
        llm.generate_patch(**ARGS, base_url="https://api.deepseek.com")
    assert chamou == []


def test_chave_enviada_e_a_do_usuario(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-chave-do-servidor")
    enviados = []

    class Resp:
        status_code = 200
        headers = {}

        def json(self):
            return {"choices": [{"message": {"content": "int main(){return 0;}"}}],
                    "model": "deepseek-flash", "usage": {}}

        def raise_for_status(self):
            pass

    def post(url, headers=None, **k):
        enviados.append(headers.get("Authorization"))
        return Resp()

    monkeypatch.setattr(llm.requests, "post", post)
    llm.generate_patch(**ARGS, base_url="https://api.deepseek.com", api_key="sk-do-usuario")
    assert enviados == ["Bearer sk-do-usuario"]


def test_servidor_nao_tem_mais_o_fallback():
    assert not hasattr(llm, "env_api_key")
    assert not hasattr(llm, "available")
