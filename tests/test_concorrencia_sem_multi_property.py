"""R1 (caso FreeRTOS #1236, 24/10/2026): com concorrência, o ESBMC roda sem --multi-property.

Com threads, --multi-property no ESBMC 8.6 procura todas as propriedades em todas as
intercalações: o caso estourou 10 GB (jobs 2) e 180 s (jobs 1), e o próprio ESBMC avisa
que o PASSED nesse modo só vale para as intercalações exploradas. Sem a opção, o ESBMC
para no primeiro defeito e achou o do caso em poucos segundos. Sem concorrência, nada muda.
"""

import pytest

from smart_jbmc.core.process import ToolResult
from smart_jbmc.core.sarif import _esbmc_cmd_template
from smart_jbmc.core.verifiers import esbmc


@pytest.fixture
def comando(monkeypatch):
    capturado = {}

    def falso_run_cmd(cmd, **kw):
        capturado["cmd"] = cmd
        return ToolResult(0, "VERIFICATION SUCCESSFUL", "")

    monkeypatch.setattr(esbmc, "run_cmd", falso_run_cmd)
    monkeypatch.setattr(esbmc, "_require", lambda nome: "/usr/bin/esbmc")
    return capturado


def test_com_concorrencia_nao_usa_multi_property(comando):
    esbmc.run_esbmc("x.c", concurrency=True)
    assert "--multi-property" not in comando["cmd"]
    assert "--sleep-sets" in comando["cmd"]


def test_sem_concorrencia_continua_com_multi_property(comando):
    esbmc.run_esbmc("x.c", concurrency=False)
    assert "--multi-property" in comando["cmd"]


def test_sarif_registra_o_comando_real():
    base = {"unwind": 3, "timeout": 180, "solver": "boolector", "strategy": "bounded"}
    assert "--multi-property" not in _esbmc_cmd_template({**base, "concurrency": True})
    assert "--multi-property" in _esbmc_cmd_template({**base, "concurrency": False})
