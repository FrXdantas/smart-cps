"""Concorrência em duas opções (24/10/2026, medição em medicoes_esbmc86/opcao_b).

- `concurrency`: explora as intercalações das threads com sleep sets e limite de 3
  trocas de contexto (Cordeiro e Fischer, ICSE 2011). Basta para asserções em
  código com threads, como o caso FreeRTOS #1236.
- `race_check`: procura também corrida de dados e impasse (CWE-362, CWE-833).
  Implica `concurrency`. Ausente (None) = igual a `concurrency`, como antes.

Na medição, o modo anterior (--no-por --sleep-sets) perdia o defeito do #1236
(tempo esgotado, 14,9 GB); com o limite 3 ele sai em 9 s.
"""

import pytest

from smart_jbmc.core.process import ToolResult
from smart_jbmc.core.repair import regression
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


def _tem(cmd, *flags):
    return all(f in cmd for f in flags)


def test_so_threads_explora_sem_procurar_corrida(comando):
    esbmc.run_esbmc("x.c", concurrency=True, race_check=False)
    cmd = comando["cmd"]
    assert _tem(cmd, "--sleep-sets", "--context-bound", "3")
    assert "--no-por" not in cmd
    assert "--data-races-check" not in cmd and "--deadlock-check" not in cmd
    assert "--multi-property" not in cmd


def test_corrida_liga_tambem_a_exploracao(comando):
    esbmc.run_esbmc("x.c", concurrency=False, race_check=True)
    assert _tem(comando["cmd"], "--sleep-sets", "--context-bound", "--data-races-check",
                "--deadlock-check")
    assert "--multi-property" not in comando["cmd"]


def test_sem_race_check_informado_vale_o_comportamento_anterior(comando):
    esbmc.run_esbmc("x.c", concurrency=True)
    assert _tem(comando["cmd"], "--data-races-check", "--deadlock-check")


def test_nada_ligado_continua_igual(comando):
    esbmc.run_esbmc("x.c")
    cmd = comando["cmd"]
    assert "--multi-property" in cmd
    assert not any(f in cmd for f in ("--sleep-sets", "--context-bound", "--data-races-check"))


def test_sarif_registra_as_duas_opcoes():
    base = {"unwind": 3, "timeout": 180, "solver": "boolector", "strategy": "bounded"}
    so_threads = _esbmc_cmd_template({**base, "concurrency": True, "race_check": False})
    assert "--context-bound 3" in so_threads and "--data-races-check" not in so_threads
    com_corrida = _esbmc_cmd_template({**base, "concurrency": True, "race_check": True})
    assert "--data-races-check" in com_corrida


def test_oraculo_herda_race_check(monkeypatch, tmp_path):
    visto = {}

    def falso(target, **kw):
        visto.update(kw)
        return ToolResult(0, "VERIFICATION SUCCESSFUL", "")

    monkeypatch.setattr(regression, "run_esbmc", falso)
    f = tmp_path / "x.c"
    f.write_text("int main(){return 0;}")
    regression.regression_check(str(f), "Race Condition", unwind=3, timeout=10,
                                concurrency=True, race_check=False)
    assert visto["concurrency"] is True and visto["race_check"] is False
