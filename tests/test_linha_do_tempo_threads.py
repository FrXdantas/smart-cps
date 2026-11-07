"""Item 4 do plano de 07/11/2026 (previsto para a semana 3): threads em linha do tempo.

Com o fatiamento padrão, o contraexemplo de uma condição de corrida no ESBMC 8.6 traz
só o estado da asserção. A ferramenta roda de novo sem fatiamento (--no-slice), só nos
alvos com threads e defeito, para entregar a intercalação ao reparo (grupo C).
"""

from pathlib import Path

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.counterexample import linha_do_tempo
from smart_jbmc.core.orchestrator import run_verification

needs_esbmc = pytest.mark.skipif(resolve_tool("esbmc") is None, reason="esbmc indisponível")

CORRIDA = """#include <pthread.h>
#include <assert.h>
int saldo = 100;
void *saque(void *arg) {
  int lido = saldo;
  lido = lido - 30;
  saldo = lido;
  return 0;
}
int main(void) {
  pthread_t t1, t2;
  pthread_create(&t1, 0, saque, 0);
  pthread_create(&t2, 0, saque, 0);
  pthread_join(t1, 0);
  pthread_join(t2, 0);
  assert(saldo == 40);
  return 0;
}
"""


def test_uma_thread_nao_tem_linha_do_tempo():
    assert linha_do_tempo([{"state": 1, "file": "a.c", "line": 1, "function": "main",
                            "assigns": ["x = 1"], "thread": 0}]) is None


def test_marca_troca_e_ignora_biblioteca():
    passos = [
        {"state": 1, "file": "a.c", "line": 5, "function": "f", "assigns": ["x = 1"], "thread": 1},
        {"state": 2, "file": "/esbmc-vfs/libc/library/pthread_lib.c", "line": 9,
         "function": "pthread_trampoline", "assigns": [], "thread": 2},
        {"state": 3, "file": "a.c", "line": 6, "function": "f", "assigns": ["x = 2"], "thread": 2},
    ]
    t = linha_do_tempo(passos)
    assert "pthread_lib" not in t
    assert ">> thread 2 | f (a.c:6) | x = 2" in t


@needs_esbmc
def test_corrida_real_mostra_a_intercalacao(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "corrida.c").write_text(CORRIDA, encoding="utf-8")
    r = run_verification(str(tmp_path / "src"), unwind=3, timeout=120, jobs=1,
                         concurrency=True, race_check=False,
                         build_root=str(tmp_path / "build"))
    t = r.targets[0]
    assert t.status == "BUG"
    e = t.explanation
    assert "Linha do tempo das threads" in e
    # as duas threads leem 100 antes de qualquer escrita: a corrida aparece
    assert e.count("lido = 100") == 2 and e.count("saldo = 70") == 2
    assert ">> thread" in e


@needs_esbmc
def test_sem_threads_nao_roda_de_novo(tmp_path, monkeypatch):
    from smart_jbmc.core import orchestrator
    chamadas = []
    original = orchestrator.run_esbmc
    monkeypatch.setattr(orchestrator, "run_esbmc",
                        lambda *a, **k: chamadas.append(k.get("no_slice")) or original(*a, **k))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "d.c").write_text("int main(void){int z=0; return 1/z;}\n")
    run_verification(str(tmp_path / "src"), unwind=2, timeout=60, jobs=1,
                     build_root=str(tmp_path / "build"))
    assert chamadas == [False] or chamadas == [None]
