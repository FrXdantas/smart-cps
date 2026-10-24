"""Tela de 24/10/2026: escolher os arquivos da pasta e ver qual está sendo verificado.

- `files` (caminhos relativos à pasta) restringe a run aos arquivos marcados no
  pop-up de envio. Vazio = todos, como antes.
- O progresso traz `current`: os arquivos em verificação naquele momento.
"""

from smart_jbmc.core import orchestrator
from smart_jbmc.core.process import ToolResult


def _pasta(tmp_path):
    for sub in ("com_bug", "sem_bug"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "x.c").write_text("int main(){return 0;}")
    return tmp_path


def _sem_esbmc(monkeypatch, vistos):
    def falso(cfile, **kw):
        vistos.append(cfile)
        return ToolResult(0, "VERIFICATION SUCCESSFUL", "")
    monkeypatch.setattr(orchestrator, "run_esbmc", falso)


def test_files_restringe_aos_arquivos_escolhidos(tmp_path, monkeypatch):
    vistos = []
    _sem_esbmc(monkeypatch, vistos)
    pasta = _pasta(tmp_path)
    rr = orchestrator.run_verification(str(pasta), jobs=1, files=["com_bug/x.c"],
                                       build_root=str(tmp_path / "b"))
    assert [t.source for t in rr.targets] == [str(pasta / "com_bug" / "x.c")]
    assert rr.config["files"] == ["com_bug/x.c"]


def test_sem_files_verifica_todos(tmp_path, monkeypatch):
    vistos = []
    _sem_esbmc(monkeypatch, vistos)
    rr = orchestrator.run_verification(str(_pasta(tmp_path)), jobs=1, build_root=str(tmp_path / "b"))
    assert len(rr.targets) == 2


def test_progresso_traz_o_arquivo_em_verificacao(tmp_path, monkeypatch):
    vistos, eventos = [], []
    _sem_esbmc(monkeypatch, vistos)
    rr = orchestrator.run_verification(
        str(_pasta(tmp_path)), jobs=1, build_root=str(tmp_path / "b"),
        on_progress=lambda phase, done, total, current=(): eventos.append((phase, list(current))))
    em_curso = [c for fase, c in eventos if fase == "verifying" and c]
    assert ["com_bug/x.c"] in em_curso and ["sem_bug/x.c"] in em_curso
    assert eventos[-1] == ("done", [])
