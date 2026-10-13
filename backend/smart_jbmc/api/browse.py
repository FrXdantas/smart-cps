"""Navegação de diretórios da máquina (para o seletor de pasta da SPA).

Ferramenta local: lista subdiretórios de um caminho do servidor para ajudar
o usuário a montar o caminho da pasta a verificar.
"""

import os

from fastapi import APIRouter, Depends, HTTPException

from ..auth.deps import require_admin
from ..core.constants import C_FAMILY_EXTS

router = APIRouter(prefix="/browse", tags=["system"])

# Mantém em sincronia com scanner.scan(): toda a família C (.c/.cpp/.cc/...) conta.
SOURCE_EXT = C_FAMILY_EXTS + (".java", ".kt")


def _count_sources(base: str, file_cap: int = 2000, dir_cap: int = 8000) -> tuple[int, bool]:
    """Conta fontes (C-família/.java/.kt) RECURSIVAMENTE — igual ao scanner.
    Limita a varredura (file_cap/dir_cap) para o seletor não travar em árvores
    enormes; devolve (contagem, capped). Pula diretórios ocultos."""
    n = dirs_seen = 0
    for root, dnames, files in os.walk(base):
        dnames[:] = [d for d in dnames if not d.startswith(".")]
        dirs_seen += 1
        n += sum(1 for f in files if f.endswith(SOURCE_EXT))
        if n >= file_cap or dirs_seen >= dir_cap:
            return n, True
    return n, False


@router.get("")
def browse(path: str | None = None, _: dict = Depends(require_admin)):
    """Lista os subdiretórios de `path` (ou do HOME, se omitido). Só admin —
    evita vazar a estrutura do disco do servidor para users comuns."""
    base = os.path.abspath(os.path.expanduser(path)) if path else os.path.expanduser("~")
    if not os.path.isdir(base):
        raise HTTPException(status_code=404, detail=f"diretório não encontrado: {base}")
    try:
        dirs = sorted(
            e.name for e in os.scandir(base)
            if e.is_dir(follow_symlinks=False) and not e.name.startswith(".")
        )
        source_files, source_capped = _count_sources(base)
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"sem permissão: {base}")

    parent = os.path.dirname(base)
    return {
        "path": base,
        "parent": parent if parent and parent != base else None,
        "dirs": dirs,
        "source_files": source_files,      # RECURSIVO (toda a árvore), como o scanner
        "source_capped": source_capped,    # True se a contagem foi limitada
    }
