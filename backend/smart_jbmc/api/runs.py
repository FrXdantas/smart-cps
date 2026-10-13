"""Rotas REST de verificação (runs), montadas sob /api/runs.

As runs são isoladas por usuário: cada um só enxerga as próprias.
"""

import io
import os
import re
import zipfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from .. import APP_REVISION
from ..auth.deps import current_user
from ..core.config import PROJECT_ROOT
from ..core.sarif import build_sarif
from ..core.verifiers import available_solvers
from . import repair_store, store
from .uploads import folder_label

router = APIRouter(prefix="/runs", tags=["runs"])

UPLOADS_DIR = (PROJECT_ROOT / "data" / "uploads").resolve()

# `<stem>_FIXED<ext>` é o patch verificado que o reparo grava ao lado do fonte
# (ver core.repair.loop._write_beside_source).
FIXED_RE = re.compile(r"_FIXED\.[A-Za-z0-9]+$")
ZIP_MAX_BYTES = int(os.environ.get("DOWNLOAD_MAX_BYTES", str(200 * 1024 * 1024)))


class RunRequest(BaseModel):
    folder: str
    unwind: int = 5
    timeout: int = 60
    jobs: int = 4
    solver: str = "boolector"
    concurrency: bool = False
    # estratégia de verificação: bounded (padrão) | sound | incremental | kinduction
    # (ver core.verifiers.esbmc.STRATEGIES). `unwinding_assertions` é o alias legado
    # do modo sound, mantido por compatibilidade.
    strategy: str = "bounded"
    unwinding_assertions: bool = False
    # opt-in: também checa overflow UNSIGNED (size_t/unsigned). Off por padrão —
    # wraparound unsigned é definido em C, ligar pode acusar uso intencional.
    unsigned_overflow: bool = False
    # include paths (-I) p/ verificar uma unidade de um projeto real cujos headers
    # não estão na pasta do alvo (ex.: ggml/include do llama.cpp). Sem buildar nada.
    include_dirs: list[str] = []
    # unidade multi-arquivo: lista de .c (main + deps) a verificar LINKADOS num único
    # alvo (ex.: ["repl.c","tinyexpr.c"]). Caminhos relativos resolvem contra `folder`.
    # Sem isto, cada .c é verificado isolado e as deps viram havoc.
    link_unit: list[str] = []
    # função-entrada (`--function`): verifica essa rotina como ponto de entrada, com
    # os argumentos HAVOCADOS (nondet) pelo ESBMC — dispensa escrever um main().
    # Permite checar uma função isolada sem corpo de chamador. Vazio = main padrão.
    function: str = ""


@router.get("/solvers")
def list_solvers(user: dict = Depends(current_user)):
    """Solvers SMT realmente compilados neste build do ESBMC (p/ o dropdown não
    oferecer um solver que vira ERROR silencioso, ex.: mathsat ausente)."""
    return {"available": available_solvers(), "default": "boolector"}


def _folder_belongs_to(user: dict[str, Any], folder: str) -> bool:
    """User comum só pode usar pastas dentro de data/uploads/<user_id>/.
    Admin pode usar qualquer pasta (inclui benchmarks locais via Browse).
    """
    if user.get("role") == "admin":
        return True
    try:
        target = Path(folder).resolve()
        owner_root = (UPLOADS_DIR / str(user["id"])).resolve()
        return owner_root in target.parents or target == owner_root
    except Exception:
        return False


@router.post("", status_code=201)
def create_run(req: RunRequest, user: dict = Depends(current_user)):
    if not os.path.isdir(req.folder):
        raise HTTPException(status_code=400, detail=f"pasta inválida: {req.folder}")
    if not _folder_belongs_to(user, req.folder):
        raise HTTPException(
            status_code=403,
            detail="pasta fora do seu espaço de upload (use 'Enviar pasta')",
        )
    rec = store.create_run(req.model_dump(), owner_id=user["id"], owner_login=user["login"])
    return {"id": rec["id"], "status": rec["status"]}


@router.get("")
def list_runs(user: dict = Depends(current_user)):
    """Lista as runs DO USUÁRIO (mais recentes primeiro)."""
    return store.list_runs(owner_id=user["id"])


@router.delete("")
def clear_runs(user: dict = Depends(current_user)):
    """Limpa o histórico do usuário (runs + uploads dele)."""
    removed = store.clear_runs(owner_id=user["id"])
    repair_store.clear()  # cache em memória — get_repair revalida no disco
    return {"cleared": removed}


@router.delete("/{run_id}")
def delete_run(run_id: str, user: dict = Depends(current_user)):
    """Apaga UMA run do histórico — e, com ela, a pasta enviada, quando nenhuma
    outra run do usuário ainda a usa (é o que evita lixo acumulado no servidor).
    """
    rec = store.get_run(run_id, owner_id=user["id"])
    if rec is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    if rec.get("status") == "running":
        raise HTTPException(status_code=409, detail="a run está em andamento — cancele antes de apagar")
    out = store.delete_run(run_id, owner_id=user["id"])
    repair_store.forget(run_id)
    return out


@router.post("/{run_id}/cancel")
def cancel_run(run_id: str, user: dict = Depends(current_user)):
    rec = store.get_run(run_id, owner_id=user["id"])
    if rec is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    store.request_cancel(run_id)
    return {"run_id": run_id, "cancelling": True}


@router.get("/{run_id}")
def get_run(run_id: str, user: dict = Depends(current_user)):
    rec = store.get_run(run_id, owner_id=user["id"])
    if rec is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    rec = dict(rec)
    rec["folder_label"] = folder_label(
        (rec.get("config") or {}).get("folder"), rec.get("owner_login"))
    return rec


@router.get("/{run_id}/download")
def download_run_folder(run_id: str, fixed: bool = True, user: dict = Depends(current_user)):
    """Baixa a pasta da run em .zip.

    `fixed=true` (padrão) leva os `<nome>_FIXED.<ext>` gerados pelo reparo lado a
    lado com os originais; `fixed=false` devolve só o que foi enviado.
    """
    rec = store.get_run(run_id, owner_id=user["id"])
    if rec is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    folder = (rec.get("config") or {}).get("folder")
    if not folder or not os.path.isdir(folder):
        raise HTTPException(status_code=404, detail="a pasta desta run não está mais no servidor")

    root = Path(folder).resolve()
    # a pasta do upload é só o invólucro (data/uploads/<owner>/<upload_id>/): quando
    # tem um único diretório dentro, o zip começa NELE — senão sairia QuixBugs/QuixBugs/.
    entries = [p for p in root.iterdir()] if root.is_dir() else []
    if len(entries) == 1 and entries[0].is_dir():
        root = entries[0]
    label = folder_label(folder) or run_id            # nome da pasta, sem o login
    base = re.sub(r"[^A-Za-z0-9._-]", "_", label) or run_id

    buf = io.BytesIO()
    total = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for fn in sorted(filenames):
                if not fixed and FIXED_RE.search(fn):
                    continue
                full = Path(dirpath) / fn
                if full.is_symlink() or not full.is_file():
                    continue
                total += full.stat().st_size
                if total > ZIP_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"pasta maior que o limite de download "
                               f"({ZIP_MAX_BYTES // (1024*1024)} MB)",
                    )
                z.write(full, arcname=str(Path(base) / full.relative_to(root)))

    suffix = "com_fix" if fixed else "original"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{base}_{suffix}.zip"'},
    )


@router.get("/{run_id}/sarif")
def get_run_sarif(run_id: str, user: dict = Depends(current_user)):
    rec = store.get_run(run_id, owner_id=user["id"])
    if rec is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    if rec.get("status") != "done":
        raise HTTPException(status_code=400, detail="a run ainda não terminou")
    sarif = build_sarif(rec, repair_store.get_repair(run_id),
                        tool_version=APP_REVISION)
    return JSONResponse(
        content=sarif,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f'attachment; filename="resultados_{run_id}.sarif"'},
    )
