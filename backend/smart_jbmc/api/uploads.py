"""Upload de pasta inteira do cliente para o servidor (sob /api/uploads).

Aceita multipart/form-data:
  - files: List[UploadFile]      (o input <... webkitdirectory> manda 1+ arquivos)
  - paths: List[str]              (caminho RELATIVO de cada arquivo dentro da pasta enviada)

Salva em data/uploads/<short_id>/<paths...> e devolve o caminho absoluto da
pasta criada — o cliente passa esse caminho em POST /api/runs.

Ao lado da pasta fica um `<short_id>.json` com o NOME LÓGICO que a pasta tinha
na máquina do usuário (ex.: "QuixBugs"). É o que a UI exibe no histórico, no
lugar do caminho absoluto do servidor — ver ``folder_label``.

As pastas em data/uploads/ permanecem enquanto existirem runs (são removidas
junto com data/runs/ em ``store.clear_runs()``).
"""

import json
import os
import re
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, UploadFile

from ..auth.deps import current_user
from ..core.config import PROJECT_ROOT

router = APIRouter(prefix="/uploads", tags=["uploads"])

UPLOADS_DIR = PROJECT_ROOT / "data" / "uploads"

MAX_FILES = int(os.environ.get("UPLOAD_MAX_FILES", "5000"))
MAX_BYTES = int(os.environ.get("UPLOAD_MAX_BYTES", str(500 * 1024 * 1024)))  # 500 MB
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._\-/]")


def _safe_relpath(p: str) -> str:
    """Normaliza e rejeita caminhos perigosos (.., absolutos, símbolos)."""
    if not p:
        raise HTTPException(status_code=400, detail="caminho vazio")
    # normaliza separadores e remove ./ no começo
    p = p.replace("\\", "/").lstrip("./")
    # nunca permitir absoluto
    if p.startswith("/"):
        raise HTTPException(status_code=400, detail=f"caminho absoluto recusado: {p}")
    parts = [seg for seg in p.split("/") if seg and seg != "."]
    for seg in parts:
        if seg == "..":
            raise HTTPException(status_code=400, detail=f"caminho escapa da pasta: {p}")
        if SAFE_NAME_RE.search(seg):
            raise HTTPException(
                status_code=400,
                detail=f"caractere inválido em '{seg}' (use só A-Z, a-z, 0-9, '.', '_', '-')",
            )
    if not parts:
        raise HTTPException(status_code=400, detail="caminho vazio após normalização")
    return "/".join(parts)


def _root_name(paths: list[str]) -> str:
    """Nome lógico da pasta enviada = primeiro segmento dos caminhos relativos.
    Arquivos soltos (sem pasta) caem no genérico "upload"."""
    for p in paths:
        parts = _safe_relpath(p).split("/")
        if len(parts) > 1:
            return parts[0]
    return "upload"


def folder_label(folder: str | None, owner_login: str | None = None) -> str:
    """Rótulo da pasta para a UI — nunca o caminho absoluto do servidor.

    Pasta enviada por upload vira ``<login>/<nome que ela tinha na máquina dele>``
    (ex.: ``ana/QuixBugs``); qualquer outra pasta (admin digitando o caminho de um
    benchmark local) vira só o nome do diretório.
    """
    if not folder:
        return ""
    try:
        p = Path(folder).resolve()
    except OSError:
        return ""
    name = p.name
    if UPLOADS_DIR.resolve() in p.parents:  # data/uploads/<owner_id>/<upload_id>
        meta = p.parent / f"{p.name}.json"
        try:
            name = json.loads(meta.read_text(encoding="utf-8")).get("name") or name
        except (OSError, ValueError):
            pass  # sidecar ausente (upload antigo) ou corrompido → cai no id
    return f"{owner_login}/{name}" if owner_login else name


@router.post("")
async def upload_folder(
    files: list[UploadFile],
    paths: list[str] = Form(...),
    user: dict = Depends(current_user),
) -> dict:
    if not files:
        raise HTTPException(status_code=400, detail="nenhum arquivo enviado")
    if len(files) != len(paths):
        raise HTTPException(
            status_code=400,
            detail=f"files ({len(files)}) e paths ({len(paths)}) devem ter o mesmo tamanho",
        )
    if len(files) > MAX_FILES:
        raise HTTPException(
            status_code=413,
            detail=f"muitos arquivos: {len(files)} > limite {MAX_FILES}",
        )

    # cada usuário escreve só sob data/uploads/<owner_id>/<upload_id>/
    owner_root = UPLOADS_DIR / str(user["id"])
    owner_root.mkdir(parents=True, exist_ok=True)
    upload_id = uuid.uuid4().hex[:12]
    dest_root = owner_root / upload_id
    dest_root.mkdir()

    total_bytes = 0
    count = 0
    try:
        for f, rel in zip(files, paths):
            rel_safe = _safe_relpath(rel)
            target = dest_root / rel_safe
            target.parent.mkdir(parents=True, exist_ok=True)
            # grava em chunks para não estourar memória em arquivos grandes
            with target.open("wb") as out:
                while True:
                    chunk = await f.read(1024 * 1024)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if total_bytes > MAX_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"upload excede limite ({MAX_BYTES // (1024*1024)} MB)",
                        )
                    out.write(chunk)
            count += 1
    except HTTPException:
        shutil.rmtree(dest_root, ignore_errors=True)
        raise
    except Exception as e:  # pragma: no cover
        shutil.rmtree(dest_root, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"falha ao gravar upload: {e}")

    name = _root_name(paths)
    try:
        (owner_root / f"{upload_id}.json").write_text(
            json.dumps({"name": name}), encoding="utf-8")
    except OSError:
        pass  # sem o sidecar a UI mostra o upload_id; não é motivo p/ perder o upload

    return {
        "upload_id": upload_id,
        "folder": str(dest_root.resolve()),
        "name": name,
        "label": f"{user['login']}/{name}",
        "count": count,
        "total_bytes": total_bytes,
    }


def remove_upload_folder(folder: str, owner_id: int) -> bool:
    """Remove UMA pasta de upload (`data/uploads/<owner_id>/<upload_id>/`) e o
    sidecar do nome. Recusa qualquer caminho fora desse espaço — pasta local
    digitada pelo admin **nunca** é apagada junto com a run."""
    try:
        p = Path(folder).resolve()
        owner_root = (UPLOADS_DIR / str(owner_id)).resolve()
    except OSError:
        return False
    if p.parent != owner_root or not p.is_dir():
        return False
    shutil.rmtree(p, ignore_errors=True)
    (owner_root / f"{p.name}.json").unlink(missing_ok=True)
    return True


def clear_uploads(owner_id: int | None = None) -> int:
    """Remove uploads. Com owner_id, só limpa data/uploads/<owner_id>/;
    sem ele, limpa tudo (uso interno/teste)."""
    removed = 0
    if not UPLOADS_DIR.is_dir():
        return 0
    if owner_id is not None:
        owner_root = UPLOADS_DIR / str(owner_id)
        if owner_root.is_dir():
            for d in owner_root.iterdir():
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)
                    removed += 1
                elif d.suffix == ".json":  # sidecar do nome lógico
                    d.unlink(missing_ok=True)
        return removed
    for d in UPLOADS_DIR.iterdir():
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    return removed
