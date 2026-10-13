"""Registro e execução de runs (em background) com persistência em data/runs/<id>/."""

import json
import shutil
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import PROJECT_ROOT
from ..core.orchestrator import run_verification
from .uploads import folder_label

RUNS_DIR = PROJECT_ROOT / "data" / "runs"

_executor = ThreadPoolExecutor(max_workers=2)
_lock = threading.Lock()
_runs: dict[str, dict] = {}
_cancels: set[str] = set()        # run_ids com cancelamento solicitado


def request_cancel(run_id: str) -> None:
    with _lock:
        _cancels.add(run_id)


def is_cancelled(run_id: str) -> bool:
    with _lock:
        return run_id in _cancels


def clear_cancel(run_id: str) -> None:
    with _lock:
        _cancels.discard(run_id)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _save(record: dict) -> None:
    d = RUNS_DIR / record["id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "run.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def _set(record: dict) -> None:
    with _lock:
        _runs[record["id"]] = record
    _save(record)


def create_run(config: dict, owner_id: int, owner_login: str) -> dict:
    run_id = uuid.uuid4().hex[:12]
    record = {
        "id": run_id, "status": "running", "created_at": _now(),
        "finished_at": None, "config": config, "result": None, "error": None,
        "progress": {"phase": "queued", "done": 0, "total": 0},
        "owner_id": owner_id, "owner_login": owner_login,
    }
    _set(record)
    _executor.submit(_execute, run_id, config)
    return record


def _execute(run_id: str, config: dict) -> None:
    record = get_run(run_id)

    def _progress(phase, done, total):
        with _lock:
            record["progress"] = {"phase": phase, "done": done, "total": total}

    try:
        build_root = str(RUNS_DIR / run_id / "build")
        rr = run_verification(
            config["folder"], unwind=config["unwind"], timeout=config["timeout"],
            jobs=config["jobs"], solver=config["solver"],
            concurrency=config.get("concurrency", False), build_root=build_root,
            unwinding_assertions=config.get("unwinding_assertions", False),
            strategy=config.get("strategy"),
            unsigned_overflow=config.get("unsigned_overflow", False),
            include_dirs=config.get("include_dirs") or None,
            link_unit=config.get("link_unit") or None,
            function=config.get("function") or None,
            on_progress=_progress, should_cancel=lambda: is_cancelled(run_id),
        )
        record["status"] = "cancelled" if rr.cancelled else "done"
        record["result"] = asdict(rr)
    except Exception as e:  # noqa: BLE001
        record["status"] = "error"
        record["error"] = str(e)
    finally:
        clear_cancel(run_id)
        record["finished_at"] = _now()
        _set(record)


def get_run(run_id: str, owner_id: int | None = None) -> dict | None:
    with _lock:
        rec = _runs.get(run_id)
    if rec is None:
        p = RUNS_DIR / run_id / "run.json"
        if p.is_file():
            rec = json.loads(p.read_text(encoding="utf-8"))
    if rec is None:
        return None
    # filtra por dono se solicitado — runs sem owner_id (legado) ficam ocultas
    if owner_id is not None and rec.get("owner_id") != owner_id:
        return None
    return rec


def _brief(rec: dict) -> dict:
    folder = (rec.get("config") or {}).get("folder")
    return {
        "id": rec["id"], "status": rec["status"], "created_at": rec.get("created_at"),
        "folder": folder,
        # rótulo p/ a UI: o histórico mostra "ana/QuixBugs", nunca o caminho do servidor
        "folder_label": folder_label(folder, rec.get("owner_login")),
        "summary": (rec.get("result") or {}).get("summary"),
        "owner_id": rec.get("owner_id"),
        "owner_login": rec.get("owner_login"),
    }


def delete_run(run_id: str, owner_id: int | None = None) -> dict:
    """Apaga UMA run: `data/runs/<id>/` (inclui `repair.json` e os patches) +
    o registro em memória + a pasta de upload dela, **quando nenhuma outra run
    do dono ainda aponta para lá** — duas runs sobre a mesma pasta são comuns
    (mudou o unwind e rodou de novo).

    É o que dá ao usuário o controle de apagar só o que ele quiser, sem deixar
    lixo no servidor. Devolve o que foi removido; `{}` se a run não é dele.
    """
    rec = get_run(run_id, owner_id=owner_id)
    if rec is None:
        return {}
    folder = (rec.get("config") or {}).get("folder")
    shutil.rmtree(RUNS_DIR / run_id, ignore_errors=True)
    with _lock:
        _runs.pop(run_id, None)
        _cancels.discard(run_id)
    upload_removed = False
    if folder and rec.get("owner_id") is not None:
        ainda_em_uso = any(r.get("folder") == folder for r in list_runs(owner_id=rec["owner_id"]))
        if not ainda_em_uso:
            from .uploads import remove_upload_folder
            upload_removed = remove_upload_folder(folder, owner_id=rec["owner_id"])
    return {"deleted": run_id, "upload_removed": upload_removed}


def clear_runs(owner_id: int | None = None) -> int:
    """Apaga o histórico do usuário: registros em memória + pastas
    data/runs/<id>/ pertencentes a ele + uploads dele. Sem owner_id passado,
    limpa TUDO (uso interno/teste). Devolve quantas pastas foram removidas."""
    removed = 0
    if RUNS_DIR.is_dir():
        for d in RUNS_DIR.iterdir():
            if not d.is_dir():
                continue
            if owner_id is not None:
                rec = None
                p = d / "run.json"
                if p.is_file():
                    try:
                        rec = json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        rec = None
                if not rec or rec.get("owner_id") != owner_id:
                    continue
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    # também esquece em memória os registros agora apagados
    with _lock:
        if owner_id is None:
            _runs.clear()
        else:
            stale = [rid for rid, r in _runs.items() if r.get("owner_id") == owner_id]
            for rid in stale:
                _runs.pop(rid, None)
    # uploads do mesmo usuário
    try:
        from .uploads import clear_uploads
        clear_uploads(owner_id=owner_id)
    except Exception:
        pass
    return removed


def list_runs(owner_id: int | None = None) -> list[dict]:
    seen: dict[str, dict] = {}
    with _lock:
        for rid, rec in _runs.items():
            if owner_id is not None and rec.get("owner_id") != owner_id:
                continue
            seen[rid] = _brief(rec)
    if RUNS_DIR.is_dir():
        for d in RUNS_DIR.iterdir():
            p = d / "run.json"
            if d.is_dir() and d.name not in seen and p.is_file():
                try:
                    rec = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if owner_id is not None and rec.get("owner_id") != owner_id:
                    continue
                seen[d.name] = _brief(rec)
    return sorted(seen.values(), key=lambda x: x.get("created_at") or "", reverse=True)
