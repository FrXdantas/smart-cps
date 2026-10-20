"""Execução (background) e persistência do reparo, por run, em data/runs/<id>/repair.json."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ..core.config import PROJECT_ROOT
from ..core.repair import repair_run
from . import store

RUNS_DIR = PROJECT_ROOT / "data" / "runs"

_executor = ThreadPoolExecutor(max_workers=1)
_lock = threading.Lock()
_repairs: dict[str, dict] = {}
_cancels: set[str] = set()        # run_ids com cancelamento de reparo solicitado


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
    d = RUNS_DIR / record["run_id"]
    d.mkdir(parents=True, exist_ok=True)
    (d / "repair.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def _set(record: dict) -> None:
    with _lock:
        _repairs[record["run_id"]] = record
    _save(record)


def create_repair(run_id: str, opts: dict) -> dict:
    run = store.get_run(run_id)
    if run is None:
        raise ValueError(f"run não encontrada: {run_id}")
    if run.get("status") != "done":
        raise ValueError("a run ainda não terminou")
    targets = (run.get("result") or {}).get("targets", [])
    # O oráculo (re-verificação BMC) precisa usar a MESMA propriedade da run
    # original: se a run achou o bug com --unsigned-overflow-check, o reparo tem
    # de re-verificar com ela também — senão diria FIX_OK sem checar o overflow
    # unsigned. Herdado da config da run, não pedido de novo na RepairRequest.
    opts["unsigned_overflow"] = bool((run.get("config") or {}).get("unsigned_overflow", False))
    # Mesma razão para a estratégia de bound: re-verificar um patch da via JVM em
    # `bounded` quando a run rodou `sound` (ou vice-versa) compara regimes distintos.
    opts["strategy"] = (run.get("config") or {}).get("strategy")
    # E pelas mesmas razões: checagem de race/deadlock, -I e ponto de entrada.
    # Sem `concurrency`, um patch de race era re-verificado SEM procurar race e
    # saía FIX_OK até com o código idêntico (confirmado em 09/10/2026).
    cfg = run.get("config") or {}
    opts["concurrency"] = bool(cfg.get("concurrency", False))
    opts["include_dirs"] = list(cfg.get("include_dirs") or [])
    opts["function"] = cfg.get("function") or None
    opts["nan_check"] = bool(cfg.get("nan_check", False))
    # Bound, tempo e solver também vêm da run, e não da tela no momento do
    # reparo: com unwind menor que o da run, o patch passava num regime mais
    # fraco do que o que achou o bug (visto no teste de 18/10/2026). Os valores
    # do pedido ficam só como reserva para runs antigas sem esses campos.
    for k in ("unwind", "timeout", "solver"):
        if cfg.get(k) is not None:
            opts[k] = cfg[k]
    # A API key NUNCA é persistida em disco: fica só em memória, repassada ao worker.
    api_key = opts.pop("api_key", None)
    # Reparo anterior (antes de sobrescrever) — base do modo incremental.
    prior = get_repair(run_id)
    prior_results = (prior.get("result") or {}).get("targets") if prior else None
    record = {
        "run_id": run_id, "status": "running", "created_at": _now(),
        "finished_at": None, "options": opts, "result": None, "error": None,
        "progress": {"done": 0, "total": 0, "iter": 0, "max": opts.get("max_iters", 5)},
    }
    _set(record)
    _executor.submit(_execute, run_id, targets, opts, api_key, prior_results)
    return record


def _execute(run_id: str, targets: list, opts: dict, api_key: str | None = None,
             prior_results: list | None = None) -> None:
    record = get_repair(run_id)

    def _progress(done, total, i, n, tok_s=None):
        with _lock:
            prev = (record.get("progress") or {}).get("tok_s")
            # mantém a última velocidade conhecida quando a chamada é o início de
            # uma iteração (tok_s=None), p/ não piscar durante a geração do LLM
            record["progress"] = {"done": done, "total": total, "iter": i, "max": n,
                                  "tok_s": tok_s if tok_s is not None else prev}

    def _checkpoint(agg):
        # persiste o parcial após cada alvo (resumível em caso de crash)
        with _lock:
            record["result"] = agg
        _save(record)

    try:
        work_dir = str(RUNS_DIR / run_id / "repairs")
        res = repair_run(
            targets, unwind=opts["unwind"], timeout=opts["timeout"],
            solver=opts["solver"], max_iters=opts["max_iters"],
            model=opts.get("model"), base_url=opts.get("base_url"),
            api_key=api_key, dry_run=opts.get("dry_run", False),
            work_dir=work_dir, on_progress=_progress,
            prior_results=prior_results,
            only_unrepaired=opts.get("only_unrepaired", False),
            unsigned_overflow=opts.get("unsigned_overflow", False),
            nan_check=opts.get("nan_check", False),
            strategy=opts.get("strategy"),
            concurrency=opts.get("concurrency", False),
            include_dirs=opts.get("include_dirs") or None,
            function=opts.get("function"),
            on_checkpoint=_checkpoint,
            should_cancel=lambda: is_cancelled(run_id),
        )
        record["status"] = "cancelled" if res.get("cancelled") else "done"
        record["result"] = res
    except Exception as e:  # noqa: BLE001
        record["status"] = "error"
        record["error"] = str(e)
    finally:
        clear_cancel(run_id)
        record["finished_at"] = _now()
        _set(record)


def get_repair(run_id: str) -> dict | None:
    with _lock:
        if run_id in _repairs:
            return _repairs[run_id]
    p = RUNS_DIR / run_id / "repair.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return None


def clear() -> None:
    """Esquece os reparos em memória (o disco é limpo junto com as runs)."""
    with _lock:
        _repairs.clear()


def forget(run_id: str) -> None:
    """Esquece o reparo de UMA run apagada (o `repair.json` some com a pasta)."""
    with _lock:
        _repairs.pop(run_id, None)
        _cancels.discard(run_id)
