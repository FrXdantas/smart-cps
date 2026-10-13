"""Rotas REST do reparo guiado por LLM, sob /api/repair."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth.deps import current_user
from . import repair_store, store

router = APIRouter(prefix="/repair", tags=["repair"])


class RepairRequest(BaseModel):
    run_id: str
    max_iters: int = 5
    unwind: int = 5
    timeout: int = 60
    solver: str = "boolector"
    # LLM (opcional): vêm da janela de configuração da UI. A api_key NÃO é
    # persistida em disco (o store a remove antes de salvar o registro).
    provider: str | None = None       # deepseek | groq | openrouter | custom
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
    dry_run: bool = False
    only_unrepaired: bool = False     # incremental: pula os já REPARADOS de um reparo anterior


@router.post("", status_code=201)
def create_repair(req: RepairRequest, user: dict = Depends(current_user)):
    """Repara (em background) os alvos com BUG de uma run concluída.
    Só permitido se a run for do próprio usuário."""
    run = store.get_run(req.run_id, owner_id=user["id"])
    if run is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    try:
        rec = repair_store.create_repair(req.run_id, req.model_dump())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"run_id": req.run_id, "status": rec["status"]}


@router.post("/{run_id}/cancel")
def cancel_repair(run_id: str, user: dict = Depends(current_user)):
    """Solicita a parada do reparo em andamento (só do dono). Cancelamento
    cooperativo: o alvo/iteração em curso termina e o laço não inicia o próximo;
    os alvos já reparados são preservados (status final `cancelled`)."""
    if store.get_run(run_id, owner_id=user["id"]) is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    repair_store.request_cancel(run_id)
    return {"run_id": run_id, "cancelling": True}


@router.get("/{run_id}")
def get_repair(run_id: str, user: dict = Depends(current_user)):
    """Status + resultados do reparo de uma run (só do dono)."""
    if store.get_run(run_id, owner_id=user["id"]) is None:
        raise HTTPException(status_code=404, detail="run não encontrada")
    rec = repair_store.get_repair(run_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="reparo não encontrado")
    return rec
