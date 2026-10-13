"""Rotas auxiliares de LLM — sob /api/llm/*.

`local/status` permite à SPA confirmar que o Ollama no SERVIDOR está respondendo
e listar os modelos baixados, para deixar claro ao cliente que a chamada
NÃO sai do PC dele e que ele não precisa ter Ollama localmente.
"""

from fastapi import APIRouter

from ..core.repair.llm import LOCAL_BASE_URL

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

router = APIRouter(prefix="/llm", tags=["llm"])


@router.get("/local/status")
def local_status() -> dict:
    """Estado do Ollama na máquina servidora (sempre verificado de localhost)."""
    base = LOCAL_BASE_URL.replace("/v1", "")
    info: dict = {"available": False, "base_url": LOCAL_BASE_URL, "models": []}
    if requests is None:
        info["error"] = "'requests' não instalado no servidor"
        return info
    try:
        r = requests.get(f"{base}/api/tags", timeout=2)
        if r.status_code == 200:
            tags = r.json().get("models", [])
            info["available"] = True
            info["models"] = sorted([m["name"] for m in tags])
        else:
            info["error"] = f"HTTP {r.status_code}"
    except requests.RequestException as e:
        info["error"] = str(e)[:200]
    return info
