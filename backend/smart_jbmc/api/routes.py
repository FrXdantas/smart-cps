"""Rotas REST da plataforma SMART-JBMC (montadas sob /api)."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import __version__
from ..auth.deps import optional_user
from ..core.config import tools_status
from ..core.process import ferramentas_em_uso, memoria_maquina

router = APIRouter()


class ToolInfo(BaseModel):
    available: bool
    path: str | None = None
    source: str | None = None  # "env" | "vendored" | "path" | None


class MemInfo(BaseModel):
    """RAM da máquina para o aviso da barra superior (ver core.process)."""

    total_mb: int
    usado_mb: int
    pct: int
    nivel: str                      # ok | atencao | alerta


class EmUso(BaseModel):
    """Verificador ou compilador rodando agora (caixa da barra superior)."""

    nome: str
    papel: str                      # verificador | compilador
    rss_mb: int
    tempo_s: int


class HealthResponse(BaseModel):
    """Só `status` é público. O resto (versão, caminhos dos binários, LLM do
    servidor) sai apenas para chamador autenticado — ver `health()`."""

    status: str
    version: str | None = None
    tools: dict[str, ToolInfo] | None = None
    memoria: MemInfo | None = None
    em_uso: list[EmUso] | None = None


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health(user: dict[str, Any] | None = Depends(optional_user)) -> HealthResponse:
    """Estado do serviço e, para quem está logado, disponibilidade/origem das
    ferramentas externas.

    Anônimo recebe **só** `{"status": "ok"}`: o endpoint segue público como prova
    de vida (monitoramento externo continua funcionando), mas parou de entregar a
    versão do software e os **caminhos absolutos** dos binários no servidor a
    quem só abriu a URL — o sistema está publicado na internet, não é mais
    intranet. A SPA consulta autenticada pelo cookie e vê tudo.
    """
    if user is None:
        return HealthResponse(status="ok")
    return HealthResponse(
        status="ok",
        version=__version__,
        tools={name: ToolInfo(**info) for name, info in tools_status().items()},
        memoria=memoria_maquina(),
        em_uso=ferramentas_em_uso(),
    )
