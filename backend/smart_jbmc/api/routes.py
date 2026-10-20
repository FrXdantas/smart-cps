"""Rotas REST da plataforma SMART-JBMC (montadas sob /api)."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from .. import __version__
from ..auth.deps import optional_user
from ..core.config import tools_status
from ..core.process import ferramentas_em_uso, memoria_maquina
from ..core.repair import llm as _llm

router = APIRouter()


class ToolInfo(BaseModel):
    available: bool
    path: str | None = None
    source: str | None = None  # "env" | "vendored" | "path" | None


class LLMInfo(BaseModel):
    """LLM de reparo configurada NO SERVIDOR (.env), usada como fallback.

    A SPA consulta isto para não exigir chave do usuário quando o servidor já
    tem uma — é o que deixa o reparo disponível para todos os logados.
    """

    configured: bool
    model: str | None = None


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
    llm: LLMInfo | None = None
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
    intranet. A SPA consulta autenticada pelo cookie e vê tudo, inclusive
    `llm.configured`, de que o botão de reparo depende.
    """
    if user is None:
        return HealthResponse(status="ok")
    tem_chave = _llm.available()
    return HealthResponse(
        status="ok",
        version=__version__,
        tools={name: ToolInfo(**info) for name, info in tools_status().items()},
        llm=LLMInfo(
            configured=tem_chave,
            model=_llm.default_model() if tem_chave else None,
        ),
        memoria=memoria_maquina(),
        em_uso=ferramentas_em_uso(),
    )
