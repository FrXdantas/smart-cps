"""Aplicação FastAPI do SMART-JBMC.

- API REST sob ``/api`` (docs em ``/api/docs``).
- SPA estática (frontend/) servida em ``/``.
- CORS liberado para permitir front-end servido separadamente em dev.
"""

from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..auth.deps import current_user
from ..auth.routes import router as auth_router
from .llm import router as llm_router
from .repair import router as repair_router
from .routes import router
from .runs import router as runs_router
from .uploads import router as uploads_router

# .../smart-jbmc/backend/smart_jbmc/api/app.py -> raiz do projeto = parents[3]
PROJECT_ROOT = Path(__file__).resolve().parents[3]
FRONTEND_DIR = PROJECT_ROOT / "frontend"


def create_app() -> FastAPI:
    # docs_url/openapi_url desligados: as rotas automáticas do FastAPI são
    # públicas e entregavam a versão do software + o mapa inteiro da API a
    # qualquer um. Recriadas abaixo exigindo login — o conteúdo é o mesmo para
    # quem entra, muda só quem alcança.
    app = FastAPI(
        title="SMART-JBMC",
        version=__version__,
        docs_url=None,
        openapi_url=None,
    )

    protected = [Depends(current_user)]

    @app.get("/api/openapi.json", include_in_schema=False, dependencies=protected)
    def openapi_protegido() -> dict:
        return app.openapi()

    @app.get("/api/docs", include_in_schema=False, dependencies=protected)
    def docs_protegido():
        return get_swagger_ui_html(openapi_url="/api/openapi.json", title="SMART-JBMC — API")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router, prefix="/api")          # /api/health público, mas só devolve status a anônimo
    app.include_router(auth_router, prefix="/api")     # /api/auth/* (cada rota define sua proteção)
    app.include_router(runs_router, prefix="/api", dependencies=protected)
    app.include_router(repair_router, prefix="/api", dependencies=protected)
    app.include_router(uploads_router, prefix="/api", dependencies=protected)
    app.include_router(llm_router, prefix="/api", dependencies=protected)

    # Serve a SPA por último, na raiz (html=True -> index.html no /).
    if FRONTEND_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

    return app


app = create_app()
