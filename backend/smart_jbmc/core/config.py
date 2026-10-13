"""Configuração e resolução de ferramentas externas.

Cada ferramenta (esbmc, jbmc, kotlinc, ...) é resolvida em 3 níveis de
prioridade, o que torna o projeto portátil entre máquinas:

    1. variável no .env  (ex.: ESBMC_PATH=/home/.../esbmc)   -> explícito
    2. tools/<nome>      (binário copiado dentro do projeto)  -> "vendorizado"
    3. PATH do sistema   (shutil.which)                        -> fallback

Sem dependências externas (stdlib).
"""

import os
import shutil
from pathlib import Path

# .../smart-jbmc/backend/smart_jbmc/core/config.py -> raiz do projeto = parents[3]
PROJECT_ROOT = Path(__file__).resolve().parents[3]
TOOLS_DIR = PROJECT_ROOT / "tools"
DOTENV_PATH = PROJECT_ROOT / ".env"

# nome lógico -> variável de ambiente correspondente
TOOL_ENV_VARS = {
    "esbmc": "ESBMC_PATH",
    "jbmc": "JBMC_PATH",
    "kotlinc": "KOTLINC_PATH",
    "javac": "JAVAC_PATH",
    "java": "JAVA_PATH",
    "gcc": "GCC_PATH",
}

_dotenv_loaded = False


def load_env(path: Path | None = None) -> None:
    """Carrega o .env do projeto para os.environ (sem sobrescrever o que já existe)."""
    global _dotenv_loaded
    if _dotenv_loaded:
        return
    path = path or DOTENV_PATH
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    _dotenv_loaded = True


def resolve_tool(tool: str) -> str | None:
    """Caminho absoluto da ferramenta, ou None se não encontrada."""
    load_env()

    # 1. .env / variável de ambiente
    env_var = TOOL_ENV_VARS.get(tool)
    if env_var:
        configured = os.environ.get(env_var)
        if configured and Path(configured).exists():
            return os.path.abspath(configured)

    # 2. tools/<tool> vendorizado
    vendored = TOOLS_DIR / tool
    if vendored.exists():
        return str(vendored.resolve())

    # 3. PATH do sistema
    return shutil.which(tool)


def tools_status() -> dict[str, dict]:
    """Mapa nome -> {available, path, source} para todas as ferramentas."""
    status = {}
    for tool, env_var in TOOL_ENV_VARS.items():
        path = resolve_tool(tool)
        if path is None:
            source = None
        elif os.environ.get(env_var) and Path(os.environ[env_var]).exists():
            source = "env"
        elif (TOOLS_DIR / tool).exists():
            source = "vendored"
        else:
            source = "path"
        status[tool] = {"available": path is not None, "path": path, "source": source}
    return status
