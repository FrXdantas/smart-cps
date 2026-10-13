"""Execução de subprocessos (portado de run_cmd do JBMC_Projeto.py)."""

import os
import resource
import subprocess
from dataclasses import dataclass

from .constants import DEFAULT_MEM_TOTAL_MB, MIN_MEM_POR_PROCESSO_MB


def _env_int(nome: str, padrao: int) -> int:
    try:
        return int(os.environ.get(nome, padrao))
    except ValueError:
        return padrao


def limite_memoria_mb(jobs: int = 1) -> int:
    """Teto de memória para UM processo de verificador, em MB (0 = sem teto).

    O orçamento é TOTAL e rateado entre os `jobs` que rodam em paralelo, para que
    aumentar `jobs` não multiplique o consumo máximo da máquina (ver
    constants.DEFAULT_MEM_TOTAL_MB). Respeita um piso por processo: abaixo dele o
    verificador nem carrega o modelo da JVM, e o rateio viraria ERROR garantido.

    Só os verificadores usam: `javac`/`kotlinc` são JVMs e reservam um espaço de
    endereçamento virtual muito maior que o heap real — impor RLIMIT_AS a eles faz
    a JVM abortar no arranque ("insufficient memory for the Java Runtime
    Environment"). Por isso o teto é opt-in por chamada, não default do run_cmd.
    """
    por_processo = _env_int("SMART_JBMC_MAX_MEM_MB", 0)
    if por_processo:
        return por_processo          # override explícito: ignora o rateio
    total = _env_int("SMART_JBMC_MAX_MEM_TOTAL_MB", DEFAULT_MEM_TOTAL_MB)
    if total <= 0:
        return 0                     # sem teto (assumido pelo operador)
    return max(MIN_MEM_POR_PROCESSO_MB, total // max(1, jobs))


@dataclass
class ToolResult:
    """Resultado de um subprocesso (verificador/compilador)."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def raw(self) -> str:
        """stdout + stderr concatenados (como o pipeline original consome)."""
        return self.stdout + self.stderr

    @property
    def timed_out(self) -> bool:
        return self.returncode == -2


def run_cmd(cmd, cwd=None, timeout=None, nice=None, max_mem_mb=None) -> ToolResult:
    """
    Executa `cmd`. Se `nice` for dado e a plataforma suportar (Linux/macOS),
    o subprocesso inicia com `os.nice(nice)` antes do exec — reduz a
    prioridade de escalonamento sem afetar este processo Python.

    `max_mem_mb` impõe RLIMIT_AS ao subprocesso (None/0 = sem teto). É proteção
    de MÁQUINA, não de desempenho: o timeout sozinho não basta porque o
    verificador pode alocar dezenas de GB antes de o prazo vencer (ver
    DEFAULT_MAX_MEM_MB). Ao bater no teto, o verificador morre com falha de
    alocação e o alvo é reportado como erro — em vez de levar o sistema junto.
    Quem passa o teto são os verificadores (ver `limite_memoria_mb`); os
    compiladores NÃO, porque são JVMs e abortariam no arranque.
    """
    limite_mb = max_mem_mb or 0

    def _preparar_filho():
        if nice is not None and hasattr(os, "nice"):
            os.nice(nice)
        if limite_mb:
            b = limite_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (b, b))

    kwargs = dict(capture_output=True, text=True, cwd=cwd, timeout=timeout)
    if (nice is not None and hasattr(os, "nice")) or limite_mb:
        kwargs["preexec_fn"] = _preparar_filho
    try:
        p = subprocess.run(cmd, **kwargs)
        return ToolResult(p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return ToolResult(-2, "", f"TIMEOUT: command exceeded {timeout}s")
    except Exception as e:  # noqa: BLE001 — qualquer falha vira ToolResult de erro
        return ToolResult(-1, "", str(e))
