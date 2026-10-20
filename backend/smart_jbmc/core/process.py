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


# Faixas do aviso de memória na barra superior (% de RAM em uso na máquina).
MEM_ATENCAO_PCT = 70
MEM_ALERTA_PCT = 85


def memoria_maquina(meminfo: str = "/proc/meminfo") -> dict | None:
    """RAM da máquina: total, em uso e o nível do aviso. None fora do Linux.

    "Em uso" é total menos MemAvailable, que já desconta o cache que o kernel
    devolve sob pressão; MemFree sozinho faria a máquina parecer sempre cheia.
    No Docker, /proc/meminfo mostra a memória do computador, não a do contêiner,
    que é o que interessa: um ESBMC pesado disputa a RAM com o resto da máquina.
    """
    try:
        campos = {}
        with open(meminfo, encoding="ascii") as f:
            for linha in f:
                nome, valor = linha.split(":", 1)
                campos[nome] = int(valor.split()[0])      # kB
        total = campos["MemTotal"] // 1024
        livre = campos.get("MemAvailable", campos.get("MemFree", 0)) // 1024
    except (OSError, KeyError, ValueError):
        return None
    usado = max(0, total - livre)
    pct = round(100 * usado / total) if total else 0
    nivel = "alerta" if pct >= MEM_ALERTA_PCT else "atencao" if pct >= MEM_ATENCAO_PCT else "ok"
    return {"total_mb": total, "usado_mb": usado, "pct": pct, "nivel": nivel}


# Processos que a barra superior mostra durante uma verificação. O kotlinc é um
# script que vira `java ... org.jetbrains.kotlin...`, então é reconhecido pela
# linha de comando; os demais pelo nome do processo.
_VERIFICADORES = {"esbmc", "jbmc"}
_COMPILADORES = {"javac", "kotlinc"}


def ferramentas_em_uso(proc: str = "/proc") -> list[dict]:
    """Verificadores e compiladores rodando agora: nome, papel, RAM e tempo.

    Lê /proc direto (sem psutil). No Docker só aparecem os processos do
    contêiner, que são justamente os da ferramenta. Lista vazia fora do Linux.
    """
    try:
        pids = [d for d in os.listdir(proc) if d.isdigit()]
        with open(os.path.join(proc, "uptime"), encoding="ascii") as f:
            uptime = float(f.read().split()[0])
        hz = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        return []
    achados = []
    for pid in pids:
        base = os.path.join(proc, pid)
        try:
            with open(os.path.join(base, "comm"), encoding="utf-8") as f:
                nome = f.read().strip()
            if nome == "java":
                with open(os.path.join(base, "cmdline"), "rb") as f:
                    if b"kotlin" not in f.read():
                        continue
                nome = "kotlinc"
            if nome not in _VERIFICADORES | _COMPILADORES:
                continue
            rss_kb = 0
            with open(os.path.join(base, "status"), encoding="utf-8") as f:
                for linha in f:
                    if linha.startswith("VmRSS:"):
                        rss_kb = int(linha.split()[1])
                        break
            with open(os.path.join(base, "stat"), encoding="utf-8") as f:
                # o nome vem entre parênteses e pode ter espaços: corta depois dele
                campos = f.read().rsplit(")", 1)[1].split()
            if campos[0] == "Z":
                continue                              # já terminou (zumbi), sem memória
            inicio_s = int(campos[19]) / hz          # campo 22 do stat (starttime)
        except (OSError, ValueError, IndexError):
            continue                                  # processo terminou no meio da leitura
        achados.append({
            "nome": nome,
            "papel": "verificador" if nome in _VERIFICADORES else "compilador",
            "rss_mb": rss_kb // 1024,
            "tempo_s": max(0, round(uptime - inicio_s)),
        })
    return sorted(achados, key=lambda a: (a["papel"] != "verificador", -a["rss_mb"]))


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
