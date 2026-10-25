"""Verificação C com ESBMC (frontend C/C++ + solver SMT)."""

import functools
import os
import tempfile

from ..compiler import _require
from ..constants import DEFAULT_TIMEOUT, DEFAULT_UNWIND
from ..process import ToolResult, limite_memoria_mb, run_cmd

SOLVER_FLAGS = {
    "boolector": ["--boolector"],
    "z3": ["--z3"],
    "mathsat": ["--mathsat"],
    "bitwuzla": ["--bitwuzla"],
    "cvc": ["--cvc"],
}

# Concorrência em duas partes (rv. 2.4-cps, medição de 24/10/2026 em
# deltas_semanais/semana_03_20a27-10/medicoes_esbmc86/opcao_b):
# - THREAD_FLAGS explora as intercalações: conjuntos de dormência com limite de 3
#   trocas de contexto (Cordeiro e Fischer, ICSE 2011). A busca sem limite
#   (--no-por --sleep-sets, adotada na 2.1) perdia o defeito real do FreeRTOS #1236
#   (tempo esgotado, 14,9 GB); com o limite ele sai em 9 s. Nos 4 programas de
#   referência o limite custa mais tempo (47 a 98 s), mas todos seguem certos.
# - RACE_FLAGS procura corrida de dados e impasse (CWE-362, CWE-833). É a parte cara
#   de provar SAFE: sem ela, a versão corrigida do #1236 sai SAFE em 24 s.
THREAD_FLAGS = ["--sleep-sets", "--context-bound", "3"]
RACE_FLAGS = ["--data-races-check", "--deadlock-check"]
CONCURRENCY_FLAGS = THREAD_FLAGS + RACE_FLAGS


def concurrency_flags(concurrency: bool, race_check: bool | None = None) -> list[str]:
    """Flags de threads. `race_check` None = igual a `concurrency` (runs e clientes
    anteriores à separação). Procurar corrida implica explorar as threads."""
    if race_check is None:
        race_check = concurrency
    if race_check:
        return THREAD_FLAGS + RACE_FLAGS
    return list(THREAD_FLAGS) if concurrency else []


def property_flags(concurrency: bool) -> list[str]:
    """`--multi-property` só sem concorrência. Com threads, o ESBMC 8.6 procura todas
    as propriedades em todas as intercalações: o caso FreeRTOS #1236 estourou 10 GB e
    180 s, e o PASSED nesse modo só vale para as intercalações que ele percorreu.
    Sem a opção, o ESBMC para no primeiro defeito (só ele aparece no relatório)."""
    return [] if concurrency else ["--multi-property"]

# Programa mínimo p/ sondar se um solver foi REALMENTE compilado no build.
# Não dá p/ confiar em `esbmc --help`: ele lista `--mathsat` mesmo quando o
# solver não foi linkado — só o runtime acusa "has not been built into this
# version of ESBMC". Por isso a sondagem roda o ESBMC de verdade (cacheada).
# O programa PRECISA gerar uma VCC (aqui, divisão por `x` nondet → div-by-zero)
# para FORÇAR o ESBMC a carregar o solver; um `return 0;` trivial não tem VCC,
# o solver nunca é invocado e a sondagem daria falso-positivo.
_PROBE_C = "int main(void){int x;return 100/x;}\n"
_NOT_BUILT = "has not been built into this version"


@functools.lru_cache(maxsize=8)
def solver_available(solver: str) -> bool:
    """True se `solver` está compilado neste build do ESBMC (sondagem real,
    cacheada). Em caso de dúvida (ESBMC ausente, falha ao sondar) assume True
    para não bloquear a run — o erro, se houver, aparece na verificação real."""
    if solver not in SOLVER_FLAGS:
        return False
    probe = None
    try:
        with tempfile.NamedTemporaryFile(
                "w", suffix=".c", delete=False, encoding="utf-8") as f:
            f.write(_PROBE_C)
            probe = f.name
        out = run_cmd([_require("esbmc"), probe] + SOLVER_FLAGS[solver],
                      timeout=30).raw
    except Exception:  # noqa: BLE001 — não conseguiu sondar → não bloqueia
        return True
    finally:
        if probe:
            try:
                os.unlink(probe)
            except OSError:
                pass
    return _NOT_BUILT not in out


def available_solvers() -> list[str]:
    """Lista, em ordem, os solvers efetivamente disponíveis neste build."""
    return [s for s in SOLVER_FLAGS if solver_available(s)]


@functools.lru_cache(maxsize=1)
def esbmc_version() -> str | None:
    """Versão do ESBMC deste build (p/ reprodutibilidade no SARIF). None se ausente."""
    try:
        out = run_cmd([_require("esbmc"), "--version"], timeout=15).raw.strip()
    except Exception:  # noqa: BLE001
        return None
    return out.splitlines()[0].strip() if out else None


# Estratégias de verificação (como o ESBMC trata os loops):
#   bounded     — `--unwind N --no-unwinding-assertions`: corta o loop no bound
#                 e NÃO acusa se foi insuficiente (SAFE só vale até o bound). Rápido.
#   sound       — `--unwind N` (mantém unwinding assertions): loop não coberto vira
#                 UNKNOWN em vez de SAFE vacuamente verdadeiro.
#   incremental — `--incremental-bmc`: SOBE o unwind sozinho até achar contraexemplo
#                 ou esgotar tempo; acha bug alcançável sem você adivinhar o N.
#   kinduction  — `--k-induction`: tenta PROVAR o loop por indução (sem desenrolar
#                 tudo); pode dar SAFE/BUG/UNKNOWN. Não limitado pelo `unwind`.
STRATEGIES = ("bounded", "sound", "incremental", "kinduction")


def run_esbmc(filec, unwind=DEFAULT_UNWIND, timeout=DEFAULT_TIMEOUT,
              concurrency=False, solver="boolector", nice=10, race_check=None,
              unwinding_assertions=False, strategy=None,
              unsigned_overflow=False, nan_check=False, include_dirs=None, function=None,
              max_mem_mb=None) -> ToolResult:
    """
    ESBMC com as flags do TASE2025 (CASTLE). Saída em TEXTO (ESBMC >= 8 não
    aceita --json-ui). O solver SMT é escolhido por argumento.

    `strategy` ∈ {bounded, sound, incremental, kinduction} (ver `STRATEGIES`).
    Compat.: se `strategy is None`, deriva de `unwinding_assertions` (True→sound,
    False→bounded). `incremental`/`kinduction` ignoram o `unwind` fixo (o ESBMC
    controla a profundidade) e são limitados só pelo `--timeout`.

    `unsigned_overflow`: quando True, adiciona `--unsigned-overflow-check`. O
    `--overflow` (overflow COM SINAL, que é UB em C) é sempre checado; overflow
    UNSIGNED é wraparound DEFINIDO pela norma C, então o ESBMC só o reporta com
    este opt-in. Liga para caçar overflow de `size_t`/`unsigned` (ex.: CWE-190 em
    cálculo de tamanho de alocação); deixa desligado p/ não acusar wraparound
    intencional (hash/ring buffer/aritmética modular) como bug.
    """
    if strategy is None:
        strategy = "sound" if unwinding_assertions else "bounded"

    # `filec` pode ser UM arquivo (str) ou VÁRIOS (list): a forma multi-arquivo
    # linka `main + deps` numa única unidade — o ESBMC compila todos juntos, então
    # as deps NÃO viram havoc (necessário p/ achar bug em projeto real multi-arquivo).
    files = list(filec) if isinstance(filec, (list, tuple)) else [filec]

    cmd = [
        _require("esbmc"), *files,
        "--overflow",
        "--memory-leak-check",
        *property_flags(bool(concurrency_flags(concurrency, race_check))),
        "--show-stacktrace",
        "--timeout", str(timeout),
    ]
    # Include paths (-I): necessários p/ verificar uma unidade de um projeto real
    # (ex.: ggml-quants.c do llama.cpp), cujos headers vivem em ggml/include etc.
    # Sem isto o frontend dá PARSING ERROR antes de verificar; funções externas
    # sem corpo o ESBMC abstrai (havoc), então NÃO é preciso buildar o projeto.
    for d in (include_dirs or []):
        cmd += ["-I", d]
    # `--function <nome>`: verifica ESSA função como ponto de entrada — o ESBMC
    # HAVOCA os argumentos (nondet) de graça, dispensando escrever um `main()`.
    # Permite checar uma rotina isolada de um projeto sem corpo de chamador.
    if function:
        cmd += ["--function", function]
    if unsigned_overflow:
        cmd.append("--unsigned-overflow-check")
    # `--nan-check`: operação em ponto flutuante que produz NaN (0/0, inf-inf).
    # Opt-in como o unsigned: código que trata NaN de propósito viraria alarme.
    if nan_check:
        cmd.append("--nan-check")
    if strategy == "incremental":
        cmd.append("--incremental-bmc")
    elif strategy == "kinduction":
        cmd.append("--k-induction")
    elif strategy == "sound":
        cmd += ["--unwind", str(unwind)]                 # mantém unwinding assertions
    else:  # bounded
        cmd += ["--unwind", str(unwind), "--no-unwinding-assertions"]
    cmd += SOLVER_FLAGS.get(solver, SOLVER_FLAGS["boolector"])
    cmd += concurrency_flags(concurrency, race_check)
    # `max_mem_mb` vem do orquestrador já rateado pelo `jobs`; sozinho, o
    # verificador assume que é o único rodando.
    mem = limite_memoria_mb() if max_mem_mb is None else max_mem_mb
    return run_cmd(cmd, timeout=timeout + 10, nice=nice, max_mem_mb=mem)
