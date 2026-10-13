"""Verificação Java/Kotlin com JBMC (suite CBMC), via bounded model checking."""

from ..compiler import _require
from ..constants import DEFAULT_TIMEOUT, DEFAULT_UNWIND
from ..process import ToolResult, limite_memoria_mb, run_cmd

# Estratégias da via JVM — espelham as do ESBMC (core.verifiers.esbmc.STRATEGIES).
# O JBMC não tem `--incremental-bmc` nem `--k-induction`, então só as duas
# primeiras existem aqui; `incremental`/`kinduction` caem em `bounded`.
#
#   bounded (padrão) — `--no-unwinding-assertions`: o resultado vale ATÉ o bound.
#   sound            — mantém as unwinding assertions: quando o bound não cobre o
#                      laço, o veredicto vira UNKNOWN em vez de SAFE.
#
# Por que `bounded` é o padrão (medido em 2026-07-26): com as unwinding assertions
# ligadas — o default do CBMC, e o que a ferramenta usava — o JBMC (a) reporta a
# própria unwinding assertion como violação, e a ferramenta a classificava como
# BUG/CWE-617 mesmo em programa provadamente seguro (falso positivo), e (b) ao
# construir o error trace dessa assertion sobre todo o estado desenrolado,
# ESTOURA a memória (~1 GB a cada 3 s). Teste decisivo: um programa que usa
# `Integer.MAX_VALUE` foi morto aos 60 s com as assertions ligadas e deu
# VERIFICATION SUCCESSFUL instantâneo com `--no-unwinding-assertions`.
# A via C já usava `bounded` por padrão desde 31/05/2026 — esta é a mesma escolha,
# aplicada tarde à via JVM.
STRATEGIES = ("bounded", "sound")

# Marcas de "esta classe não tem ponto de entrada". O JBMC precisa de um `main`;
# uma classe de biblioteca (ex.: o algoritmo `LIS`, chamado pelo harness `Main`)
# não tem. Isso NÃO é erro do verificador nem defeito do código — é alvo
# inaplicável. Antes virava ERROR e inflava o relatório (metade dos 100 alvos do
# QuixBugs eram isso), escondendo os erros de verdade.
_NO_ENTRY_MARKERS = (
    "no entry point",
    "main symbol resolution failed",
    "symbol resolution failed",
    "is ambiguous between",
)


def is_no_entry_point(raw: str) -> bool:
    """True se a saída do JBMC indica ausência/ambiguidade de ponto de entrada."""
    low = (raw or "").lower()
    return any(m in low for m in _NO_ENTRY_MARKERS)


def _jbmc_invoke(cls, classpath, unwind, timeout, nice, entry=None,
                 strategy="bounded", max_mem_mb=None) -> ToolResult:
    cmd = [
        _require("jbmc"), cls,
        "--classpath", classpath,
        "--unwind", str(unwind),
        "--json-ui",
        # OBRIGATÓRIO, não é otimização: sem `--stop-on-fail` o JBMC 6.9.0 constrói
        # um error trace por propriedade violada e TRAVA em "Building error trace"
        # a partir do segundo — consumo de memória sem limite (medido: >3 GiB e
        # crescendo na fixture trivial ArrayOob.java, morto só pelo timeout; chegou
        # a 26 GiB e congelou a máquina de dev). O SAT em si leva ~1 ms. Com a flag:
        # 14 MB de pico e 0,01 s, com o trace COMPLETO da primeira violação.
        # Implica `--trace`, que é justamente o que o parser de contraexemplo lê.
        # Ressalva: entrega só a PRIMEIRA propriedade violada; se essa for uma
        # unwinding assertion (só ocorre no modo `sound`), ela mascara um bug real
        # que viesse depois.
        "--stop-on-fail",
    ]
    if strategy != "sound":
        cmd.append("--no-unwinding-assertions")
    if entry:
        cmd += ["--function", entry]
    # `max_mem_mb` vem do orquestrador já rateado pelo `jobs`; sozinho, o
    # verificador assume que é o único rodando.
    mem = limite_memoria_mb() if max_mem_mb is None else max_mem_mb
    return run_cmd(cmd, timeout=timeout, nice=nice, max_mem_mb=mem)


def run_jbmc(cls, classpath, unwind=DEFAULT_UNWIND, timeout=DEFAULT_TIMEOUT,
             nice=10, strategy=None, max_mem_mb=None) -> ToolResult:
    """
    Roda JBMC sobre <cls>. Estratégia de duas passagens para entrypoints:
      1. Default (procura main(String[])): cobre Java padrão e Kotlin Unit.
      2. Se 'no entry point'/'ambiguous', tenta assinaturas explícitas
         (:([Ljava/lang/String;)V, :()V, :()I) — necessário p/ Kotlin.

    `strategy` ∈ {bounded, sound} (ver STRATEGIES); None => bounded. Valores da
    via C que o JBMC não suporta (incremental/kinduction) caem em bounded.
    """
    strategy = strategy if strategy in STRATEGIES else "bounded"
    res = _jbmc_invoke(cls, classpath, unwind, timeout, nice, strategy=strategy,
                       max_mem_mb=max_mem_mb)
    raw = res.raw
    needs_retry = (
        "no entry point" in raw
        or "is ambiguous between" in raw
        or "main symbol resolution failed" in raw
    )
    if not needs_retry:
        return res

    for sig in (
        f"{cls}.main:([Ljava/lang/String;)V",
        f"{cls}.main:()V",
        f"{cls}.main:()I",
    ):
        res2 = _jbmc_invoke(cls, classpath, unwind, timeout, nice, entry=sig,
                            strategy=strategy, max_mem_mb=max_mem_mb)
        if "symbol resolution failed" not in res2.raw and "no entry point" not in res2.raw:
            return res2

    # Nenhuma assinatura serviu — retorna o resultado original p/ diagnóstico.
    return res
