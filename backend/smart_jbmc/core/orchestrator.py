"""Orquestração: roda o pipeline de verificação sobre uma pasta (portado do main()).

scan → compile (por unidade) → verify em paralelo → classify → contraexemplo →
métricas (CASTLE + distribuição CWE). Devolve um RunResult serializável.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from . import classify, compiler, scanner, stubs
from .counterexample import (explain_counterexample, parse_esbmc_trace_text,
                            parse_jbmc_trace_json)
from .metrics import aggregate_cwe, castle_score, infer_oracle_from_path
from .process import limite_memoria_mb
from .verifiers import (available_solvers, is_no_entry_point, run_esbmc,
                        run_jbmc, solver_available)


@dataclass
class TargetResult:
    target: str
    source: str | None
    kind: str                       # jbmc | esbmc
    status: str                     # BUG | SAFE | TIMEOUT | ERROR
    bug: str | None = None
    cwe_id: str | None = None
    cwe_name: str | None = None
    cert_priority: int | None = None
    cert_level: str | None = None
    n_findings: int = 0
    elapsed_s: float = 0.0
    oracle: str | None = None
    explanation: str | None = None
    # Arquivos da MESMA unidade de compilação deste alvo (todos os fontes que
    # foram compilados juntos). O reparo precisa disto: num projeto multi-arquivo
    # o bug quase nunca está no arquivo do entrypoint (ex.: QuixBugs — o `main`
    # está em Main.java, o defeito está em LIS.java).
    unit_sources: list[str] = field(default_factory=list)
    # Arquivos citados pelo contraexemplo, do mais provável ao menos (violação
    # primeiro, depois os passos mais recentes do trace). É o que aponta QUAL
    # arquivo da unidade contém o defeito.
    fault_files: list[str] = field(default_factory=list)
    # Ponto da violação como DADO, não como texto. A `explanation` já trazia
    # arquivo e linha, mas só em prosa — o SARIF não tinha como ancorar o achado
    # na linha do defeito e todo resultado caía na linha 1 do arquivo.
    # {file, line, description, condition, aproximada} ou None.
    violation: dict | None = None


@dataclass
class RunResult:
    config: dict
    targets: list[TargetResult] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    cwe_dist: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    cancelled: bool = False


def _fault_files(steps, violations) -> list[str]:
    """Basenames dos arquivos citados no contraexemplo, do mais provável ao menos.

    Ordem: primeiro onde a propriedade foi violada, depois os passos do trace do
    mais recente para o mais antigo. Sem duplicatas e sem os placeholders (`-`)
    que o parser usa quando a localização não veio na saída.
    """
    ordered: list[str] = []
    for src in ([v.get("file") for v in violations]
                + [s.get("file") for s in reversed(steps)]):
        name = os.path.basename(str(src or "").strip())
        if not name or name == "-" or name in ordered:
            continue
        ordered.append(name)
    return ordered


def _to_int(v):
    """Converte a linha para int; devolve None se o parser usou placeholder."""
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _primary_violation(violations) -> dict | None:
    """A violação que ancora o achado: a última, que é onde a propriedade falhou.

    Devolve None quando o trace não trouxe localização (`-`), caso em que
    inventar uma linha seria pior que não ter nenhuma — ver o ramo `sem_local`
    de `explain_counterexample`.
    """
    if not violations:
        return None
    v = violations[-1]
    line = _to_int(v.get("line"))
    file = str(v.get("file") or "").strip()
    if not line or not file or file == "-":
        return None
    return {
        "file": os.path.basename(file),
        "line": line,
        "description": v.get("description"),
        "condition": v.get("condition"),
        "aproximada": bool(v.get("line_aproximada")),
    }


def _build_target(kind, target, source, raw, obj, elapsed,
                  unit_sources=None) -> TargetResult:
    v = classify.classify(raw, obj)
    explanation = None
    fault_files: list[str] = []
    violation: dict | None = None
    if v.status == "BUG":
        if kind == "esbmc":
            steps, violations = parse_esbmc_trace_text(raw)
        else:
            # JVM: o trace vem em JSON (--json-ui). Antes ficava `[], []`, e a
            # explicação — que é o contraexemplo entregue à LLM no reparo —
            # trazia só o parágrafo genérico da categoria.
            steps, violations = parse_jbmc_trace_json(obj if obj is not None else raw)
        explanation = explain_counterexample(v.bug, steps, violations)
        fault_files = _fault_files(steps, violations)
        violation = _primary_violation(violations)
    elif v.status == "ERROR" and kind == "jbmc" and is_no_entry_point(raw):
        # Classe de biblioteca (sem `main`): alvo INAPLICÁVEL, não erro. Fica
        # fora do denominador de ERROR para o relatório não virar ruído.
        v = classify.Verdict("NO_ENTRY_POINT", None, None, None, None, 0)
        explanation = ("Classe sem ponto de entrada (`main`): o JBMC não tem por onde "
                       "começar a verificação. Não é erro nem defeito — esta classe é "
                       "exercitada a partir da classe que tem o `main`.")
    elif v.status == "ERROR":
        # NÃO deixar o card vazio: surfaceia o motivo real do erro do verificador
        # (parse error / header faltando / flag inválida) extraído da saída bruta.
        explanation = (classify.extract_diagnostics(raw)
                       or "Erro do verificador (sem diagnóstico na saída).")
    elif v.status == "TIMEOUT":
        explanation = "Verificação excedeu o tempo limite (timeout) antes de concluir."
    info = v.cwe_info or {}
    return TargetResult(
        target=target, source=source, kind=kind, status=v.status, bug=v.bug,
        cwe_id=info.get("cwe_id"), cwe_name=info.get("cwe_name"),
        cert_priority=v.cert_priority, cert_level=v.cert_level,
        n_findings=v.n_findings, elapsed_s=elapsed,
        oracle=infer_oracle_from_path(source), explanation=explanation,
        unit_sources=list(unit_sources or []), fault_files=fault_files,
        violation=violation,
    )


def run_verification(folder, *, unwind=5, timeout=60, jobs=4, solver="boolector",
                     concurrency=False, build_root="build_verify",
                     unwinding_assertions=False, strategy=None,
                     unsigned_overflow=False, include_dirs=None, link_unit=None,
                     function=None, on_progress=None, should_cancel=None) -> RunResult:
    """Roda a verificação. `on_progress(phase, done, total)` é chamado ao longo
    das fases (scanning / compiling / verifying / done) para feedback visual.
    `should_cancel()` (opcional) é consultado entre alvos: se True, para cedo e
    devolve resultados PARCIAIS com `cancelled=True` (cancelamento cooperativo)."""
    t0 = time.perf_counter()

    def _cb(phase, done, total):
        if on_progress:
            try:
                on_progress(phase, done, total)
            except Exception:  # noqa: BLE001 — progresso nunca derruba a run
                pass

    def _cancelled() -> bool:
        return bool(should_cancel and should_cancel())

    warnings: list[str] = []
    _cb("scanning", 0, 0)
    java, kt, c = scanner.scan(folder)

    # Unidade multi-arquivo: linka vários .c (`main` + deps) num ÚNICO alvo ESBMC
    # em vez de um-por-arquivo (que havocaria as deps). Necessário p/ achar bug em
    # projeto real multi-arquivo (ex.: repl.c + tinyexpr.c). Caminhos relativos
    # resolvem contra `folder`. Quando ativo, o C vira esse único alvo linkado.
    link_files = None
    if link_unit:
        link_files = [p if os.path.isabs(p) else os.path.join(folder, p) for p in link_unit]
        missing = [p for p in link_files if not os.path.isfile(p)]
        if missing:
            warnings.append("link_unit: arquivo(s) não encontrado(s): " + ", ".join(missing))
            link_files = [p for p in link_files if os.path.isfile(p)] or None
        c = []   # o C vira UM alvo linkado; ignora a varredura por arquivo

    # Validação do solver SMT (só faz sentido se há alvos C/ESBMC). O build do
    # ESBMC pode não ter o solver pedido compilado (ex.: mathsat ausente acusa
    # ERROR silencioso em todos os alvos). Sonda de verdade e cai p/ boolector.
    solver_requested = solver
    if (c or link_files) and not solver_available(solver):
        avail = available_solvers() or ["boolector"]
        warnings.append(
            f"solver '{solver}' não está compilado neste build do ESBMC "
            f"(disponíveis: {', '.join(avail)}); usando 'boolector'."
        )
        solver = "boolector"

    # estratégia de verificação (ver core.verifiers.esbmc.STRATEGIES). Compat.:
    # se não veio strategy explícita, deriva do flag legado unwinding_assertions.
    if strategy is None or strategy not in ("bounded", "sound", "incremental", "kinduction"):
        strategy = "sound" if unwinding_assertions else "bounded"

    config = {
        "folder": folder, "unwind": unwind, "timeout": timeout, "jobs": jobs,
        "solver": solver, "solver_requested": solver_requested,
        "concurrency": concurrency, "strategy": strategy,
        "unwinding_assertions": (strategy == "sound"),
        "unsigned_overflow": unsigned_overflow,
    }
    _cb("compiling", 0, 0)
    stubs_cp = stubs.ensure_stubs()   # classpath p/ APIs SV-COMP/CProver (ou None)
    # Modelos de biblioteca: SÓ para o JBMC. O javac/kotlinc seguem compilando
    # contra o JDK real, senão um método não coberto pelo modelo quebraria a
    # compilação de código que hoje compila.
    models_cp = stubs.ensure_models()

    # Orçamento de memória RATEADO entre os verificadores que rodam em paralelo:
    # o teto é do conjunto, não de cada processo. Sem o rateio, subir `jobs`
    # multiplicava o consumo máximo da máquina (ver constants.DEFAULT_MEM_TOTAL_MB).
    mem_por_processo = limite_memoria_mb(jobs)

    results: list[TargetResult] = []

    # --- preparação JVM: compila cada unidade e coleta classes/alvos ---
    jbmc_specs: list[tuple] = []
    for unit_dir, items in scanner.group_units(java, kt).items():
        if _cancelled():
            break
        out_dir = scanner.unit_build_dir(unit_dir, folder, build_root)
        ok, err = True, ""
        if items["java"]:
            comp = compiler.compile_java(items["java"], out_dir, classpath=stubs_cp)
            if comp.returncode != 0:
                warnings.append(f"javac falhou em {unit_dir}")
                ok, err = False, comp.raw
        if ok and items["kt"]:
            comp = compiler.compile_kotlin(items["kt"], out_dir, classpath=stubs_cp)
            if comp.returncode != 0:
                warnings.append(f"kotlinc falhou em {unit_dir}")
                ok, err = False, comp.raw
        if not ok:
            # NÃO some silenciosamente: cada fonte da unidade vira um COMPILE_FAIL
            for src in items["java"] + items["kt"]:
                results.append(TargetResult(
                    target=os.path.basename(src), source=src, kind="jbmc",
                    status="COMPILE_FAIL", oracle=infer_oracle_from_path(src),
                    explanation="Falha de compilação (não verificado):\n" + (err or "")[:1500],
                ))
            continue
        # Ordem importa: os MODELOS vêm antes dos modelos internos do JBMC, que
        # é o que faz `java.util.Random` ser o nosso e não o havocado.
        cp = os.pathsep.join([p for p in (models_cp, out_dir, stubs_cp) if p])
        src_map = scanner.map_classes_to_sources(items["java"], items["kt"])
        # Todos os fontes compilados JUNTOS: é a unidade que o reparo precisa ver
        # para achar o arquivo do defeito e para re-verificar o patch linkado.
        unit_files = list(items["java"]) + list(items["kt"])
        for cls in scanner.classes_generated(out_dir):
            jbmc_specs.append((cls, cp, src_map.get(cls), unit_files))

    # --- execução paralela entre alvos ---
    def do_jbmc(spec):
        cls, classpath, src, unit_files = spec
        t = time.perf_counter()
        res = run_jbmc(cls, classpath=classpath, unwind=unwind, timeout=timeout,
                       strategy=strategy, max_mem_mb=mem_por_processo)
        return _build_target("jbmc", cls, src, res.raw, classify.safe_json(res.raw),
                             round(time.perf_counter() - t, 3),
                             unit_sources=unit_files)

    def do_esbmc(cfile):
        t = time.perf_counter()
        res = run_esbmc(cfile, unwind=unwind, timeout=timeout,
                        concurrency=concurrency, solver=solver,
                        strategy=strategy, unsigned_overflow=unsigned_overflow,
                        include_dirs=include_dirs, function=function,
                        max_mem_mb=mem_por_processo)
        return _build_target("esbmc", os.path.basename(cfile), cfile, res.raw, None,
                             round(time.perf_counter() - t, 3))

    def do_esbmc_unit(files):
        # Verifica `files` como UMA unidade linkada (multi-arquivo). O alvo é
        # rotulado pelos basenames; o `source` é o 1º arquivo (a entrada/`main`).
        t = time.perf_counter()
        res = run_esbmc(files, unwind=unwind, timeout=timeout,
                        concurrency=concurrency, solver=solver,
                        strategy=strategy, unsigned_overflow=unsigned_overflow,
                        include_dirs=include_dirs, function=function,
                        max_mem_mb=mem_por_processo)
        label = " + ".join(os.path.basename(f) for f in files)
        return _build_target("esbmc", label, files[0], res.raw, None,
                             round(time.perf_counter() - t, 3),
                             unit_sources=list(files))

    total = len(jbmc_specs) + len(c) + (1 if link_files else 0)
    _cb("verifying", 0, total)

    # `results` já pode conter COMPILE_FAIL (acumulados acima); o progresso conta
    # só o trabalho verificado (`done`). Cancelamento cooperativo: para de coletar
    # e encerra o pool sem esperar os alvos em voo.
    pool = ThreadPoolExecutor(max_workers=max(1, jobs))
    futures = []
    if not _cancelled():
        futures = [pool.submit(do_jbmc, s) for s in jbmc_specs]
        futures += [pool.submit(do_esbmc, cf) for cf in c]
        if link_files:
            futures.append(pool.submit(do_esbmc_unit, link_files))
    done = 0
    try:
        for fut in as_completed(futures):
            if _cancelled():
                break
            results.append(fut.result())
            done += 1
            _cb("verifying", done, total)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    cancelled = _cancelled()
    _cb("cancelled" if cancelled else "done", done, total)

    # --- agregações ---
    summary = {"total": len(results)}
    for st in ("BUG", "SAFE", "UNKNOWN", "TIMEOUT", "ERROR", "COMPILE_FAIL",
               "NO_ENTRY_POINT"):
        summary[st] = sum(1 for r in results if r.status == st)

    metrics = castle_score(
        [{"bug": r.bug, "n_findings": r.n_findings, "oracle": r.oracle} for r in results])
    cwe_dist = aggregate_cwe([{"bug": r.bug} for r in results])

    return RunResult(
        config=config, targets=results, summary=summary, metrics=metrics,
        cwe_dist=cwe_dist, warnings=warnings,
        elapsed_s=round(time.perf_counter() - t0, 3), cancelled=cancelled,
    )
