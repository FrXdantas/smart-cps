"""Fase de regressão: re-verifica um arquivo *_FIXED e compara com o bug original.

Portado de _verify_fixed_jvm / _verify_fixed_c / regression_check_one. É o
mecanismo de validação compartilhado pelo reparo heurístico e pelo reparo-LLM:
nenhum patch é aceito (FIX_OK) sem o BMC provar que a violação sumiu.
"""

import os
import shutil
import tempfile
import time
from dataclasses import dataclass

from ..classify import detect_bug, esbmc_timed_out, has_error, has_failure
from ..compiler import compile_java, compile_kotlin
from ..constants import C_FAMILY_EXTS
from ..stubs import ensure_stubs
from ..verifiers import run_esbmc, run_jbmc


@dataclass
class RegressionResult:
    verdict: str                 # FIX_OK | STILL_VULNERABLE | DIFFERENT_BUG | ERROR | TIMEOUT
    fixed_bug: str | None = None
    elapsed_s: float = 0.0
    reason: str | None = None
    raw: str = ""                # saída bruta do verificador (p/ extrair o novo CEX)


def _verify_fixed_c(fixed_path, unwind, timeout, solver,
                    unsigned_overflow=False, nan_check=False, unit_sources=None,
                    repaired_source=None, strategy=None, concurrency=False,
                    include_dirs=None, function=None) -> tuple[str, str | None]:
    """Re-verifica o patch. Se o alvo original era uma unidade linkada de vários
    `.c`, re-linka a unidade inteira trocando só o arquivo reparado — verificar o
    arquivo isolado havocaria as dependências e o veredicto não valeria."""
    unit = [s for s in (unit_sources or []) if os.path.isfile(s)]
    if len(unit) > 1 and repaired_source:
        target = [fixed_path if os.path.abspath(s) == os.path.abspath(repaired_source)
                  else s for s in unit]
    else:
        target = fixed_path
    # Mesmas opções da run que ACHOU o bug. Sem `concurrency` o oráculo nem
    # procurava a race (código idêntico saía FIX_OK); sem `strategy` re-verificava
    # sempre em `bounded`, aceitando SAFE vacuamente verdadeiro; sem `function`
    # verificava outro ponto de entrada; sem `include_dirs` nem compilava.
    res = run_esbmc(target, unwind=unwind, timeout=timeout, solver=solver,
                    unsigned_overflow=unsigned_overflow, nan_check=nan_check, strategy=strategy,
                    concurrency=concurrency, include_dirs=include_dirs,
                    function=function or None)
    return res.raw, None


def _verify_fixed_jvm(fixed_path, unwind, timeout, strategy=None,
                      unit_sources=None, repaired_source=None,
                      entry_class=None) -> tuple[str, str | None]:
    """Compila o patch em diretório temporário e roda JBMC.

    Quando `unit_sources` é dado, re-verifica a UNIDADE DE COMPILAÇÃO inteira com
    o arquivo reparado no lugar do original — e não o patch isolado. Sem isso, num
    projeto multi-arquivo o oráculo compilava um arquivo que sozinho não é o
    programa: o harness `Main.java` sem a classe `LIS` só fecha se o modelo
    reescrever `LIS` inteira dentro dele, e aí o FIX_OK não diz nada sobre o
    `LIS.java` de verdade, que continua com o defeito.

    `entry_class` fixa o MESMO ponto de entrada que a verificação original usou;
    escolher "a primeira classe que apareceu" verificaria outro programa.
    """
    tmp_dir = tempfile.mkdtemp(prefix="smart_jbmc_fix_")
    try:
        ext = os.path.splitext(fixed_path)[1].lower()
        if ext not in (".java", ".kt"):
            return "", f"Extensão não suportada: {ext}"
        base_name = os.path.basename(fixed_path).replace("_FIXED", "")

        # Monta a unidade no tmp: cada fonte original, com o reparado substituído.
        sources: list[str] = []
        for src in (unit_sources or []):
            if not os.path.isfile(src):
                continue
            dest = os.path.join(tmp_dir, os.path.basename(src))
            same = (repaired_source and os.path.abspath(src) == os.path.abspath(repaired_source))
            shutil.copy2(fixed_path if same else src, dest)
            sources.append(dest)
        if not sources:   # alvo de arquivo único (ou unidade indisponível)
            dest = os.path.join(tmp_dir, base_name)
            shutil.copy2(fixed_path, dest)
            sources = [dest]

        stubs_cp = ensure_stubs()
        java = [s for s in sources if s.lower().endswith(".java")]
        kt = [s for s in sources if s.lower().endswith(".kt")]
        for files, compile_fn in ((java, compile_java), (kt, compile_kotlin)):
            if not files:
                continue
            comp = compile_fn(files, out_dir=tmp_dir, classpath=stubs_cp)
            if comp.returncode != 0:
                return "", f"FIXED não compila:\n{comp.raw}"

        class_files = [
            os.path.join(root, f)
            for root, _, files in os.walk(tmp_dir)
            for f in files if f.endswith(".class")
        ]
        if not class_files:
            return "", "Nenhuma classe .class gerada"

        cls = entry_class
        if not cls:
            rel = os.path.relpath(class_files[0], tmp_dir)
            cls = rel.replace(os.sep, ".").replace("/", ".")
            if cls.endswith(".class"):
                cls = cls[:-6]

        cp = (tmp_dir + os.pathsep + stubs_cp) if stubs_cp else tmp_dir
        res = run_jbmc(cls, classpath=cp, unwind=unwind, timeout=timeout,
                       strategy=strategy)
        return res.raw, None
    except Exception as e:  # noqa: BLE001
        return "", f"Erro interno _verify_fixed_jvm: {e}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _extract_diagnostics(raw: str, max_lines: int = 15, max_chars: int = 1000) -> str:
    """Extrai as linhas acionáveis (erros do compilador/frontend) da saída bruta
    do verificador, para realimentar a LLM com um diagnóstico útil — ex.:
    `error: use of undeclared identifier 'INT_MAX'` — em vez da mensagem genérica
    'erro do verificador', que não diz ao modelo o que corrigir."""
    keep = []
    for line in raw.splitlines():
        low = line.lower()
        if ("error" in low or "undeclared" in low or "undefined" in low
                or line.lstrip().startswith("^") or " | " in line):
            keep.append(line.rstrip())
    if not keep:  # fallback: últimas linhas não vazias da saída
        keep = [ln.rstrip() for ln in raw.splitlines() if ln.strip()][-max_lines:]
    return "\n".join(keep[:max_lines])[:max_chars].strip()


def regression_check(fixed_path: str, original_bug: str, unwind: int, timeout: int,
                     solver: str = "boolector",
                     unsigned_overflow: bool = False,
                     nan_check: bool = False,
                     strategy: str | None = None,
                     concurrency: bool = False,
                     include_dirs: list[str] | None = None,
                     function: str | None = None,
                     unit_sources: list[str] | None = None,
                     repaired_source: str | None = None,
                     entry_class: str | None = None) -> RegressionResult:
    """Re-verifica o *_FIXED e devolve o veredicto frente ao bug original.

    `unsigned_overflow` e `strategy` devem espelhar a config da run original (o
    oráculo precisa checar a MESMA propriedade, sob o MESMO regime de bound) —
    ver core.verifiers.esbmc.run_esbmc e core.verifiers.jbmc.run_jbmc. Sem isso o
    patch seria re-verificado com propriedade/rigor diferentes do que achou o bug.

    `unit_sources`/`repaired_source`/`entry_class` reconstroem o MESMO programa
    que foi verificado, com apenas o arquivo reparado trocado. Sem eles, num
    projeto multi-arquivo o oráculo aprovaria patches que não se aplicam ao
    projeto real (ver _verify_fixed_jvm)."""
    if not os.path.exists(fixed_path):
        return RegressionResult("ERROR", reason=f"FIXED não encontrado: {fixed_path}")

    ext = os.path.splitext(fixed_path)[1].lower()
    t0 = time.perf_counter()

    if ext in C_FAMILY_EXTS:
        raw, comp_err = _verify_fixed_c(fixed_path, unwind, timeout, solver,
                                        unsigned_overflow=unsigned_overflow, nan_check=nan_check,
                                        unit_sources=unit_sources,
                                        repaired_source=repaired_source,
                                        strategy=strategy, concurrency=concurrency,
                                        include_dirs=include_dirs, function=function)
    elif ext in (".java", ".kt"):
        raw, comp_err = _verify_fixed_jvm(fixed_path, unwind, timeout, strategy=strategy,
                                          unit_sources=unit_sources,
                                          repaired_source=repaired_source,
                                          entry_class=entry_class)
    else:
        return RegressionResult("ERROR", reason=f"extensão não suportada: {ext}")

    elapsed = round(time.perf_counter() - t0, 3)

    if comp_err:
        return RegressionResult("ERROR", reason=comp_err, elapsed_s=elapsed, raw=comp_err)
    if "TIMEOUT:" in raw or (esbmc_timed_out(raw) and not has_failure(raw)):
        return RegressionResult("TIMEOUT", elapsed_s=elapsed, raw=raw)
    if has_error(raw):
        diag = _extract_diagnostics(raw) or "erro do verificador"
        return RegressionResult("ERROR", reason=diag, elapsed_s=elapsed, raw=raw)

    fixed_bug = detect_bug(raw) if has_failure(raw) else None
    if fixed_bug is None:
        verdict = "FIX_OK"
    elif fixed_bug == original_bug:
        verdict = "STILL_VULNERABLE"
    else:
        verdict = "DIFFERENT_BUG"
    return RegressionResult(verdict, fixed_bug=fixed_bug, elapsed_s=elapsed, raw=raw)
