"""Reparo verificado guiado por contraexemplo (a contribuição central).

Loop: LLM propõe patch -> regressão re-verifica com o BMC -> se ainda falha,
realimenta o NOVO contraexemplo e itera, até FIX_OK ou max_iters. O verificador
é o oráculo: só conta como reparado o que o BMC prova SAFE.

Adota do EVA: realimentação iterativa e refinamento em timeout (reduz unwind).
"""

import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass, field

from ..classify import CWE_INFO
from ..constants import C_FAMILY_EXTS, CPP_EXTS
from ..counterexample import (explain_counterexample, parse_esbmc_trace_text,
                              parse_jbmc_trace_json)
from . import llm, reachability
from .regression import regression_check

LANG_BY_EXT = {".c": "C", ".java": "Java", ".kt": "Kotlin"}
LANG_BY_EXT.update({ext: "C++" for ext in CPP_EXTS})

# Normalização de compilação (só C): símbolo da stdlib -> cabeçalho que o declara.
# Se o patch usa o símbolo sem incluir o header, injetamos o #include antes de
# compilar. Não altera a lógica do reparo — só evita que um header esquecido
# invalide um patch semanticamente correto (caso recorrente: INT_MAX sem
# <limits.h>). Includes redundantes em C são inofensivos.
_C_SYMBOL_HEADERS = [
    (r"\b(INT_MAX|INT_MIN|LONG_MAX|LONG_MIN|UINT_MAX|ULONG_MAX|CHAR_BIT)\b", "limits.h"),
    (r"\b(malloc|free|calloc|realloc|size_t|NULL)\b", "stdlib.h"),
    (r"\b(bool|true|false)\b", "stdbool.h"),
    (r"\b(printf|fprintf|snprintf|sprintf)\b", "stdio.h"),
]


def ensure_c_headers(code: str) -> str:
    """Prepend os #include faltantes para símbolos da stdlib usados no patch (C).

    Etapa determinística de normalização; reportar como tal na avaliação (não é
    reparo semântico — não conserta o bug, só garante que a lógica do LLM compile).
    """
    missing = []
    for pattern, header in _C_SYMBOL_HEADERS:
        inc = f"#include <{header}>"
        if inc in code or not re.search(pattern, code):
            continue
        # não injetar stdbool se o programa já define seu próprio bool (evita conflito)
        if header == "stdbool.h" and re.search(
                r"\btypedef\b[^;\n]*\bbool\b|#\s*define\s+bool\b|\b_Bool\b", code):
            continue
        missing.append(inc)
    if not missing:
        return code
    return "\n".join(missing) + "\n" + code


# --- escopo do reparo dentro da unidade de compilação -----------------------
# Num projeto multi-arquivo o BUG é REPORTADO no alvo que tem o ponto de entrada,
# mas o DEFEITO quase nunca mora nele. No QuixBugs, `Main.java` só tem asserções
# de teste e o defeito está em `LIS.java`/`BUCKETSORT.java`. Mandar só o
# entrypoint à LLM fazia ela reimplementar a classe ausente dentro do harness: o
# arquivo defeituoso continuava intacto, e o patch nem sequer se aplicava ao
# projeto (`duplicate class`). Estas funções escolhem o arquivo certo e barram
# esse tipo de patch.

# Declaração de tipo de nível superior em Java/Kotlin.
_TYPE_DECL_RE = re.compile(
    r"^[ \t]*(?:(?:public|private|protected|final|abstract|sealed|static|open|data|"
    r"inner|internal|annotation|value)\s+)*"
    r"(?:class|interface|enum|record|object)\s+([A-Za-z_]\w*)", re.M)

# Marcas de asserção/teste — usadas só para detectar patch que "conserta" APAGANDO
# a verificação (ver _validate_patch).
_ASSERT_RE = re.compile(r"AssertionError|__VERIFIER_assert|\bassert\b")

# `assume` diz ao verificador para NÃO considerar certas execuções. Adicionar um
# não conserta o programa: encolhe o espaço de estados até o defeito sair dele.
# Em SV-COMP isso é trapaça explícita. Observado na prática: um patch inseriu
# `assume_abort_if_not(n >= 0)` e foi aceito como REPARADO.
_ASSUME_RE = re.compile(
    r"assume_abort_if_not|__VERIFIER_assume|CProver\.assume|Verifier\.assume"
    r"|\bassume\s*\(")

_COMENTARIO_RE = re.compile(r"//.*$|/\*.*?\*/", re.S)


def _assercoes(code: str) -> list[str]:
    """Linhas de asserção normalizadas (sem comentário, sem espaço).

    Comparar o CONTEÚDO, e não só a quantidade: a guarda antiga contava asserts
    e por isso deixava passar o pior caso — reescrever a asserção para que ela
    seja trivialmente verdadeira. Casos reais que passaram: `assert false` →
    `assert true`, `assert(number == 44)` → `assert(number == 43)`,
    `assert(p1.age == 23)` → `assert(p1.age == 25)`. Em todos a LLM alterou a
    ESPECIFICAÇÃO em vez do código.
    """
    out = []
    for linha in (code or "").splitlines():
        limpa = _COMENTARIO_RE.sub("", linha)
        if _ASSERT_RE.search(limpa):
            out.append(re.sub(r"\s+", "", limpa))
    return out

JVM_EXTS = (".java", ".kt")


def _declared_types(code: str) -> set[str]:
    return set(_TYPE_DECL_RE.findall(code or ""))


def _pick_repair_file(entry_source: str, unit_sources, fault_files) -> str:
    """Qual arquivo da unidade contém o defeito, segundo o contraexemplo.

    Prefere um arquivo citado no trace que NÃO seja o do ponto de entrada; se o
    trace não apontar nenhum outro (ou a unidade tiver um arquivo só), mantém o
    comportamento antigo e repara o próprio alvo."""
    unit = [s for s in (unit_sources or []) if os.path.isfile(s)]
    if len(unit) <= 1:
        return entry_source
    by_name = {os.path.basename(s): s for s in unit}
    entry_abs = os.path.abspath(entry_source)
    for name in (fault_files or []):
        path = by_name.get(name)
        if path and os.path.abspath(path) != entry_abs:
            return path
    return entry_source


def _validate_patch(patch_code: str, original_code: str, ext: str,
                    sibling_types: set[str]) -> str | None:
    """Devolve o motivo da rejeição, ou None se o patch é aceitável.

    Barra os dois modos de "reparo" que passavam pelo oráculo sem consertar nada:
      (a) redeclarar no arquivo reparado um tipo que já existe em outro arquivo da
          unidade — compila isolado, mas quebra o projeto (`duplicate class`) e
          deixa o defeito original onde estava;
      (b) fazer a violação sumir removendo a própria asserção/teste.
    """
    if ext in JVM_EXTS:
        orig_types = _declared_types(original_code)
        patch_types = _declared_types(patch_code)
        intrusos = sorted((patch_types - orig_types) & sibling_types)
        if intrusos:
            return ("O patch declara tipo(s) que já existem em OUTRO arquivo da mesma "
                    f"unidade: {', '.join(intrusos)}. Não redeclare nem reimplemente o "
                    "que já está em outro arquivo — corrija o arquivo indicado, "
                    "mantendo as demais classes como estão.")
        sumidos = sorted(orig_types - patch_types)
        if sumidos:
            return (f"O patch removeu a(s) declaração(ões) {', '.join(sumidos)} que "
                    "existiam no arquivo original. Mantenha as mesmas classes/tipos.")
    n_orig = len(_ASSERT_RE.findall(original_code or ""))
    n_patch = len(_ASSERT_RE.findall(patch_code or ""))
    if n_orig and n_patch < n_orig:
        return (f"O patch reduziu as asserções de {n_orig} para {n_patch}. Não remova "
                "nem enfraqueça verificações/testes para fazer a violação sumir — "
                "corrija a causa.")

    # (c) reescrever a asserção para que ela passe. A contagem acima não pega:
    # `assert false` -> `assert true` continua sendo uma asserção.
    orig_asserts = _assercoes(original_code)
    patch_asserts = set(_assercoes(patch_code))
    alteradas = [a for a in orig_asserts if a not in patch_asserts]
    if alteradas:
        # a mensagem volta no prompt da próxima iteração: mostrar o suficiente
        # para o modelo se localizar, sem despejar a linha inteira.
        amostra = "; ".join(a[:80] for a in alteradas[:2])
        return ("O patch ALTEROU a(s) asserção(ões) do original: "
                f"{amostra}. A asserção é a especificação — mudá-la faz a "
                "violação sumir sem consertar o programa. Mantenha as asserções "
                "exatamente como estão e corrija o código que as viola.")

    # (d) inserir `assume`: restringe o que o verificador explora em vez de
    # corrigir o programa.
    n_assume_orig = len(_ASSUME_RE.findall(original_code or ""))
    n_assume_patch = len(_ASSUME_RE.findall(patch_code or ""))
    if n_assume_patch > n_assume_orig:
        return ("O patch adicionou `assume`/`assume_abort_if_not`, que manda o "
                "verificador ignorar execuções em vez de corrigir o defeito. "
                "Remova a suposição e corrija a causa do problema.")
    return None


@dataclass
class RepairAttempt:
    iteration: int
    verdict: str
    fixed_bug: str | None
    model: str
    ms: int
    tokens: int = 0       # tokens gerados (completion) nesta iteração, se o provedor informar
    tok_s: float = 0.0    # velocidade de geração ≈ tokens / (ms/1000)


@dataclass
class RepairResult:
    target: str
    source: str | None
    original_bug: str
    status: str = "NOT_REPAIRED"      # REPAIRED | NOT_REPAIRED | ERROR
    iterations: int = 0
    attempts: list = field(default_factory=list)
    fixed_path: str | None = None
    origin_fixed_path: str | None = None  # cópia _FIXED gravada ao lado do fonte (só REPAIRED)
    original_code: str | None = None  # p/ diff + relatório na UI
    final_code: str | None = None     # última versão proposta (FIX_OK se REPAIRED)
    cancelled: bool = False           # True se o laço deste alvo parou por cancelamento
    # Arquivo REALMENTE reparado. Difere de `source` quando o bug foi reportado no
    # alvo do entrypoint mas o defeito estava em outro arquivo da unidade.
    repaired_file: str | None = None


def _next_cex(reg, ext, fixed_bug):
    """Texto do novo contraexemplo (ou erro de compilação) para realimentar a LLM."""
    if reg.verdict == "ERROR" and reg.reason:
        return f"O patch anterior não compilou/verificou:\n{reg.reason}"
    if ext in C_FAMILY_EXTS:
        steps, violations = parse_esbmc_trace_text(reg.raw or "")
    else:
        # JVM (.java/.kt): trace em JSON do JBMC. Sem isto a realimentação entre
        # iterações não levava contraexemplo NOVO — o modelo re-tentava sem saber
        # por que o patch anterior continuou violando a propriedade.
        steps, violations = parse_jbmc_trace_json(reg.raw or "")
    return explain_counterexample(fixed_bug, steps, violations)


def _write_beside_source(source_path: str, code: str) -> str | None:
    """Grava o patch verificado ao lado do fonte original (`<stem>_FIXED<ext>`),
    SEM sobrescrever o original. Só é chamado quando o alvo é REPAIRED. Devolve o
    caminho gravado, ou None se a pasta de origem não for gravável."""
    base = os.path.basename(source_path)
    stem, ext = os.path.splitext(base)
    dest = os.path.join(os.path.dirname(os.path.abspath(source_path)), f"{stem}_FIXED{ext}")
    try:
        with open(dest, "w", encoding="utf-8") as f:
            f.write(code)
        return dest
    except OSError:  # pasta read-only / sem permissão — não derruba a run
        return None


def repair_target(*, source_path, original_bug, counterexample, unwind, timeout,
                  solver="boolector", max_iters=5, model=None, base_url=None,
                  api_key=None, dry_run=False,
                  patch_fn=None, work_dir=None, on_progress=None,
                  should_cancel=None, unsigned_overflow=False,
                  strategy=None, concurrency=False, include_dirs=None, function=None,
                  unit_sources=None, fault_files=None,
                  entry_class=None, linha_defeito=None) -> RepairResult:
    """Tenta reparar UM alvo. `patch_fn` é injetável (default: DeepSeek).

    `should_cancel`: callable opcional; se devolver True no início de uma
    iteração, o laço para antes de chamar a LLM (cancelamento cooperativo).

    `unit_sources`/`fault_files`: unidade de compilação do alvo e arquivos
    apontados pelo contraexemplo. Com eles o reparo edita o arquivo do DEFEITO
    (não o do entrypoint) e o oráculo re-verifica a unidade inteira.

    `linha_defeito`: linha da violação no arquivo reparado, vinda do
    contraexemplo. Habilita a guarda de alcançabilidade — sem ela, um patch que
    apenas torna o trecho inalcançável passa como REPARADO (ver reachability).
    """
    patch_fn = patch_fn or llm.generate_patch
    # Arquivo do defeito — pode não ser `source_path` (ver _pick_repair_file).
    repair_path = _pick_repair_file(source_path, unit_sources, fault_files)
    ext = os.path.splitext(repair_path)[1].lower()
    lang = LANG_BY_EXT.get(ext, "C")
    cwe_info = CWE_INFO.get(original_bug, CWE_INFO["Unknown Failure"])
    cert_rule = cwe_info["cert_rule"]
    with open(repair_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()
    stem = os.path.splitext(os.path.basename(repair_path))[0]

    # Demais arquivos da unidade: vão à LLM como CONTEXTO SOMENTE-LEITURA. Sem
    # eles o modelo não vê as chamadas/assinaturas que precisa preservar — e, se
    # o arquivo reparado referencia uma classe que ele não enxerga, inventa uma.
    context_files = {}
    sibling_types: set[str] = set()
    repair_abs = os.path.abspath(repair_path)
    for src in (unit_sources or []):
        if os.path.abspath(src) == repair_abs or not os.path.isfile(src):
            continue
        try:
            with open(src, "r", encoding="utf-8", errors="ignore") as f:
                sib = f.read()
        except OSError:
            continue
        context_files[os.path.basename(src)] = sib
        if ext in JVM_EXTS:
            sibling_types |= _declared_types(sib)

    own_tmp = work_dir is None
    work_dir = work_dir or tempfile.mkdtemp(prefix="smart_repair_")
    os.makedirs(work_dir, exist_ok=True)

    result = RepairResult(target=os.path.basename(source_path), source=source_path,
                          original_bug=original_bug, original_code=code,
                          repaired_file=repair_path)
    cur_unwind = unwind
    cex = counterexample
    prev_patch = prev_verdict = None

    try:
        for i in range(1, max_iters + 1):
            if should_cancel and should_cancel():
                result.cancelled = True   # sinaliza p/ o repair_run marcar a run como cancelled
                break   # cancelamento cooperativo: para antes de gastar a próxima iteração
            if on_progress:
                on_progress(i, max_iters)
            try:
                gen = patch_fn(
                    bug=original_bug, cwe_info=cwe_info, cert_rule=cert_rule,
                    code=code, counterexample=cex, lang=lang, model=model,
                    base_url=base_url, api_key=api_key,
                    prev_patch=prev_patch, prev_cex=(cex if prev_patch else None),
                    prev_verdict=prev_verdict, dry_run=dry_run,
                    file_name=os.path.basename(repair_path),
                    context_files=context_files,
                )
            except llm.LLMRateLimited:
                # cota/limite do provedor (429) — erro de INFRAESTRUTURA, não de reparo.
                # Status distinto p/ NÃO contar como "não reparado" nas métricas.
                result.status = "PROVIDER_ERROR"
                result.attempts.append(asdict(RepairAttempt(i, "PROVIDER_ERROR", None, "rate-limit (429)", 0)))
                result.iterations = i
                return result
            except Exception as e:  # noqa: BLE001 — falha de LLM não derruba a run
                result.status = "ERROR"
                result.attempts.append(asdict(RepairAttempt(i, "ERROR", None, str(e)[:40], 0)))
                result.iterations = i
                return result

            if should_cancel and should_cancel():
                # cancelado durante a geração do LLM: pula a re-verificação BMC
                # (que pode levar até o timeout) e para imediatamente
                result.cancelled = True
                break

            patch_code = gen.get("patch") or code
            if ext in C_FAMILY_EXTS:
                patch_code = ensure_c_headers(patch_code)  # normalização de compilação
            result.final_code = patch_code

            gen_ms = gen.get("ms", 0) or 0
            # Guarda ANTES do BMC: um patch que reimplementa classe alheia ou apaga
            # asserção não deve nem chegar ao oráculo — ele passaria. Rejeita, gasta
            # a iteração e realimenta o motivo para o modelo tentar diferente.
            recusa = _validate_patch(patch_code, code, ext, sibling_types)
            if recusa:
                comp_tokens = (gen.get("usage") or {}).get("completion_tokens") or 0
                tok_s = round(comp_tokens / (gen_ms / 1000), 1) if comp_tokens and gen_ms else 0.0
                result.attempts.append(asdict(
                    RepairAttempt(i, "INVALID_PATCH", None, gen.get("model", "?"), gen_ms,
                                  tokens=comp_tokens, tok_s=tok_s)))
                result.iterations = i
                if on_progress:
                    on_progress(i, max_iters, tok_s)
                cex = f"O patch anterior foi REJEITADO antes da verificação:\n{recusa}"
                prev_patch, prev_verdict = patch_code, "INVALID_PATCH"
                continue

            fixed_path = os.path.join(work_dir, f"{stem}_FIXED{ext}")
            with open(fixed_path, "w", encoding="utf-8") as f:
                f.write(patch_code)

            reg = regression_check(fixed_path, original_bug, cur_unwind, timeout, solver,
                                   unsigned_overflow=unsigned_overflow,
                                   strategy=strategy, concurrency=concurrency,
                                   include_dirs=include_dirs, function=function,
                                   unit_sources=unit_sources,
                                   repaired_source=repair_path,
                                   entry_class=entry_class)
            comp_tokens = (gen.get("usage") or {}).get("completion_tokens") or 0
            tok_s = round(comp_tokens / (gen_ms / 1000), 1) if comp_tokens and gen_ms else 0.0
            result.attempts.append(asdict(
                RepairAttempt(i, reg.verdict, reg.fixed_bug, gen.get("model", "?"), gen_ms,
                              tokens=comp_tokens, tok_s=tok_s)))
            result.iterations = i
            if on_progress:   # reporta a velocidade desta iteração para exibição ao vivo
                on_progress(i, max_iters, tok_s)

            if reg.verdict == "FIX_OK" and linha_defeito:
                # O oráculo aprovou — mas ele aprova igual quando o patch apenas
                # tornou o trecho defeituoso inalcançável. Sonda semântica antes
                # de declarar reparo (ver reachability).
                executa = reachability.ponto_do_defeito_executa(
                    original_code=code, patch_code=patch_code,
                    linha_defeito=linha_defeito, ext=ext,
                    work_dir=work_dir, stem=stem, unwind=cur_unwind,
                    timeout=timeout, solver=solver,
                    unsigned_overflow=unsigned_overflow, strategy=strategy,
                    concurrency=concurrency, include_dirs=include_dirs,
                    function=function,
                    unit_sources=unit_sources, repaired_source=repair_path,
                    entry_class=entry_class)
                if executa is False:
                    result.attempts[-1]["verdict"] = "INVALID_PATCH"
                    cex = ("O patch anterior foi REJEITADO: ele fez o trecho do "
                           "defeito deixar de EXECUTAR (ficou inalcançável) em vez "
                           "de corrigi-lo. O verificador aprova código morto, mas o "
                           "programa perdeu o comportamento. Mantenha a instrução "
                           "executando e corrija a causa do defeito.")
                    prev_patch, prev_verdict = patch_code, "INVALID_PATCH"
                    continue

            if reg.verdict == "FIX_OK":
                result.status = "REPAIRED"
                result.fixed_path = fixed_path
                # entrega o patch verificado ao lado do arquivo REPARADO (que pode
                # não ser o do entrypoint) — é lá que o defeito estava
                result.origin_fixed_path = _write_beside_source(repair_path, patch_code)
                return result

            if reg.verdict == "TIMEOUT":
                cur_unwind = max(1, cur_unwind // 2)   # refinamento (tática EVA)

            cex = _next_cex(reg, ext, reg.fixed_bug or original_bug)
            prev_patch, prev_verdict = patch_code, reg.verdict

        return result
    finally:
        if own_tmp and result.status != "REPAIRED":
            shutil.rmtree(work_dir, ignore_errors=True)


def _aggregate(results, total) -> dict:
    """Resumo + distribuição por categoria a partir da lista de resultados."""
    repaired = sum(1 for r in results if r["status"] == "REPAIRED")
    provider_errors = sum(1 for r in results if r["status"] == "PROVIDER_ERROR")
    iters = [r["iterations"] for r in results if r["status"] == "REPAIRED"]
    tok_speeds = [a["tok_s"] for r in results for a in r.get("attempts", []) if a.get("tok_s")]
    by_category: dict[str, dict] = {}
    for r in results:
        c = r["original_bug"]
        by_category.setdefault(c, {"total": 0, "repaired": 0})
        by_category[c]["total"] += 1
        if r["status"] == "REPAIRED":
            by_category[c]["repaired"] += 1
    return {
        "targets": results,
        "summary": {
            # provider_errors (429/cota) NÃO contam como "não reparado": ficam fora do
            # denominador. attempted = alvos que de fato receberam resposta do LLM.
            "total": total, "repaired": repaired,
            "provider_errors": provider_errors,
            "attempted": total - provider_errors,
            "not_repaired": total - repaired - provider_errors,
            "avg_iterations_when_repaired": round(sum(iters) / len(iters), 2) if iters else 0,
            "avg_tok_s": round(sum(tok_speeds) / len(tok_speeds), 1) if tok_speeds else 0,
        },
        "by_category": by_category,
    }


def repair_run(targets, *, unwind, timeout, solver="boolector", max_iters=5,
               model=None, base_url=None, api_key=None, dry_run=False,
               work_dir=None, on_progress=None, prior_results=None,
               only_unrepaired=False, on_checkpoint=None, should_cancel=None,
               unsigned_overflow=False, strategy=None, concurrency=False,
               include_dirs=None, function=None, patch_fn=None) -> dict:
    """Repara os alvos com BUG de uma run. Devolve resultados + agregados.

    Incremental/resumível:
      - `only_unrepaired`: alvos já REPARADOS em `prior_results` são reaproveitados
        (verificados FIX_OK) sem chamar LLM/BMC de novo — só (re)tenta os que
        faltam. Custo do re-run passa a ser ∝ nº de alvos não resolvidos.
      - `on_checkpoint(agregado_parcial)`: chamado após CADA alvo, para persistir
        o progresso (retomável em caso de crash).
      - `should_cancel`: callable opcional; checado no início de cada alvo (e
        propagado às iterações de cada alvo). Ao cancelar, devolve o parcial já
        reparado com a flag `cancelled=True` no agregado.
    """
    # mesmo cuidado da verificação: se o solver pedido não foi compilado no
    # ESBMC, a re-verificação (oráculo) erraria em todo patch — cai p/ boolector.
    from ..verifiers import solver_available
    if not solver_available(solver):
        solver = "boolector"

    bug_targets = [t for t in targets
                   if t.get("status") == "BUG" and t.get("source") and t.get("bug")]
    total = len(bug_targets)
    prior = {r.get("source"): r for r in (prior_results or []) if r.get("source")}

    def _is_carryover(t):
        prev = prior.get(t["source"])
        return bool(only_unrepaired and prev and prev.get("status") == "REPAIRED")

    # No modo incremental, o progresso conta só os alvos QUE FALTAM (não os
    # reaproveitados): a barra mostra "X/faltam", não "X/total de bugs".
    todo = sum(1 for t in bug_targets if not _is_carryover(t))
    results = []
    cancelled = False
    done = 0
    for t in bug_targets:
        if should_cancel and should_cancel():
            cancelled = True
            break
        prev = prior.get(t["source"])
        if _is_carryover(t):
            # entrega o _FIXED ao lado do fonte mesmo em carry-over (idempotente)
            if prev.get("final_code") and not prev.get("origin_fixed_path"):
                prev["origin_fixed_path"] = _write_beside_source(
                    prev.get("repaired_file") or t["source"], prev["final_code"])
            results.append(prev)                      # reaproveita (já provado FIX_OK), sem avançar a barra
            if on_checkpoint:
                on_checkpoint(_aggregate(results, total))
            continue

        def prog(i, n, tok_s=None, _idx=done):
            if on_progress:
                on_progress(_idx, todo, i, n, tok_s)
        rr = repair_target(
            source_path=t["source"], original_bug=t["bug"],
            counterexample=t.get("explanation") or "", unwind=unwind, timeout=timeout,
            solver=solver, max_iters=max_iters, model=model, base_url=base_url,
            api_key=api_key, dry_run=dry_run,
            work_dir=work_dir, on_progress=prog, should_cancel=should_cancel,
            unsigned_overflow=unsigned_overflow, strategy=strategy,
            concurrency=concurrency, include_dirs=include_dirs, function=function,
            unit_sources=t.get("unit_sources"), fault_files=t.get("fault_files"),
            entry_class=t.get("target"), patch_fn=patch_fn,
            linha_defeito=(t.get("violation") or {}).get("line"),
        )
        results.append(asdict(rr))
        done += 1                   # avança o progresso só nos alvos que faltavam
        if on_checkpoint:
            on_checkpoint(_aggregate(results, total))
        if rr.cancelled:            # cancelado durante ESTE alvo (inclusive se for o único/último)
            cancelled = True
            break

    agg = _aggregate(results, total)
    agg["cancelled"] = cancelled
    return agg
