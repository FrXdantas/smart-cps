"""Exportação dos achados de uma run em SARIF 2.1.0 (padrão OASIS).

Cada alvo com BUG vira um `result` (regra = CWE, localização = arquivo-fonte);
alvos UNKNOWN (bound insuficiente) viram um `result` nível `note`. Além dos
achados, o documento carrega — para reprodutibilidade — TUDO que foi testado e
COMO:
  * `artifacts[]`         — todo arquivo-fonte verificado (caminho + status/tempo);
  * `invocations[0]`      — config exata (solver, unwind, timeout, jobs, modo),
                            linha de comando, e tempos (start/end UTC, elapsed);
  * `tool.driver.version` — versões do SMART-JBMC e do ESBMC deste build.

Quando há um reparo verificado para a run, o patch confirmado pelo BMC é anexado
ao resultado como um `fix` (artifactChanges/replacements) — formato que IDEs
(VS Code), GitHub Code Scanning e CI sabem consumir.
"""

import os

from .classify import CWE_INFO
from .verifiers.esbmc import checagens, concurrency_flags, esbmc_version, property_flags

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# nível SARIF por severidade da tabela CWE/CERT.
# `note` NÃO aparece aqui de propósito: um BUG é uma violação PROVADA, com
# contraexemplo, e o GitHub Code Scanning trata `note` como informativo — não
# abre alerta. Um defeito alcançável entrando silencioso é pior que um alarme a
# mais. O piso para achado provado é `warning`; `note` fica reservado ao
# INCOMPLETE-BOUND, que é justamente o resultado inconclusivo.
_LEVEL_BY_SEV = {"high": "error", "medium": "warning", "low": "warning",
                 "unknown": "warning"}

# regra sintética p/ resultados inconclusivos (loop não coberto pelo unwind)
_RULE_INCOMPLETE = "INCOMPLETE-BOUND"


def _file_uri(path: str | None) -> str:
    if not path:
        return ""
    return "file://" + os.path.abspath(path)


def _read(path: str | None) -> str | None:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None


def _repair_index(repair_record: dict | None) -> dict[str, dict]:
    """Mapa source-path -> alvo de reparo REPARADO (para anexar fixes)."""
    if not repair_record:
        return {}
    targets = (repair_record.get("result") or {}).get("targets", [])
    idx = {}
    for t in targets:
        if t.get("status") == "REPAIRED" and t.get("source"):
            idx[t["source"]] = t
    return idx


def _fix_for(target: dict, repair: dict | None) -> list | None:
    """Constrói o array `fixes` SARIF com o patch verificado, se houver."""
    if not repair:
        return None
    fixed = repair.get("final_code") or _read(repair.get("fixed_path"))
    if not fixed:
        return None
    # O patch se aplica ao arquivo do DEFEITO, que num projeto multi-arquivo não é
    # o do ponto de entrada onde o bug foi reportado.
    patched = repair.get("repaired_file") or target.get("source")
    original = repair.get("original_code") or _read(patched) or ""
    end_line = original.count("\n") + 1 if original else 1
    iters = repair.get("iterations", "?")
    onde = ("" if patched == target.get("source")
            else f" Arquivo corrigido: {os.path.basename(patched)}.")
    return [{
        "description": {
            "text": f"Reparo verificado (proposto por LLM, confirmado FIX_OK pelo "
                    f"verificador em {iters} iteração(ões)).{onde}"
        },
        "artifactChanges": [{
            "artifactLocation": {"uri": _file_uri(patched)},
            "replacements": [{
                "deletedRegion": {"startLine": 1, "endLine": end_line},
                "insertedContent": {"text": fixed},
            }],
        }],
    }]


def build_sarif(run_record: dict, repair_record: dict | None = None,
                tool_version: str = "0.1.0") -> dict:
    """Monta o documento SARIF 2.1.0 de uma run de verificação concluída."""
    result_obj = run_record.get("result") or {}
    config = run_record.get("config") or result_obj.get("config") or {}
    targets = result_obj.get("targets", [])
    bug_targets = [t for t in targets if t.get("status") == "BUG"]
    unknown_targets = [t for t in targets if t.get("status") == "UNKNOWN"]
    repair_idx = _repair_index(repair_record)

    # --- regras: uma por CWE distinto + a regra sintética de bound incompleto ---
    rules, rule_ids = [], set()
    for t in bug_targets:
        cid = t.get("cwe_id") or "CWE-Other"
        if cid in rule_ids:
            continue
        rule_ids.add(cid)
        info = CWE_INFO.get(t.get("bug"), {})
        rules.append({
            "id": cid,
            "name": (t.get("cwe_name") or t.get("bug") or "Finding").replace(" ", ""),
            "shortDescription": {"text": t.get("cwe_name") or t.get("bug") or cid},
            "properties": {
                "cwe": cid,
                "cert": info.get("cert_rule", ""),
                "tags": ["security", cid],
            },
        })
    if unknown_targets:
        rules.append({
            "id": _RULE_INCOMPLETE,
            "name": "IncompleteBound",
            "shortDescription": {"text": "Verificação inconclusiva (bound insuficiente)"},
            "fullDescription": {"text": "O loop não coube no `unwind`; o resultado "
                                "não é SAFE nem BUG — aumente o unwind ou reduza o "
                                "tamanho do problema (modo sound)."},
            "properties": {"tags": ["incomplete"]},
        })

    # --- artifacts: TODO arquivo testado (caminho + status/ferramenta/tempo) ---
    artifacts, artifact_index = [], {}
    for t in targets:
        src = t.get("source")
        if not src or src in artifact_index:
            continue
        artifact_index[src] = len(artifacts)
        artifacts.append({
            "location": {"uri": _file_uri(src)},
            "sourceLanguage": "java" if t.get("kind") == "jbmc" else "c",
            "properties": {
                "status": t.get("status"),
                "verifier": t.get("kind"),
                "elapsed_s": t.get("elapsed_s"),
                "oracle": t.get("oracle"),
                "bug": t.get("bug"),
            },
        })

    def _location(src, violation=None, unit_sources=None):
        """Localização do achado; com `region` na linha do defeito, se houver.

        Sem `region` todo resultado ancora na linha 1 e o revisor precisa caçar
        o ponto no arquivo. Num projeto multi-arquivo o defeito raramente está
        no fonte do entrypoint, então o arquivo citado pela violação manda — é
        ele que o `fixes` também corrige.
        """
        alvo = src
        if violation and violation.get("file"):
            nome = violation["file"]
            for cand in (unit_sources or []):
                if os.path.basename(cand) == nome:
                    alvo = cand
                    break
        loc = {"physicalLocation": {"artifactLocation": {"uri": _file_uri(alvo)}}}
        if alvo in artifact_index:
            loc["physicalLocation"]["artifactLocation"]["index"] = artifact_index[alvo]
        if violation and violation.get("line"):
            loc["physicalLocation"]["region"] = {"startLine": violation["line"]}
        return loc

    # --- results: BUGs (nível por severidade) + UNKNOWN (nível note) ---
    results = []
    for t in bug_targets:
        info = CWE_INFO.get(t.get("bug"), {})
        level = _LEVEL_BY_SEV.get(info.get("severity", "unknown"), "warning")
        res = {
            "ruleId": t.get("cwe_id") or "CWE-Other",
            "level": level,
            "message": {
                "text": f"{t.get('bug', 'Bug')} detectado por {t.get('kind', 'BMC')} "
                        f"em {t.get('target', '?')}."
            },
            "locations": [_location(t.get("source"), t.get("violation"),
                                    t.get("unit_sources"))],
            "partialFingerprints": {"smartJbmcFindingV1": _fingerprint(t)},
            "properties": {
                "status": t.get("status"),
                "cert_priority": t.get("cert_priority"),
                "cert_level": t.get("cert_level"),
                "verifier": t.get("kind"),
                "elapsed_s": t.get("elapsed_s"),
                "violation": t.get("violation"),
            },
        }
        fix = _fix_for(t, repair_idx.get(t.get("source")))
        if fix:
            res["fixes"] = fix
        results.append(res)
    for t in unknown_targets:
        results.append({
            "ruleId": _RULE_INCOMPLETE,
            "level": "note",
            "message": {
                "text": f"Inconclusivo em {t.get('target', '?')}: o unwind "
                        f"({config.get('unwind', '?')}) não cobriu o loop — "
                        f"nem SAFE nem BUG."
            },
            "locations": [_location(t.get("source"))],
            "properties": {
                "status": "UNKNOWN", "verifier": t.get("kind"),
                "elapsed_s": t.get("elapsed_s"),
            },
        })

    # --- invocation: a configuração exata + a linha de comando + os tempos ---
    # Um alvo Java foi verificado por JBMC, não por ESBMC: registrar a linha do
    # ESBMC para uma run JVM documentava um comando que nunca rodou — e o campo
    # existe justamente para reprodutibilidade.
    kinds = {t.get("kind") for t in targets if t.get("kind")}
    invocation = {
        "commandLine": _cmd_template(config, kinds),
        "startTimeUtc": run_record.get("created_at"),
        "endTimeUtc": run_record.get("finished_at"),
        "executionSuccessful": run_record.get("status") in ("done", "cancelled"),
        "properties": {
            "folder": config.get("folder"),
            "solver": config.get("solver"),
            "solver_requested": config.get("solver_requested", config.get("solver")),
            "unwind": config.get("unwind"),
            "timeout_s": config.get("timeout"),
            "jobs": config.get("jobs"),
            "concurrency": config.get("concurrency"),
            # com concorrência o ESBMC para no primeiro defeito (sem --multi-property)
            "race_check": config.get("race_check"),
            "only_first_violation": bool(concurrency_flags(bool(config.get("concurrency")),
                                                           config.get("race_check"),
                                                           config.get("propriedade") or None)),
            "unsigned_overflow": bool(config.get("unsigned_overflow")),
            "nan_check": bool(config.get("nan_check")),
            "propriedade": config.get("propriedade") or "todas",
            # opções que não viram flag do ESBMC, mas mudam o que foi verificado
            "include_dirs": list(config.get("include_dirs") or []),
            "link_unit": list(config.get("link_unit") or []),
            "function": config.get("function") or None,
            "unwinding_assertions": config.get("unwinding_assertions"),
            "strategy": _strategy_of(config),
            "mode": _strategy_of(config),
            "n_targets": len(targets),
            "elapsed_s": result_obj.get("elapsed_s"),
            "verifiers": sorted({t.get("kind") for t in targets if t.get("kind")}),
            "warnings": result_obj.get("warnings", []),
        },
    }

    esbmc_v = esbmc_version()
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SMART ESBMC/JBMC",
                    "informationUri": "https://github.com/esbmc/esbmc",
                    "version": tool_version,
                    "rules": rules,
                    "properties": {
                        "esbmc_version": esbmc_v,
                        "verifiers": ["ESBMC (C)", "JBMC (Java/Kotlin)"],
                    },
                }
            },
            "invocations": [invocation],
            "artifacts": artifacts,
            "results": results,
            "properties": {
                "run_id": run_record.get("id"),
                "summary": result_obj.get("summary"),
                "metrics": result_obj.get("metrics"),
                "metrics_scope": _metrics_scope(result_obj),
            },
        }],
    }


def _fingerprint(t: dict) -> str:
    """Identidade estável do achado, para o Code Scanning não reabrir tudo a
    cada run. Ancorada em (arquivo, linha, CWE) — não no run_id nem no caminho
    absoluto, que mudam a cada upload e destruiriam a deduplicação."""
    v = t.get("violation") or {}
    arquivo = v.get("file") or os.path.basename(str(t.get("source") or ""))
    return "|".join([str(arquivo), str(v.get("line") or "?"),
                     str(t.get("cwe_id") or "CWE-Other")])


def _metrics_scope(result_obj: dict) -> dict:
    """Diz sobre QUANTOS alvos a matriz de confusão foi calculada.

    Sem isso, um `tp/tn/fp/fn` todo zero é ambíguo: pode ser "a ferramenta errou
    tudo" ou "não havia gabarito para comparar". Só alvos cujo caminho declara o
    ground truth (pastas com_bug//sem_bug/, bug//safe/) entram na matriz.
    """
    metrics = result_obj.get("metrics") or {}
    total = len(result_obj.get("targets") or [])
    n = metrics.get("n_avaliados")
    if n is None:                                   # runs antigas, sem o campo
        n = metrics.get("tp", 0) + metrics.get("tn", 0) \
            + metrics.get("fp", 0) + metrics.get("fn", 0)
    if not n:
        return {
            "aplicavel": False,
            "n_avaliados": 0,
            "n_total": total,
            "motivo": "Nenhum alvo tem gabarito no caminho: a matriz de confusão "
                      "e as taxas não se aplicam a esta run. Para medi-las, "
                      "organize o corpus em pastas com_bug/ e sem_bug/.",
        }
    return {
        "aplicavel": True,
        "n_avaliados": n,
        "n_total": total,
        "motivo": f"Matriz de confusão calculada sobre {n} de {total} alvo(s) — "
                  f"os demais não declaram o gabarito no caminho.",
    }


def _strategy_of(config: dict) -> str:
    """Estratégia da run, com fallback ao flag legado unwinding_assertions."""
    strat = config.get("strategy")
    if strat in ("bounded", "sound", "incremental", "kinduction"):
        return strat
    return "sound" if config.get("unwinding_assertions") else "bounded"


def _jbmc_cmd_template(config: dict) -> str:
    """Linha do JBMC desta run (alvos Java/Kotlin)."""
    parts = ["jbmc", "<classe>", "--json-ui", "--stop-on-fail",
             "--unwind", str(config.get("unwind", "?"))]
    if not _strategy_of(config) == "sound":
        parts.append("--no-unwinding-assertions")
    return " ".join(parts)


def _cmd_template(config: dict, kinds) -> str:
    """Comando(s) reproduzindo a run, um por verificador efetivamente usado."""
    kinds = set(kinds or ())
    linhas = []
    if "esbmc" in kinds or not kinds:
        linhas.append(_esbmc_cmd_template(config))
    if "jbmc" in kinds:
        linhas.append(_jbmc_cmd_template(config))
    return "  &&  ".join(linhas)


def _esbmc_cmd_template(config: dict) -> str:
    """Reconstrói a linha de comando ESBMC desta run (com `<arquivo.c>` no lugar
    do alvo) — registro fiel das flags exatas usadas."""
    unwind = config.get("unwind", "?")
    timeout = config.get("timeout", "?")
    solver = config.get("solver", "boolector")
    strat = _strategy_of(config)
    prop = config.get("propriedade") or None
    parts = ["esbmc", "<arquivo.c>", *checagens(prop),
             *property_flags(bool(concurrency_flags(bool(config.get("concurrency")),
                                                    config.get("race_check"), prop))),
             "--show-stacktrace", "--timeout", str(timeout)]
    for d in (config.get("include_dirs") or []):
        parts += ["-I", d]
    if config.get("function"):
        parts += ["--function", config["function"]]
    if config.get("unsigned_overflow"):
        parts.append("--unsigned-overflow-check")
    if config.get("nan_check"):
        parts.append("--nan-check")
    if strat == "incremental":
        parts.append("--incremental-bmc")
    elif strat == "kinduction":
        parts.append("--k-induction")
    elif strat == "sound":
        parts += ["--unwind", str(unwind)]
    else:  # bounded
        parts += ["--unwind", str(unwind), "--no-unwinding-assertions"]
    parts.append("--" + solver)
    parts += concurrency_flags(bool(config.get("concurrency")), config.get("race_check"), prop)
    return " ".join(parts)
