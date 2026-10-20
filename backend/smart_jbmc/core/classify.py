"""Classificação CWE/CERT-C e detecção de falha/bug.

Portado fielmente de JBMC_Projeto.py (CWE_INFO, cert_priority, has_failure,
has_error, detect_bug) — a tabela é inspirada no MITRE CWE Top-25 e no
CERT-C (Severity × Likelihood × Remediation → Priority + Level).
"""

import json
import re
from dataclasses import dataclass

# =====================================================
# TABELA CWE / CERT-C
# =====================================================

CWE_INFO = {
    "Division by Zero": {
        "cwe_id": "CWE-369", "cwe_name": "Divide By Zero", "top25_rank": 23,
        "severity": "low", "likelihood": "likely", "remediation": "low",
        "cert_rule": "INT33-C — operações de divisão/resto não devem ter divisor zero.",
    },
    "Null Pointer": {
        "cwe_id": "CWE-476", "cwe_name": "NULL Pointer Dereference", "top25_rank": 21,
        "severity": "high", "likelihood": "likely", "remediation": "medium",
        "cert_rule": "EXP34-C — não desreferenciar ponteiros nulos.",
    },
    "Overflow": {
        "cwe_id": "CWE-190", "cwe_name": "Integer Overflow or Wraparound", "top25_rank": None,
        "severity": "medium", "likelihood": "likely", "remediation": "medium",
        "cert_rule": "INT32-C — operações sobre inteiros com sinal não devem overflow.",
    },
    # Direção B. O estouro em ponto flutuante caía em "Overflow"/CWE-190, que é de
    # inteiro, e o NaN em "Unknown Failure". Não há CWE própria para nenhum dos
    # dois; a mais próxima é a CWE-682 (cálculo incorreto), mãe da 190 e da 369.
    # A regra CERT é que distingue os dois casos.
    "Float Overflow": {
        "cwe_id": "CWE-682", "cwe_name": "Incorrect Calculation", "top25_rank": None,
        "severity": "medium", "likelihood": "probable", "remediation": "medium",
        "cert_rule": "FLP03-C — detectar e tratar erros de ponto flutuante (estouro para infinito).",
    },
    "Float NaN": {
        "cwe_id": "CWE-682", "cwe_name": "Incorrect Calculation", "top25_rank": None,
        "severity": "medium", "likelihood": "probable", "remediation": "medium",
        "cert_rule": "FLP32-C — prevenir erros de domínio (resultado NaN) em ponto flutuante.",
    },
    # O ESBMC não acusa conversão para inteiro menor (não é UB em C). Esta
    # categoria recebe a asserção da regra de truncamento (incremento 3), cujo
    # texto deve conter "fixed-point truncation".
    "Numeric Truncation": {
        "cwe_id": "CWE-197", "cwe_name": "Numeric Truncation Error", "top25_rank": None,
        "severity": "medium", "likelihood": "probable", "remediation": "low",
        "cert_rule": "INT31-C — conversões de inteiros não devem perder nem alterar o valor.",
    },
    "Array Out Of Bounds": {
        "cwe_id": "CWE-125", "cwe_name": "Out-of-bounds Read", "top25_rank": 6,
        "severity": "high", "likelihood": "likely", "remediation": "medium",
        "cert_rule": "ARR30-C — não formar nem usar índices/ponteiros fora dos limites.",
    },
    "Buffer Overflow": {
        "cwe_id": "CWE-787", "cwe_name": "Out-of-bounds Write", "top25_rank": 2,
        "severity": "high", "likelihood": "likely", "remediation": "high",
        "cert_rule": "STR31-C — garantir espaço suficiente para strings; evitar escrita OOB.",
    },
    "Memory Leak": {
        "cwe_id": "CWE-401", "cwe_name": "Missing Release of Memory after Effective Lifetime",
        "top25_rank": None, "severity": "low", "likelihood": "probable", "remediation": "medium",
        "cert_rule": "MEM31-C — liberar memória dinâmica quando não for mais necessária.",
    },
    "Use After Free": {
        "cwe_id": "CWE-416", "cwe_name": "Use After Free", "top25_rank": 8,
        "severity": "high", "likelihood": "likely", "remediation": "medium",
        "cert_rule": "MEM30-C — não acessar memória já liberada (dangling pointer).",
    },
    "Double Free": {
        "cwe_id": "CWE-415", "cwe_name": "Double Free", "top25_rank": None,
        "severity": "high", "likelihood": "likely", "remediation": "medium",
        "cert_rule": "MEM30-C — não liberar duas vezes o mesmo bloco.",
    },
    "Deadlock": {
        "cwe_id": "CWE-833", "cwe_name": "Deadlock", "top25_rank": None,
        "severity": "medium", "likelihood": "probable", "remediation": "high",
        "cert_rule": "POS51-C — evitar deadlocks ao usar múltiplos mutexes.",
    },
    "Race Condition": {
        "cwe_id": "CWE-362", "cwe_name": "Concurrent Execution with Improper Synchronization",
        "top25_rank": None, "severity": "high", "likelihood": "probable", "remediation": "high",
        "cert_rule": "CON43-C — não permitir data races em código multithread.",
    },
    "Assertion Failure": {
        "cwe_id": "CWE-617", "cwe_name": "Reachable Assertion", "top25_rank": None,
        "severity": "medium", "likelihood": "probable", "remediation": "medium",
        "cert_rule": "MSC15-C — verificar invariantes; assert é alcançável e falha.",
    },
    # Específica da JVM: existe caminho em que uma exceção escapa sem tratamento
    # (ex.: require()/check() do Kotlin, que lançam IllegalArgumentException /
    # IllegalStateException). Antes caía em "Unknown Failure"/CWE-Other, o que
    # deixava a LLM sem CWE para citar no reparo — o prompt de reparo exige citar
    # o CWE recebido. A regra citada é do CERT Oracle **Java** (não CERT-C): a
    # violação não é de memória, é de contrato/tratamento de erro.
    "Uncaught Exception": {
        "cwe_id": "CWE-248", "cwe_name": "Uncaught Exception", "top25_rank": None,
        "severity": "medium", "likelihood": "probable", "remediation": "medium",
        "cert_rule": "ERR05-J/ERR08-J (CERT Oracle Java) — não deixar exceção escapar sem tratamento.",
    },
    "Unknown Failure": {
        "cwe_id": "CWE-Other", "cwe_name": "Unclassified", "top25_rank": None,
        "severity": "unknown", "likelihood": "unknown", "remediation": "unknown",
        "cert_rule": "Revisão manual recomendada.",
    },
}

_SEV_W = {"low": 1, "medium": 2, "high": 3, "unknown": 1}
_LIK_W = {"unlikely": 1, "probable": 2, "likely": 3, "unknown": 1}
_REM_W = {"high": 1, "medium": 2, "low": 3, "unknown": 1}


def suggestion(bug: str) -> str:
    """Texto curto de remediação por categoria de bug."""
    return {
        "Division by Zero": "Verifique se o denominador é diferente de zero antes da divisão/resto.",
        "Null Pointer": "Valide se a referência não é nula antes de desreferenciar.",
        "Overflow": "Use tipos maiores (Math.addExact / int64_t) ou valide limites.",
        "Float Overflow": "Limite a faixa das entradas ou sature o resultado antes que vire infinito.",
        "Float NaN": "Evite 0/0, inf-inf e raiz de negativo: valide o domínio antes da operação.",
        "Numeric Truncation": "Sature o valor na faixa do tipo de destino (ex.: __SSAT) ou ajuste a escala.",
        "Array Out Of Bounds": "Valide o índice em [0, size) antes do acesso.",
        "Buffer Overflow": "Limite o tamanho da escrita com strncpy/snprintf ou verifique tamanho.",
        "Memory Leak": "Libere a memória alocada (free/delete) ao final do tempo de vida.",
        "Use After Free": "Não acesse ponteiro após free; atribua NULL após liberar.",
        "Double Free": "Garanta que cada bloco seja liberado exatamente uma vez.",
        "Deadlock": "Imponha ordem global de aquisição de mutex; use try-lock com timeout.",
        "Race Condition": "Sincronize acessos compartilhados (mutex, atomic, volatile).",
        "Assertion Failure": "Revise o invariante; o BMC encontrou um caminho violando o assert.",
        "Uncaught Exception": "Trate a exceção (try/catch) ou valide a pré-condição antes da chamada que a lança.",
        "Unknown Failure": "Inspecione o contraexemplo manualmente.",
    }.get(bug, "Revisar código.")


def cert_priority(bug: str) -> tuple[int, str]:
    """Retorna (priority 1..27, level L1/L2/L3) segundo a tabela CERT-C."""
    info = CWE_INFO.get(bug, CWE_INFO["Unknown Failure"])
    p = _SEV_W[info["severity"]] * _LIK_W[info["likelihood"]] * _REM_W[info["remediation"]]
    if p >= 12:
        level = "L1"
    elif p >= 6:
        level = "L2"
    else:
        level = "L3"
    return p, level


# =====================================================
# DETECÇÃO DE FALHA / ERRO / BUG
# =====================================================

# Valores de `status` que marcam uma propriedade VIOLADA no JSON dos
# verificadores. O `--json-ui` do JBMC escreve "failed"; outras vias/versões
# escrevem "failure". Procurar só por "failure" fazia o casamento NUNCA ocorrer
# na via JVM — e sem ele o split real × unwinding não acontecia, de modo que uma
# unwinding assertion (bound insuficiente = UNKNOWN) era reportada como BUG.
_STATUS_FALHA = ("failed", "failure")


def safe_json(txt: str):
    """Tenta carregar JSON; se falhar, extrai o primeiro bloco {..}/[..]."""
    try:
        return json.loads(txt)
    except Exception:
        m = re.search(r"(\[.*\]|\{.*\})", txt, re.S)
        if m:
            try:
                return json.loads(m.group(1))
            except Exception:
                return None
    return None


def has_failure(text: str) -> bool:
    """Verificador reportou violação de propriedade (JBMC JSON ou texto ESBMC)."""
    if re.search(r'"status"\s*:\s*"(?:failure|failed)"', text, re.I):
        return True
    if re.search(r"\bVERIFICATION\s+FAILED\b", text):
        return True
    if re.search(r"Violated property", text):
        return True
    if re.search(r"(?:✗|\bX\b)\s*FAILED\s*:", text):
        return True
    return False


def has_error(text: str) -> bool:
    """Erro do verificador (flag inválida, parse error) — distinto de falha."""
    if re.search(r"^ERROR:", text, re.M):
        return True
    # Erro reportado DENTRO do JSON (--json-ui do JBMC): sem isto, um verificador
    # que morre no meio (ex.: estouro do teto de memória durante "Building error
    # trace") não casava nenhum padrão de erro, não tinha falha registrada — e o
    # alvo era classificado como SAFE. Verificador que quebra NÃO é prova de
    # ausência de bug; tem de virar ERROR.
    if re.search(r'"messageType"\s*:\s*"ERROR"', text):
        return True
    if re.search(r"unrecognised option", text, re.I):
        return True
    if re.search(r"PARSING\s+ERROR", text):
        return True
    if re.search(r"CONVERSION\s+ERROR", text):
        return True
    return False


def extract_diagnostics(raw: str, max_lines: int = 15, max_chars: int = 1000) -> str:
    """Extrai as linhas acionáveis (erros do compilador/frontend) da saída bruta
    do verificador — ex.: `fatal error: 'llama-model.h' file not found`,
    `PARSING ERROR`, `error: use of undeclared identifier` — para mostrar ao
    usuário/realimentar a LLM o MOTIVO de um ERROR, em vez de um card vazio.
    Fallback: últimas linhas não vazias da saída."""
    keep = []
    for line in raw.splitlines():
        low = line.lower()
        if ("error" in low or "undeclared" in low or "undefined" in low
                or "not found" in low or "fatal" in low
                or line.lstrip().startswith("^") or " | " in line):
            keep.append(line.rstrip())
    if not keep:  # fallback: últimas linhas não vazias
        keep = [ln.rstrip() for ln in raw.splitlines() if ln.strip()][-max_lines:]
    return "\n".join(keep[:max_lines])[:max_chars].strip()


def _failed_blob(text: str) -> str | None:
    """
    Extrai descrição+propriedade SOMENTE das propriedades que FALHARAM no
    JSON do JBMC (--json-ui), parseando a árvore de verdade. Ignora unwinding
    assertions (`.unwind.*` / "unwinding assertion") — ruído de bound, não a
    propriedade violada de interesse.

    Retorna None quando não há JSON com falhas (ex.: saída-texto do ESBMC),
    deixando o caminho legado (regex/texto) assumir.

    Motivo: o regex antigo casava `description ... property ... status:failure`
    com `[^{}]*?`, que NÃO atravessa o objeto `sourceLocation: {...}` que o
    JBMC insere entre `property` e `status`. Sem casar, caía no varrimento do
    texto inteiro e classificava pelas checagens que PASSARAM (ex.: bounds do
    `args[]`) — um div/0 em Java virava "Array Out Of Bounds".
    """
    obj = safe_json(text)
    if obj is None:
        return None
    real, anyfail = [], []

    def walk(o):
        if isinstance(o, dict):
            if str(o.get("status", "")).lower() in _STATUS_FALHA:
                desc = str(o.get("description", ""))
                prop = str(o.get("property", ""))
                entry = f"{desc} {prop}"
                anyfail.append(entry)
                if "unwind" not in prop.lower() and "unwinding assertion" not in desc.lower():
                    real.append(entry)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    chosen = real or anyfail
    return " ".join(chosen).lower() if chosen else None


def _split_failures(text: str) -> tuple[list[str], list[str]]:
    """Separa as propriedades VIOLADAS em (reais, unwinding).

    Uma 'unwinding assertion' falha quando o loop não coube no `unwind` (bound
    insuficiente) — NÃO é um bug, é incompletude. Distingui-la de uma violação
    real permite reportar UNKNOWN/INCOMPLETE em vez de SAFE vacuamente verdadeiro
    (quando ESBMC roda SEM `--no-unwinding-assertions`) ou de BUG falso.

    Funciona no JSON do JBMC (--json-ui) e no texto do ESBMC (--multi-property,
    linhas '✗ FAILED: ...'). Retorna ([], []) quando não há falhas explícitas.
    """
    real: list[str] = []
    unwind: list[str] = []

    def _is_unwind(desc: str, prop: str) -> bool:
        return ("unwind" in prop.lower()
                or "unwinding assertion" in desc.lower()
                or "unwinding assertion" in prop.lower())

    obj = safe_json(text)
    if obj is not None:
        def walk(o):
            if isinstance(o, dict):
                if str(o.get("status", "")).lower() in _STATUS_FALHA:
                    desc = str(o.get("description", ""))
                    prop = str(o.get("property", ""))
                    entry = f"{desc} {prop}".strip()
                    (unwind if _is_unwind(desc, prop) else real).append(entry)
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(obj)
        if real or unwind:
            return real, unwind

    # fallback texto (ESBMC): linhas '✗ FAILED: ...'
    for m in re.findall(r"(?:✗|\bX\b)\s*FAILED\s*:\s*'([^']+)'", text):
        (unwind if "unwinding assertion" in m.lower() else real).append(m)
    return real, unwind


def detect_bug(text: str) -> str:
    """
    Classifica a falha. Prioriza memória > concorrência > aritmética para
    evitar masking. Considera apenas as propriedades que FALHARAM.

    Estratégia de extração das falhas, em ordem:
      1. JSON do JBMC parseado (`_failed_blob`) — robusto a `sourceLocation`;
      2. linhas '✗ FAILED:' (formato compacto);
      3. texto completo (fallback p/ saída-texto do ESBMC).
    """
    low = text.lower()
    blob = _failed_blob(text)
    if blob is None:
        failed = re.findall(r"(?:✗|\bX\b)\s*FAILED\s*:\s*'([^']+)'", text)
        blob = " ".join(failed).lower() if failed else low

    # MEMÓRIA — CERT MEM30/MEM31
    if "forgotten memory" in blob or "memory leak" in blob:
        return "Memory Leak"
    if ("invalidated dynamic object" in blob or "use after free" in blob
            or "use-after-free" in blob
            or "dereference failure: deallocated dynamic object" in blob):
        return "Use After Free"
    if ("double free" in blob or "double-free" in blob
            or "freed pointer was not allocated" in blob
            or "deallocate already-deallocated" in blob):
        return "Double Free"

    # ARRAYS / BUFFER — CWE-787 / CWE-125
    if ("array bounds" in blob or "array-create-negative" in blob
            or "out-of-bounds" in blob or "buffer overflow" in blob):
        if "store" in blob or "write" in blob or "upper bound" in blob:
            return "Buffer Overflow"
        return "Array Out Of Bounds"

    # CONCORRÊNCIA
    if "deadlock" in blob:
        return "Deadlock"
    if "data race" in blob or "race condition" in blob:
        return "Race Condition"

    # PONTEIRO NULO — CERT EXP34-C
    if ("null pointer" in blob or "null-pointer" in blob
            or "dereference failure: null" in blob):
        return "Null Pointer"

    # ARITMÉTICA
    if ("division by zero" in blob or "divide-by-zero" in blob
            or "denominator should be nonzero" in blob):
        return "Division by Zero"
    # Direção B: antes do "overflow" genérico, que pegaria o de ponto flutuante,
    # e do "assertion", já que a regra de truncamento é uma asserção.
    if "fixed-point truncation" in blob:
        return "Numeric Truncation"
    if "nan on " in blob:
        return "Float NaN"
    if "overflow on floating-point" in blob:
        return "Float Overflow"
    if "overflow" in blob:
        return "Overflow"

    # ASSERT
    if "assertion" in blob:
        return "Assertion Failure"

    # EXCEÇÃO NÃO TRATADA (JVM) — checado DEPOIS de "assertion" de propósito: um
    # assert explícito é mais específico e mantém a prioridade. A propriedade do
    # JBMC chama-se "no uncaught exception" (violá-la = existe exceção escapando);
    # é o que `require()`/`check()` do Kotlin produzem.
    if "uncaught exception" in blob:
        return "Uncaught Exception"

    return "Unknown Failure"


# =====================================================
# VEREDICTO CONSOLIDADO  (lógica de status do analyze() original)
# =====================================================

@dataclass
class Verdict:
    status: str          # BUG | SAFE | UNKNOWN | TIMEOUT | ERROR | NO_ENTRY_POINT
    bug: str | None
    cwe_info: dict | None
    cert_priority: int | None
    cert_level: str | None
    n_findings: int


def classify(raw_text: str, obj=None) -> Verdict:
    """Deriva status + classificação a partir da saída bruta do verificador.

    Status possíveis:
      BUG     — propriedade real violada (contraexemplo).
      UNKNOWN — só falharam unwinding assertions: o `unwind` não cobriu o loop,
                então o resultado é INCONCLUSIVO (nem SAFE nem BUG). Só ocorre no
                modo sound (ESBMC sem `--no-unwinding-assertions`).
      SAFE    — nenhuma propriedade violada (no modo bounded é garantia até o bound).
      TIMEOUT / ERROR — verificador estourou tempo / erro de ferramenta.
    """
    timed_out = "TIMEOUT:" in raw_text
    errored = has_error(raw_text)
    # veredito explícito de inconclusão (k-induction / incremental-bmc):
    # "VERIFICATION UNKNOWN" / "Unable to prove or falsify the program".
    unknown_verdict = ("VERIFICATION UNKNOWN" in raw_text
                       or "Unable to prove or falsify" in raw_text)
    real, unwind = _split_failures(raw_text)
    # rede de segurança: se o detector textual acusa falha mas o split não pegou
    # nada (formato inesperado), trata como falha real para não perder bugs.
    if not real and not unwind and has_failure(raw_text):
        real = ["unclassified failure"]
    bug = detect_bug(raw_text) if real else None

    n_findings = (
        len(re.findall(r'"status"\s*:\s*"(?:failure|failed)"', raw_text, re.I))
        + len(re.findall(r"Violated property", raw_text))
    ) or len(real)

    if timed_out:
        status = "TIMEOUT"
    elif bug:
        status = "BUG"
    elif errored:
        status = "ERROR"
    elif unwind or unknown_verdict:   # bound insuficiente ou inconclusão explícita
        status = "UNKNOWN"
    else:
        status = "SAFE"

    info = CWE_INFO.get(bug) if bug else None
    prio, level = cert_priority(bug) if bug else (None, None)
    return Verdict(status, bug, info, prio, level, n_findings)
