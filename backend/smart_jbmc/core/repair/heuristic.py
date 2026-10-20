"""Reparo heurístico (baseline a ser batido pelo reparo-LLM da Etapa 6).

Portado dos patch_* / fixed_source / FIX_HEADER do JBMC_Projeto.py. Os patches
de uma linha (div-zero, null, array-OOB) reescrevem o código; bugs de memória
recebem apenas um cabeçalho TODO — por isso costumam ficar STILL_VULNERABLE na
regressão (achado honesto que motiva o reparo guiado por contraexemplo).
"""

import re

from ..classify import CWE_INFO, suggestion
from ..constants import KOTLIN_PRIMITIVES

JAVA_PRIMITIVES = {"int", "long", "short", "byte", "float", "double", "boolean", "char"}

FIX_HEADER = (
    "// =====================================================\n"
    "// Correção automática gerada por SMART-JBMC.\n"
    "// Bug: {bug} ({cwe})\n"
    "// CERT-C: {cert}\n"
    "// Sugestão: {sug}\n"
    "// As alterações são heurísticas — revise antes de usar.\n"
    "// =====================================================\n\n"
)


def patch_division_by_zero(src, ext):
    pat = re.compile(r"(\b\w+\b)\s*([/%])\s*(\b\w+\b)")

    def repl(m):
        a, op, b = m.group(1), m.group(2), m.group(3)
        if b.isdigit() and int(b) != 0:
            return m.group(0)
        if ext == ".kt":
            return f"(if ({b} != 0) {a} {op} {b} else 0)"
        return f"(({b}) != 0 ? ({a} {op} {b}) : 0)"

    return pat.sub(repl, src)


def patch_null_pointer(src, ext):
    if ext == ".kt":
        new_lines = []
        for line in src.splitlines(keepends=True):
            new_lines.append(line)
            m = re.match(r"^\s*fun\s+\w+\s*\(([^)]*)\)", line)
            if not m:
                continue
            for p in m.group(1).split(","):
                pm = re.match(r"(\w+)\s*:\s*([\w\.\?<>]+)", p.strip())
                if not pm:
                    continue
                name, typ = pm.group(1), pm.group(2).replace("?", "")
                if typ not in KOTLIN_PRIMITIVES:
                    new_lines.append(f'    requireNotNull({name}) {{ "{name} não pode ser nulo" }}\n')
        return "".join(new_lines)

    out = []
    method_re = re.compile(
        r"^(\s*(?:public|private|protected|static|\s)+\s*[\w<>,\s\[\]]+\s+\w+\s*\(([^)]*)\))\s*\{"
    )
    for line in src.splitlines(keepends=True):
        out.append(line)
        m = method_re.match(line)
        if not m:
            continue
        for p in m.group(2).split(","):
            pm = re.match(r"(?:final\s+)?([\w<>,\[\]]+)\s+(\w+)", p.strip())
            if not pm:
                continue
            typ, name = pm.group(1), pm.group(2)
            if typ not in JAVA_PRIMITIVES:
                out.append(f"        java.util.Objects.requireNonNull({name});\n")
    return "".join(out)


def patch_array_oob(src, ext):
    pat = re.compile(r"(\b\w+\b)\[(.*?)\]")

    def repl(m):
        arr, idx = m.group(1), m.group(2).strip()
        if ext == ".kt":
            return (f"({arr}.let {{ a -> require(({idx}) in 0 until a.size) "
                    f'{{ "índice fora dos limites" }}; a[{idx}] }})')
        return f"((({idx}) >= 0 && ({idx}) < ({arr}).length) ? ({arr})[{idx}] : 0)"

    return pat.sub(repl, src)


def _todo(msg):
    return lambda src, _ext: f"// TODO[SMART-JBMC]: {msg}\n\n" + src


_PATCHERS = {
    "Division by Zero": patch_division_by_zero,
    "Null Pointer": patch_null_pointer,
    "Array Out Of Bounds": patch_array_oob,
    "Overflow": _todo("risco de overflow — use Math.*Exact / __builtin_*_overflow."),
    "Float Overflow": _todo("estouro em ponto flutuante — limite a faixa ou sature (FLP03-C)."),
    "Float NaN": _todo("NaN — valide o domínio antes da operação (FLP32-C)."),
    "Numeric Truncation": _todo("truncamento — sature na faixa do tipo de destino (INT31-C)."),
    "Memory Leak": _todo("memory leak — garanta um free por malloc (MEM31-C)."),
    "Use After Free": _todo("use-after-free — após free(p), p = NULL (MEM30-C)."),
    "Double Free": _todo("double free — libere cada bloco exatamente uma vez."),
    "Buffer Overflow": _todo("escrita fora dos limites — use snprintf/strncpy (CWE-787)."),
    "Deadlock": _todo("deadlock — ordem global de mutexes ou try-lock (POS51-C)."),
    "Race Condition": _todo("data race — sincronize estado compartilhado (CON43-C)."),
}


def fixed_source(bug: str, original_text: str, ext: str) -> str:
    """Aplica o patch heurístico correspondente à categoria do bug."""
    return _PATCHERS.get(bug, lambda s, _e: s)(original_text, ext)


def build_fixed_source(bug: str, original_text: str, ext: str) -> str:
    """Conteúdo completo do arquivo *_FIXED: cabeçalho explicativo + patch."""
    info = CWE_INFO.get(bug, CWE_INFO["Unknown Failure"])
    header = FIX_HEADER.format(bug=bug, cwe=info["cwe_id"], cert=info["cert_rule"], sug=suggestion(bug))
    return header + fixed_source(bug, original_text, ext)
