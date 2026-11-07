"""Grupo D do experimento: LLM puro, sem BMC.

A LLM recebe SÓ o código: nenhum contraexemplo, nenhuma categoria, nenhuma linha.
Ela diz se há defeito, qual (CWE), onde (linha) e propõe a correção numa única
chamada, sem laço e sem realimentação. A detecção é comparada com o gabarito
(F1 da RQ3). A correção, quando houver, é conferida depois pelo BMC só para
registro, por quem chama (tools/executar_bracos.py).

Usa a mesma via HTTP do reparo (`llm.chat`): mesmo provedor, tentativas e teto.
"""

import json
import re

from . import llm

SYSTEM_PROMPT_D = (
    "Você é um revisor de código C de sistemas embarcados e concorrentes (RTOS, "
    "drivers, controladores digitais em ponto fixo). Recebe um programa e deve "
    "decidir, só pela leitura do código, se ele contém um defeito que viola uma "
    "propriedade de segurança: asserção que pode falhar, chamada a reach_error() "
    "alcançável, condição de corrida, impasse, estouro aritmético, acesso fora dos "
    "limites, ponteiro nulo, uso após free, vazamento de memória.\n"
    "Responda EXATAMENTE neste formato:\n"
    "1) Um bloco ```json com as chaves: \"defeito\" (true ou false), \"cwe\" (ex.: "
    "\"CWE-362\", ou null), \"linha\" (número da linha do defeito, ou null) e "
    "\"justificativa\" (uma frase).\n"
    "2) Se \"defeito\" for true, um bloco ```c com o PROGRAMA INTEIRO corrigido, com a "
    "menor mudança possível, sem apagar asserções nem acrescentar assume. Se for "
    "false, não escreva o bloco ```c."
)

_JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_C_RE = re.compile(r"```(?:c|C|cpp)?\s*\n(.*?)\n```", re.DOTALL)
_CWE_RE = re.compile(r"CWE-(\d+)")


def _numerar(code: str) -> str:
    """Linhas numeradas para a LLM poder apontar a linha do defeito."""
    return "\n".join(f"{i:4d}| {ln}" for i, ln in enumerate(code.splitlines(), 1))


def mensagens(code: str, file_name: str | None = None) -> list[dict]:
    rotulo = f"ARQUIVO ({file_name})" if file_name else "PROGRAMA"
    user = (f"--- {rotulo}, com as linhas numeradas à esquerda (a numeração não faz "
            f"parte do código) ---\n{_numerar(code)}\n")
    return [{"role": "system", "content": SYSTEM_PROMPT_D},
            {"role": "user", "content": user}]


def interpretar(texto: str) -> dict:
    """Extrai a resposta. Formato inválido vira `formato_invalido=True`, não exceção:
    no experimento isso é um resultado do braço (a LLM não seguiu o formato)."""
    out = {"defeito": None, "cwe": None, "linha": None, "justificativa": None,
           "codigo": None, "formato_invalido": False}
    m = _JSON_RE.search(texto or "")
    if not m:
        out["formato_invalido"] = True
        return out
    try:
        dados = json.loads(m.group(1))
    except json.JSONDecodeError:
        out["formato_invalido"] = True
        return out
    d = dados.get("defeito")
    out["defeito"] = d if isinstance(d, bool) else None
    if out["defeito"] is None:
        out["formato_invalido"] = True
    cwe = _CWE_RE.search(str(dados.get("cwe") or ""))
    out["cwe"] = f"CWE-{cwe.group(1)}" if cwe else None
    try:
        out["linha"] = int(dados.get("linha")) if dados.get("linha") is not None else None
    except (TypeError, ValueError):
        out["linha"] = None
    out["justificativa"] = dados.get("justificativa")
    resto = texto[m.end():]
    c = _C_RE.search(resto)
    if out["defeito"] and c:
        out["codigo"] = c.group(1)
    return out


def detectar_e_corrigir(code: str, *, file_name=None, model=None, base_url=None,
                        api_key=None, temperature=0.2, max_tokens=None) -> dict:
    """Uma chamada do grupo D. Devolve a resposta interpretada + uso e tempo."""
    r = llm.chat(mensagens(code, file_name), code_len_hint=code, model=model,
                 base_url=base_url, api_key=api_key, temperature=temperature,
                 max_tokens=max_tokens)
    out = interpretar(r["content"])
    out.update(usage=r.get("usage"), model=r.get("model"), ms=r.get("ms"),
               truncated=r.get("truncated"))
    if out["truncated"]:
        out["codigo"] = None   # código cortado não é correção (RR1)
    return out
