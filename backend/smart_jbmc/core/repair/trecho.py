"""RR4: reparo por função, para unidades que não cabem no teto de saída da LLM.

O reparo normal pede o arquivo inteiro de volta. Uma unidade de firmware depois do
pré-processamento pode passar do teto (llm.MAX_TOKENS_CAP) e a resposta seria
cortada sempre (LLM_TRUNCATED). Nesses casos, e só neles, a LLM recebe a função que
contém a linha do defeito e devolve só essa função, que é recolocada no arquivo
antes da verificação. O oráculo continua verificando o arquivo inteiro.
"""

import re

from . import llm

_CABECALHO_NOME = re.compile(r"([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$", re.S)


def precisa_trecho(code: str) -> bool:
    """True quando o arquivo inteiro não cabe no teto de saída."""
    return (len(code or "") * 3) // 4 + llm._FOLGA_RACIOCINIO > llm.MAX_TOKENS_CAP


def _blocos_de_topo(code: str):
    """(início, fim) em offsets de cada bloco { } de nível zero, ignorando
    comentários, strings e literais de caractere."""
    blocos, prof, ini, i, n = [], 0, None, 0, len(code)
    while i < n:
        c = code[i]
        if code.startswith("//", i):
            j = code.find("\n", i)
            i = n if j < 0 else j
            continue
        if code.startswith("/*", i):
            j = code.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in "\"'":
            j = i + 1
            while j < n and code[j] != c:
                j += 2 if code[j] == "\\" else 1
            i = j + 1
            continue
        if c == "{":
            if prof == 0:
                ini = i
            prof += 1
        elif c == "}":
            prof -= 1
            if prof == 0 and ini is not None:
                blocos.append((ini, i))
                ini = None
        i += 1
    return blocos


def funcao_que_contem(code: str, linha: int):
    """(ini, fim, nome): linhas (base 0, inclusivas) da definição de função que
    contém `linha` (base 1), com o cabeçalho. None se a linha não cai numa função."""
    if not linha or linha < 1:
        return None
    off_linha = [0]
    for m in re.finditer("\n", code):
        off_linha.append(m.end())
    if linha > len(off_linha):
        return None
    alvo = off_linha[linha - 1]
    blocos = _blocos_de_topo(code)
    for k, (a, b) in enumerate(blocos):
        if not (a <= alvo <= b):
            continue
        # o cabeçalho começa depois do último ';', '}' ou diretiva de nível zero anterior
        inicio_busca = blocos[k - 1][1] + 1 if k else 0
        antes = code[inicio_busca:a]
        corte = max(antes.rfind(";"), antes.rfind("}"))
        cab_ini = inicio_busca + corte + 1
        cabecalho = code[cab_ini:a]
        # pula linhas em branco, comentários e diretivas antes do cabeçalho
        linhas_cab = cabecalho.split("\n")
        while linhas_cab and (not linhas_cab[0].strip()
                              or linhas_cab[0].lstrip().startswith(("#", "//", "/*", "*"))):
            cab_ini += len(linhas_cab[0]) + 1
            linhas_cab.pop(0)
        m = _CABECALHO_NOME.search(code[cab_ini:a])
        if not m:
            return None          # bloco que não é função (struct, inicializador)
        ini = code.count("\n", 0, cab_ini)
        fim = code.count("\n", 0, b)
        return ini, fim, m.group(1)
    return None


def extrair(code: str, ini: int, fim: int) -> str:
    return "\n".join(code.split("\n")[ini:fim + 1])


def recolocar(code: str, ini: int, fim: int, nova: str) -> str:
    linhas = code.split("\n")
    return "\n".join(linhas[:ini] + nova.rstrip("\n").split("\n") + linhas[fim + 1:])


def parece_uma_funcao(texto: str) -> bool:
    """A resposta precisa ser UMA definição de função (um bloco de nível zero)."""
    return len(_blocos_de_topo(texto or "")) == 1
