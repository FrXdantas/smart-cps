"""Guarda semântica: o ponto do defeito ainda EXECUTA depois do patch?

As guardas de `loop._validate_patch` são sintáticas e pegam o patch que mexe na
especificação (asserção reescrita, `assume` novo). Sobra o modo mais sutil de
enganar o oráculo: **tornar o trecho defeituoso inalcançável**. O BMC então prova
SAFE — e está certo, código morto não viola nada — mas o programa deixou de fazer
o que fazia. Casos reais que passaram como REPARADO:

    // TC4 — `y` é constante 0; a divisão nunca mais executa
    + if (y == 0) return 0
      return x/y

    // TC6 — array de tamanho 2; o corpo do `if` é morto
    + if (100 in arr.indices) {
          arr[100] = 2
      }

Como se decide, sem heurística sintática: insere-se uma asserção-sonda
(`assert false`) imediatamente ANTES da instrução do defeito e re-verifica.
  * a sonda FALHA  -> aquele ponto é alcançável -> o patch reparou de verdade;
  * a sonda PASSA  -> ninguém chega lá          -> o defeito foi removido por
                                                   inalcançabilidade, não corrigido.

Custo: uma verificação extra por patch que já passou no oráculo. Só roda quando
o veredicto foi FIX_OK, então não pesa nas iterações que falharam.

Em qualquer situação ambígua devolve None (= "não sei"), e quem chama aceita o
patch. Falso positivo aqui rejeitaria reparo legítimo, que é o pior erro
possível — ver o caso `Random.nextInt`, em que o oráculo já recusava o patch
correto.
"""

import os
import re

from .regression import regression_check

# Instrução-sonda por linguagem. `assert false` é a forma mais portátil de
# perguntar "este ponto executa?" a um verificador que já checa asserções.
_SONDA = {
    ".java": "assert false;",
    ".kt": "assert(false)",
    ".c": "assert(0);",
    ".h": "assert(0);",
    ".cpp": "assert(0);",
    ".cc": "assert(0);",
}

_SO_ESPACO = re.compile(r"\s+")


def _norm(linha: str) -> str:
    return _SO_ESPACO.sub("", linha or "")


def _indentacao(linha: str) -> str:
    return linha[:len(linha) - len(linha.lstrip())]


def localizar_no_patch(original_code: str, patch_code: str,
                       linha_defeito: int) -> int | None:
    """Índice (0-based) da instrução do defeito dentro do patch.

    Casa pelo TEXTO da instrução, não pelo número da linha: o patch quase sempre
    desloca as linhas. Exige correspondência única — se a instrução sumiu do
    patch (reescrita legítima) ou aparece várias vezes, devolve None e a guarda
    se abstém.
    """
    orig = (original_code or "").splitlines()
    if not (1 <= (linha_defeito or 0) <= len(orig)):
        return None
    alvo = _norm(orig[linha_defeito - 1])
    if not alvo:
        return None
    achados = [i for i, l in enumerate((patch_code or "").splitlines())
               if _norm(l) == alvo]
    return achados[0] if len(achados) == 1 else None


def instrumentar(patch_code: str, idx: int, ext: str) -> str | None:
    """Devolve o patch com a sonda inserida imediatamente antes de `idx`."""
    sonda = _SONDA.get(ext)
    if sonda is None:
        return None
    linhas = (patch_code or "").splitlines()
    if not (0 <= idx < len(linhas)):
        return None
    linhas.insert(idx, _indentacao(linhas[idx]) + sonda)
    return "\n".join(linhas) + "\n"


def ponto_do_defeito_executa(*, original_code, patch_code, linha_defeito, ext,
                             work_dir, stem, unwind, timeout, solver,
                             unsigned_overflow=False, nan_check=False, propriedade=None, strategy=None,
                             concurrency=False, race_check=None, include_dirs=None, function=None,
                             unit_sources=None, repaired_source=None,
                             entry_class=None) -> bool | None:
    """True se o ponto do defeito ainda é alcançável no patch; None se indecidível.

    Não levanta: qualquer falha de compilação/verificação da sonda vira None, e
    o patch segue aceito como antes desta guarda existir.
    """
    idx = localizar_no_patch(original_code, patch_code, linha_defeito)
    if idx is None:
        return None
    sondado = instrumentar(patch_code, idx, ext)
    if sondado is None:
        return None
    if ext in (".c", ".h", ".cpp", ".cc"):
        from .loop import ensure_c_headers
        sondado = ensure_c_headers(sondado)

    caminho = os.path.join(work_dir, f"{stem}_REACH{ext}")
    try:
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(sondado)
        # A sonda é a ÚNICA asserção que pode falhar (o patch já passou no
        # oráculo). Falhou => o ponto executa.
        reg = regression_check(caminho, "Assertion Failure", unwind, timeout, solver,
                               unsigned_overflow=unsigned_overflow, nan_check=nan_check, propriedade=propriedade, strategy=strategy,
                               concurrency=concurrency, race_check=race_check, include_dirs=include_dirs,
                               function=function,
                               unit_sources=unit_sources,
                               repaired_source=repaired_source,
                               entry_class=entry_class)
    except OSError:
        return None
    finally:
        try:
            os.remove(caminho)
        except OSError:
            pass

    if reg.verdict in ("ERROR", "TIMEOUT"):
        return None                      # indecidível: não penaliza o patch
    if reg.verdict == "FIX_OK":
        return False                     # nada falhou => a sonda não é atingida
    return True                          # a sonda falhou => ponto alcançável
