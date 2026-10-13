"""Constantes do motor de verificação (portadas do JBMC_Projeto.py)."""

DEFAULT_UNWIND = 5
DEFAULT_TIMEOUT = 120

# Orçamento de memória dos VERIFICADORES. Limitar só o TEMPO não protege a
# máquina: medido em 2026-07-26, o JBMC cresce ~1 GB a cada 3 s construindo o
# error trace de certos casos (ex.: qualquer uso de `Integer.MAX_VALUE`, que puxa
# o clinit de java.lang.Integer). Com o timeout padrão isso dá dezenas de GB por
# processo — e `jobs` deles em paralelo — o que congela a máquina ANTES de
# qualquer timeout disparar (foi o que aconteceu: um único jbmc chegou a 26,4 GiB
# de 30,7 GiB). Com o teto, o verificador morre sozinho com erro de alocação e o
# alvo vira ERROR, sem derrubar o resto.
#
# O orçamento é TOTAL e dividido pelo `jobs`, não um teto fixo por processo: com
# teto fixo, aumentar `jobs` multiplicava o consumo máximo (8 × 4 GB = 32 GB, mais
# que a RAM da máquina) e reintroduzia justamente o risco que o teto deveria
# eliminar. Dividindo, `jobs` alto fica seguro por construção e `jobs=1` entrega o
# orçamento inteiro ao caso pesado.
#   SMART_JBMC_MAX_MEM_TOTAL_MB — orçamento total (0 = sem teto)
#   SMART_JBMC_MAX_MEM_MB       — força um teto POR PROCESSO, ignorando o rateio
DEFAULT_MEM_TOTAL_MB = 12288
# Piso por processo: abaixo disto o verificador não consegue nem carregar o
# modelo da JVM, e o rateio viraria ERROR garantido em vez de proteção.
MIN_MEM_POR_PROCESSO_MB = 1024

# Bytecode em Java 8 (--release 8) para compatibilidade ampla da JVM.
JAVAC_RELEASE = "8"
KOTLIN_JVM_TARGET = "1.8"

KOTLIN_PRIMITIVES = {
    "Int", "Long", "Short", "Byte",
    "Float", "Double", "Boolean", "Char",
}

# Extensões da família C verificadas pelo ESBMC. O frontend do ESBMC detecta C
# vs C++ pela própria extensão do arquivo (todas seguem o mesmo pipeline:
# do_esbmc → run_esbmc, sem flag de linguagem). Fonte única consumida pelo
# scanner, pela contagem da SPA, pela regressão e pelo reparo-LLM.
C_EXTS = (".c",)
CPP_EXTS = (".cpp", ".cc", ".cxx", ".c++")
C_FAMILY_EXTS = C_EXTS + CPP_EXTS
