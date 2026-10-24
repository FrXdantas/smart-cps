"""R3 (caso FreeRTOS #1236, 24/10/2026): diagnóstico do ERROR sem linhas repetidas.

Na run c341df7b77ef (jobs 2) a explicação trouxe "ERROR: Out of memory" e "ERROR: SMT
solver failed" repetidos dezenas de vezes. Cada linha passa a aparecer uma vez e, na
falta de memória, vem a causa provável e o que fazer.
"""

from smart_jbmc.core.classify import extract_diagnostics

SAIDA = "Solving with solver Boolector 3.2.4\n" + \
    "ERROR: Out of memory\nERROR: SMT solver failed\n" * 30


def test_cada_linha_aparece_uma_vez():
    d = extract_diagnostics(SAIDA)
    assert d.count("ERROR: Out of memory") == 1
    assert d.count("ERROR: SMT solver failed") == 1


def test_falta_de_memoria_traz_a_acao():
    d = extract_diagnostics(SAIDA)
    assert "jobs" in d and "unwind" in d


def test_sem_falta_de_memoria_nao_traz_a_dica():
    assert "jobs" not in extract_diagnostics("PARSING ERROR\nerror: undeclared x\n")
