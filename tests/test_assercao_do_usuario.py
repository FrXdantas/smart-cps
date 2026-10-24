"""R4 (caso FreeRTOS #1236, 24/10/2026): asserção do usuário com mensagem própria.

`__ESBMC_assert(cond, "texto")` ou `assert` com mensagem não tem a palavra "assertion"
na descrição, e saía "Unknown Failure / CWE-Other". O identificador da propriedade no
resumo do 8.6 tem ".assertion.", mas o 8.6 também usa esse identificador em falhas
internas de ponteiro ("dereference failure: ..."), que não podem virar asserção.
"""

from smart_jbmc.core.classify import classify, detect_bug

# Resumo REAL do ESBMC 8.6.0 no com_bug do caso (run 965f15d918e9), encurtado.
FALHA_ASSERCAO = """\
** Results:
  PASSED       [modelo_fim_da_thread.assertion.1]                           line  94  dereference failure: Program code accessed with non-zero offset
  FAILED       [modelo_getspecific.assertion.1]                             line  49  pthread_getspecific com chave que não veio de pthread_key_create

** 1 of 84 properties failed, 83 passed

VERIFICATION FAILED
"""

# Mesmo formato, mas a falha é interna de ponteiro com identificador ".assertion.".
FALHA_INTERNA = """\
** Results:
  FAILED       [modelo_fim_da_thread.assertion.1]                           line  94  dereference failure: Program code accessed with non-zero offset

** 1 of 84 properties failed, 83 passed

VERIFICATION FAILED
"""


def test_assercao_com_mensagem_propria_e_assertion_failure():
    v = classify(FALHA_ASSERCAO)
    assert v.status == "BUG"
    assert v.bug == "Assertion Failure"
    assert v.cwe_info["cwe_id"] == "CWE-617"


def test_falha_interna_de_ponteiro_nao_vira_assercao():
    assert detect_bug(FALHA_INTERNA) != "Assertion Failure"
