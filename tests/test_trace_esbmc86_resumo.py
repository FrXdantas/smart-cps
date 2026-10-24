"""R5 (caso FreeRTOS #1236, 24/10/2026): o trace do ESBMC 8.6 não engole o resumo.

No 8.6 o estado final pode vir sem atribuições, com "Violated property:" logo após a
linha de traços. O corpo do estado só terminava em "\nViolated property:", e como o
"\n" já tinha sido consumido, ia até o fim da saída: as linhas "PASSED [...]" do resumo
que têm "=" viravam "valores que levaram à violação".
"""

from smart_jbmc.core.counterexample import explain_counterexample, parse_esbmc_trace_text

# Saída REAL do ESBMC 8.6.0 (--multi-property --show-stacktrace) no com_bug do caso,
# com o resumo encurtado.
AMOSTRA = """\
State 3 file freertos_1236.c line 49 column 5 function modelo_getspecific thread 2
----------------------------------------------------
Violated property:
  file freertos_1236.c line 49 column 5 function modelo_getspecific
Stack trace:
  c:freertos_1236.c@F@modelo_getspecific at file freertos_1236.c line 170 column 35 function prvIsFreeRTOSThread
  c:freertos_1236.c@F@prvIsFreeRTOSThread at file freertos_1236.c line 182 column 9 function vPortDisableInterrupts
  c:@F@vPortDisableInterrupts at file freertos_1236.c line 205 column 5 function prvOutraThread
  c:freertos_1236.c@F@prvOutraThread at file /esbmc-vfs/libc/library/pthread_lib.c line 231 column 20 function pthread_trampoline
  pthread_getspecific com chave que não veio de pthread_key_create
  k < 4 && (_Bool)(ucChaveCriada[(signed long int)k])


** Results:
freertos_1236.c, function modelo_fim_da_thread
  PASSED       [modelo_fim_da_thread.arithmetic-overflow.1]                 line  87  arithmetic overflow on add
  PASSED       [modelo_fim_da_thread.array-bounds-violated.1]               line  89  array bounds violated: array `xValores' lower bound
  PASSED       [modelo_fim_da_thread.array-bounds-violated.2]               line  89  array bounds violated: array `xValores' upper bound
  PASSED       [modelo_fim_da_thread.array-bounds-violated.3]               line  89  array bounds violated: array `xValores' lower bound
  PASSED       [modelo_fim_da_thread.assertion.1]                           line  94  dereference failure: Program code accessed with non-zero offset
freertos_1236.c, function modelo_getspecific
  PASSED       [modelo_getspecific.array-bounds-violated.1]                 line  49  array bounds violated: array `ucChaveCriada' upper bound
  FAILED       [modelo_getspecific.assertion.1]                             line  49  pthread_getspecific com chave que não veio de pthread_key_create
  PASSED       [modelo_getspecific.array-bounds-violated.2]                 line  55  array bounds violated: array `xValores' lower bound [xValores[(signed long int)i].valor != 0 => (signed long int)i >= 0]
  PASSED       [modelo_getspecific.arithmetic-overflow.1]                   line  53  arithmetic overflow on add

** 1 of 84 properties failed, 83 passed

VERIFICATION FAILED
"""


def test_estado_final_sem_atribuicoes_nao_engole_o_resumo():
    steps, violations = parse_esbmc_trace_text(AMOSTRA)
    assert [s["state"] for s in steps] == [3]
    assert steps[0]["assigns"] == []
    assert violations[-1]["line"] == 49


def test_explicacao_sem_linhas_do_resumo():
    steps, violations = parse_esbmc_trace_text(AMOSTRA)
    texto = explain_counterexample("Assertion Failure", steps, violations)
    assert "PASSED" not in texto
    assert "pthread_getspecific com chave" in texto
