"""Parser de contraexemplo (JBMC JSON + texto ESBMC) e explicação em linguagem natural.

Portado de parse_trace_steps / flatten_state / parse_esbmc_trace_text /
explain_counterexample do JBMC_Projeto.py.

Os dois parsers devolvem a MESMA forma — `(steps, violations)` — para que
`explain_counterexample` sirva as duas vias (ESBMC/C e JBMC/JVM) sem ramificar:
  steps      = [{"state": int, "file": str, "line": int|str, "function": str,
                 "assigns": [str]}]
  violations = [{"file": str, "line": int|str, "description": str,
                 "condition": str}]
"""

import os
import re

from .classify import detect_bug, safe_json

# =====================================================
# TRACE DO JBMC (JSON, --json-ui)
# =====================================================

# Símbolos que o JBMC materializa no trace por causa do modelo da JVM e que não
# ajudam a entender o bug: plumbing do alocador de arrays, identificadores de
# classe e variáveis do próprio CPROVER. Tudo que é interno ao modelo usa '@'
# (`@class_identifier`, `@inflight_exception`) ou um destes nomes fixos.
#
# O bloco do Kotlin foi acrescentado depois de ver o contraexemplo real de um
# `require()`: dos 5 valores entregues à LLM, 4 eram ruído — o marcador de lambda
# inline (`$i$a$-require-...`), o literal da mensagem de erro repetido em dois
# passos e temporários do compilador. Sem filtrar, o sinal útil some no meio.
_JBMC_NOISE_LHS = re.compile(
    r"@"
    r"|^__CPROVER"
    r"|^nondet_"
    r"|^(array_data_init|array_init_iter|new_array_item|malloc_site"
    r"|tmp_object_factory|uncaught_exception)"
    r"|_already_run$"
    # --- Kotlin/JVM ---
    r"|^\$i\$"              # marcador de função/lambda inline do kotlinc
    r"|^anonlocal::"        # frame SEM debug info (stdlib inline); o código do
                            # usuário tem nome real, pois compilamos com -g
    r"|^return_tmp\d*$"     # temporário de retorno do compilador
    r"|^stub_ignored_arg"   # argumento descartado de stub
    r"|^this$"              # receptor do método: não explica o bug
)

_JBMC_FAILED = ("failed", "failure")   # o --json-ui usa "failed"; outras vias, "failure"


def _fmt_value(val):
    """Renderiza o valor de um passo: prefere o dado concreto ('data')."""
    if isinstance(val, dict):
        return val.get("data", val.get("name", str(val)))
    return val


def _jbmc_line(v):
    """Linha como int (o JBMC serializa como string)."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return v if v is not None else "-"


def _jbmc_function(name) -> str:
    """`java::ArrayOob.main:([Ljava/lang/String;)V` -> `ArrayOob.main`.

    Descarta o descritor JVM, que é ruído para a LLM e para o relatório.
    """
    if not name:
        return "-"
    name = str(name)
    if name.startswith("java::"):
        name = name[len("java::"):]
    return name.split(":")[0] or "-"


def _jbmc_properties(obj) -> list:
    """Entradas de propriedade (as que têm 'trace') do JSON do JBMC.

    O `--json-ui` entrega uma LISTA no topo, em que a propriedade violada é um
    objeto solto `{description, property, status, trace}`; outras versões/vias
    aninham as propriedades sob `result`. Varrer a árvore cobre os dois formatos.
    """
    found: list = []

    def walk(o):
        if isinstance(o, dict):
            if isinstance(o.get("trace"), list):
                found.append(o)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return found


def parse_jbmc_trace_json(raw) -> tuple[list, list]:
    """Retorna (steps, violations) do contraexemplo do JBMC (`--json-ui`).

    Aceita a saída bruta (str) ou o objeto já parseado. Espelha
    `parse_esbmc_trace_text`: sem isto, a via JVM chegava à LLM sem contraexemplo
    (só o parágrafo genérico da categoria) — o reparo em Java/Kotlin corrigia às
    cegas, enquanto o de C recebia ponto exato da violação + valores.

    O trace do JBMC é dominado por passos do modelo da JVM: dos 69 passos de um
    caso trivial, só ~11 dizem algo. Por isso descartamos os passos marcados
    `hidden`/`internal` pelo próprio JBMC, os sem origem no código do usuário e
    os símbolos de plumbing (`_JBMC_NOISE_LHS`) — o que sobra são os valores que
    de fato levaram à violação.
    """
    obj = raw if isinstance(raw, (dict, list)) else safe_json(raw or "")
    if obj is None:
        return [], []

    steps: list = []
    violations: list = []
    state = 0

    for prop in _jbmc_properties(obj):
        if str(prop.get("status", "")).lower() not in _JBMC_FAILED:
            continue
        last_assign = None      # colapsa repetições consecutivas do mesmo valor
        last_loc = ("-", "-")
        saw_failure = False

        for st in prop["trace"]:
            if not isinstance(st, dict):
                continue
            kind = st.get("stepType")
            sl = st.get("sourceLocation") or {}

            if kind == "failure":
                saw_failure = True
                # Nem toda propriedade do JBMC tem LINHA: a de exceção não tratada
                # é atribuída ao MÉTODO. Nesse caso caímos na linha do último passo
                # do trace — o que é um palpite razoável (é onde a execução estava),
                # mas NÃO é o ponto reportado pelo verificador. Marcamos como
                # aproximada para a explicação não afirmar precisão que não tem.
                tem_linha = bool(sl.get("line"))
                violations.append({
                    "file": sl.get("file") or last_loc[0],
                    "line": _jbmc_line(sl.get("line")) if tem_linha else last_loc[1],
                    "line_aproximada": not tem_linha,
                    "description": (st.get("reason")
                                    or prop.get("description") or "").strip(),
                    # análogo à "condição que falha" do ESBMC: a classe da
                    # propriedade violada (ex.: array-index-out-of-bounds-high).
                    "condition": (sl.get("propertyClass") or st.get("property")
                                  or prop.get("property") or "").strip(),
                })
                continue

            if kind != "assignment" or st.get("hidden") or st.get("internal"):
                continue
            lhs = str(st.get("lhs") or "").strip()
            if not lhs or _JBMC_NOISE_LHS.search(lhs):
                continue
            file = sl.get("file") or "-"
            if file == "-":
                continue        # passo sem origem no código do usuário
            assign = f"{lhs} = {_fmt_value(st.get('value'))}"
            if assign == last_assign:
                continue
            last_assign = assign
            last_loc = (file, _jbmc_line(sl.get("line")))
            state += 1
            steps.append({
                "state": state, "file": file, "line": last_loc[1],
                "function": _jbmc_function(sl.get("function")), "assigns": [assign],
            })

        if not saw_failure:
            # propriedade violada sem passo 'failure' no trace: ainda assim
            # entrega o ponto aproximado (último passo) em vez de nada.
            violations.append({
                "file": last_loc[0], "line": last_loc[1], "line_aproximada": True,
                "description": str(prop.get("description") or "").strip(),
                "condition": str(prop.get("property") or "").strip(),
            })

    return steps, violations


# =====================================================
# TRACE DO ESBMC (texto)
# =====================================================

_ESBMC_STATE_RE = re.compile(
    r"State\s+(\d+)\s+file\s+(\S+)\s+line\s+(\d+)\s+column\s+(\d+)"
    r"\s+function\s+(\S+)\s+thread\s+(\d+)\s*\n"
    r"-{5,}\s*\n"
    r"(.*?)"
    # Âncoras de início de linha (re.M), não "\n...": no 8.6 o estado final pode vir
    # sem atribuições, com "Violated property:" logo após os traços, e o corpo ia até
    # o fim da saída, engolindo o resumo "** Results:" (caso FreeRTOS #1236).
    r"(?=^State\s+\d+\s+file|^Violated property:|^\*\* Results:|^VERIFICATION|\Z)",
    re.S | re.M,
)
_ESBMC_ASSIGN_RE = re.compile(
    r"^\s+([^=\n]+?)\s*=\s*(.+?)(?:\s+\([01\s]+\))?\s*$", re.M
)
# Com --show-stacktrace, quando o defeito está fora do `main`, o ESBMC intercala
# um bloco "Stack trace:" (uma linha "... at file ..." por quadro) entre o local
# e a descrição. A condição pode faltar (ex.: "arithmetic overflow on add"
# seguida de linha em branco), por isso é opcional e só vale a linha seguinte.
# A partir do 8.6 o ESBMC imprime "CWE: CWE-681" entre a descrição e a condição;
# essa linha é lida à parte para não tomar o lugar da condição.
_ESBMC_VIOLATION_RE = re.compile(
    r"Violated property:\s*\n"
    r"\s+file\s+(\S+)\s+line\s+(\d+)[^\n]*\n"
    r"(?:[ \t]*Stack trace:[ \t]*\n((?:[^\n]*\bat file\b[^\n]*\n)*))?"
    r"[ \t]+([^\n]+)"
    r"(?:\n[ \t]+CWE:[ \t]*([^\n]+))?"
    r"(?:\n[ \t]+([^\n]+))?",
)


# Quadro do "Stack trace:" do ESBMC (--show-stacktrace):
#   c:@F@divide at file a.c line 3 column 34 function media
# = estava em `divide`, chamada a partir de `media`, na linha 3.
_ESBMC_QUADRO_RE = re.compile(
    r"(?:c:[^@\s]*@F@)?(\S+)\s+at file\s+(\S+)\s+line\s+(\d+)(?:\s+column\s+\d+)?"
    r"(?:\s+function\s+(\S+))?")


def _pilha(bloco: str) -> list[dict]:
    """Quadros da pilha real do ESBMC, do mais interno (onde falhou) ao `main`."""
    quadros = []
    for ln in bloco.splitlines():
        m = _ESBMC_QUADRO_RE.search(ln)
        if m:
            quadros.append({"funcao": m.group(1), "arquivo": m.group(2),
                            "linha": int(m.group(3)), "chamador": m.group(4)})
    return quadros


def parse_esbmc_trace_text(text: str) -> tuple[list, list]:
    """Retorna (steps, violations) do contraexemplo em texto do ESBMC."""
    steps = []
    for m in _ESBMC_STATE_RE.finditer(text):
        state, file, line, _col, func, thread, body = m.groups()
        assigns = []
        for am in _ESBMC_ASSIGN_RE.finditer(body):
            lhs, rhs = am.group(1).strip(), am.group(2).strip()
            if lhs.lower().startswith(("violated", "file", "function")):
                continue
            assigns.append(f"{lhs} = {rhs}")
        steps.append({
            "state": int(state), "file": file, "line": int(line),
            "function": func, "assigns": assigns, "thread": int(thread),
        })
    violations = []
    for vm in _ESBMC_VIOLATION_RE.finditer(text):
        violations.append({
            "file": vm.group(1), "line": int(vm.group(2)),
            "description": vm.group(4).strip(), "condition": (vm.group(6) or "").strip(),
            "cwe_esbmc": (vm.group(5) or "").strip(),
            "pilha": _pilha(vm.group(3) or ""),
        })
    return steps, violations


# =====================================================
# EXPLICAÇÃO EM LINGUAGEM NATURAL
# =====================================================

EXPLAIN_TEMPLATES = {
    "Division by Zero": (
        "O verificador encontrou uma execução em que o divisor vale 0 no momento da divisão.\n"
        "  • Propriedade violada: INT33-C (CERT-C): o operando direito de '/' ou '%' não pode ser zero.\n"
        "  • Resultaria em SIGFPE (em C) ou ArithmeticException (na JVM)."
    ),
    "Null Pointer": (
        "O verificador encontrou um caminho em que um ponteiro/referência nulo(a) é desreferenciado(a).\n"
        "  • Propriedade violada: EXP34-C (CERT-C).\n"
        "  • Em C: segmentation fault. Na JVM: NullPointerException."
    ),
    "Array Out Of Bounds": (
        "Existe uma execução em que um índice de leitura está fora de [0, length).\n"
        "  • Propriedade violada: ARR30-C (CERT-C) / CWE-125 (Out-of-bounds Read).\n"
        "  • Em C: leitura de memória inválida (UB). Na JVM: ArrayIndexOutOfBoundsException."
    ),
    "Buffer Overflow": (
        "Existe uma execução em que uma escrita ultrapassa o limite de um buffer.\n"
        "  • Propriedade violada: STR31-C (CERT-C) / CWE-787 (ranking #2 no CWE Top-25).\n"
        "  • Em C: corrupção de memória, base clássica de exploits."
    ),
    "Overflow": (
        "Existe uma execução em que uma operação aritmética com sinal sofre overflow/wraparound.\n"
        "  • Propriedade violada: INT32-C (CERT-C) / CWE-190.\n"
        "  • UB em C; wrap-around silencioso em Java."
    ),
    "Float Overflow": (
        "Existe uma execução em que uma operação em ponto flutuante passa do maior valor do tipo e vira infinito.\n"
        "  • Propriedade violada: FLP03-C (CERT-C) / CWE-682.\n"
        "  • Não é UB em C: o infinito segue no cálculo e contamina o resultado (ex.: saída do controlador)."
    ),
    "Float NaN": (
        "Existe uma execução em que uma operação em ponto flutuante produz NaN (ex.: 0/0, inf-inf).\n"
        "  • Propriedade violada: FLP32-C (CERT-C) / CWE-682.\n"
        "  • Toda comparação com NaN dá falso, então testes de limite passam a ser ignorados."
    ),
    "Numeric Truncation": (
        "Existe uma execução em que um valor é convertido para um inteiro menor sem caber nele.\n"
        "  • Propriedade violada: INT31-C (CERT-C) / CWE-197.\n"
        "  • Em ponto fixo (Q15/Q31), o valor volta pelo outro extremo: +1,0 vira -1,0."
    ),
    "Memory Leak": (
        "Memória alocada (malloc/calloc/strdup) não é liberada antes de o ponteiro perder alcance.\n"
        "  • Propriedade violada: MEM31-C (CERT-C) / CWE-401.\n"
        "  • Degrada o programa em execução longa."
    ),
    "Use After Free": (
        "Existe um caminho em que um ponteiro é usado depois de free().\n"
        "  • Propriedade violada: MEM30-C (CERT-C) / CWE-416 (ranking #8 no CWE Top-25).\n"
        "  • Vetor frequente de exploits."
    ),
    "Double Free": (
        "Um mesmo bloco é liberado mais de uma vez.\n"
        "  • Propriedade violada: MEM30-C (CERT-C) / CWE-415.\n"
        "  • Pode corromper o heap."
    ),
    "Deadlock": (
        "Threads aguardam mutexes em ordens contrárias.\n"
        "  • Propriedade violada: POS51-C (CERT-C) / CWE-833.\n"
        "  • Bloqueio indefinido."
    ),
    "Race Condition": (
        "Duas threads acessam a mesma variável compartilhada sem sincronização.\n"
        "  • Propriedade violada: CON43-C (CERT-C) / CWE-362.\n"
        "  • Resultado depende da escala de execução."
    ),
    "Assertion Failure": (
        "Um caminho faz um assert(...) explícito do código falhar.\n"
        "  • Propriedade violada: MSC15-C (CERT-C) / CWE-617.\n"
        "  • O invariante presumido não vale para todas as entradas."
    ),
    "Uncaught Exception": (
        "Existe um caminho em que uma exceção é lançada e escapa sem tratamento.\n"
        "  • Propriedade violada: ERR05-J/ERR08-J (CERT Oracle Java) / CWE-248.\n"
        "  • Típico de contratos idiomáticos do Kotlin: require() lança\n"
        "    IllegalArgumentException e check() lança IllegalStateException.\n"
        "  • Não é violação de memória: a pré-condição do contrato não vale para\n"
        "    todas as entradas, ou falta tratar a exceção no chamador."
    ),
    "Unknown Failure": (
        "O verificador reportou falha, mas a categoria não foi reconhecida.\n"
        "  • Inspecione o trace para entender a causa."
    ),
}


def pick_violation(bug, violations) -> dict | None:
    """A violação que ancora o achado `bug`.

    O JBMC para na primeira falha, então a última violação basta. O ESBMC, com
    --multi-property, lista várias, e a última pode ser só consequência da
    principal (ex.: o overflow na soma de um valor lido fora do vetor). Prefere
    a última cuja descrição classifica como o próprio `bug`.
    """
    if not violations:
        return None
    for v in reversed(violations):
        texto = f"{v.get('description') or ''} {v.get('condition') or ''}"
        if bug and detect_bug(texto) == bug:
            return v
    return violations[-1]


def explain_counterexample(bug, esbmc_steps, esbmc_violations) -> str:
    """Explicação em duas partes: significado do bug + resumo da execução."""
    parts = [EXPLAIN_TEMPLATES.get(bug or "Unknown Failure", EXPLAIN_TEMPLATES["Unknown Failure"])]

    if esbmc_violations:
        v = pick_violation(bug, esbmc_violations)
        sem_local = str(v.get("file", "-")) == "-" and str(v.get("line", "-")) == "-"
        if sem_local:
            # O verificador acusou a violação mas o trace não veio (típico de morte
            # por estouro do teto de memória durante a construção do error trace).
            # Dizer "linha aproximada" sobre "arquivo -, linha -" seria inventar
            # precisão inexistente: o certo é declarar que o contraexemplo falta.
            parts.append(
                f"\nContraexemplo indisponível:\n"
                f"  o verificador acusou a violação mas NÃO produziu o trace —\n"
                f"  causa provável: estourou o teto de memória ao construí-lo.\n"
                f"  Reduza `jobs` (o orçamento é rateado entre eles) ou aumente\n"
                f"  SMART_JBMC_MAX_MEM_TOTAL_MB para obter o contraexemplo.\n"
                f"  descrição: {v['description']}\n"
                f"  condição que falha: {v['condition']}"
            )
        else:
            # Só chamamos de "exato" quando o verificador de fato reportou a linha.
            aprox = v.get("line_aproximada")
            titulo = ("Ponto da violação (linha aproximada)" if aprox
                      else "Ponto exato da violação")
            nota = ("  (o verificador atribuiu esta propriedade ao método, sem linha;\n"
                    "   a linha abaixo é a do último passo do contraexemplo)\n") if aprox else ""
            parts.append(
                f"\n{titulo}:\n"
                f"{nota}"
                f"  arquivo {v['file']}, linha {v['line']}\n"
                f"  descrição: {v['description']}"
                + (f"\n  condição que falha: {v['condition']}" if v.get("condition") else "")
            )

    linha = linha_do_tempo(esbmc_steps)
    if linha:
        parts.append(linha)
        return "\n".join(parts)

    relevant = []
    for st in esbmc_steps[-8:]:
        for a in st["assigns"]:
            relevant.append((st["state"], st["file"], st["line"], a))
    if relevant:
        parts.append("\nValores que levaram à violação (últimos passos):")
        for state, file, line, a in relevant[-5:]:
            parts.append(f"  • estado {state} ({file}:{line})  {a}")

    return "\n".join(parts)


# =====================================================
# GRUPO B: "STACK TRACE" (sem valores, sem passos)
# =====================================================

# Funções do modelo do verificador que não pertencem ao programa.
_FUNCOES_INTERNAS = re.compile(r"^(__ESBMC|__CPROVER|__VERIFIER|c::__|pthread_|_start$)")


def cadeia_de_chamadas(steps, violations=None, limite: int = 10) -> list[str]:
    """Funções do caminho até a falha, da mais recente para a mais antiga.

    O ESBMC não emite pilha de chamadas. A aproximação usada é a ordem em que as
    funções do programa aparecem no traço, de trás para frente, sem repetição:
    é o que um programador reconstruiria de um crash com depurador. Não leva
    valores de variáveis nem os passos.
    """
    nomes: list[str] = []
    for st in reversed(steps or []):
        f = str(st.get("function") or "").strip()
        if not f or f == "-" or _FUNCOES_INTERNAS.match(f) or f in nomes:
            continue
        nomes.append(f)
        if len(nomes) >= limite:
            break
    return nomes


def stack_trace_text(bug, steps, violations) -> str:
    """Contexto do grupo B (BMC + stack trace): categoria, ponto da falha e cadeia
    de chamadas. Diferente de `explain_counterexample`, NÃO traz a condição que
    falha nem os valores que levaram à violação: isso é o que o grupo C acrescenta.
    """
    parts = [EXPLAIN_TEMPLATES.get(bug or "Unknown Failure", EXPLAIN_TEMPLATES["Unknown Failure"])]
    v = pick_violation(bug, violations or [])
    if v and not (str(v.get("file", "-")) == "-" and str(v.get("line", "-")) == "-"):
        parts.append(f"\nPonto da falha:\n  arquivo {v['file']}, linha {v['line']}\n"
                     f"  descrição: {v['description']}")
    pilha = (v or {}).get("pilha") or []
    if pilha:
        # pilha real do ESBMC (--show-stacktrace): função e local de cada chamada
        parts.append("\nPilha de chamadas (da mais recente para a mais antiga):")
        for q in pilha:
            onde = (f", chamada por {q['chamador']} na linha {q['linha']}"
                    if q.get("chamador") else "")
            parts.append(f"  em {q['funcao']}{onde}")
        return "\n".join(parts)
    # Sem o bloco (defeito no próprio main, ou JBMC): aproximação pelo traço.
    cadeia = cadeia_de_chamadas(steps, violations)
    if cadeia:
        parts.append("\nFunções no caminho até a falha (da mais recente para a mais antiga):")
        parts.extend(f"  em {f}" for f in cadeia)
    return "\n".join(parts)


# =====================================================
# LINHA DO TEMPO DAS THREADS (item 4 do plano de 07/11)
# =====================================================

def _passo_do_programa(st) -> bool:
    f = str(st.get("file") or "")
    return not f.startswith("/esbmc-vfs") and not _FUNCOES_INTERNAS.match(str(st.get("function") or ""))


def linha_do_tempo(steps, limite: int = 30) -> str | None:
    """Intercalação das threads no contraexemplo, só com os passos do programa.

    Devolve None quando o traço tem uma thread só (não há o que intercalar) ou
    não traz o número da thread (JBMC). Cada troca de thread é marcada com ">>",
    porque é nela que mora a condição de corrida: quem leu antes de quem gravar.
    """
    passos = [st for st in steps or [] if "thread" in st and _passo_do_programa(st)]
    if len({st["thread"] for st in passos}) < 2:
        return None
    passos = passos[-limite:]
    linhas = ["\nLinha do tempo das threads (passos do programa até a violação; "
              ">> marca a troca de thread):"]
    anterior = None
    for st in passos:
        troca = ">>" if anterior is not None and st["thread"] != anterior else "  "
        efeito = "; ".join(st.get("assigns") or []) or "(sem atribuição)"
        nome = os.path.basename(str(st.get("file") or ""))
        linhas.append(f"{troca} thread {st['thread']} | {st.get('function')} "
                      f"({nome}:{st.get('line')}) | {efeito}")
        anterior = st["thread"]
    return "\n".join(linhas)
