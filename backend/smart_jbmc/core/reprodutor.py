"""Reprodutor do defeito: caso de teste do ESBMC + executável com sanitizer (incremento 4).

Orientação de 10/11/2026: o ESBMC gera o caso de teste que verifica a issue, e o executável é
gerado junto com o sanitizer. Requisitos RT1 a RT9 em
deltas_semanais/semana_06_10a17-11/requisitos_reprodutor_sanitizer.txt.

Dois modos, por alvo com veredito BUG:
- "caso de teste": o ESBMC roda de novo com as mesmas opções e --generate-ctest-testcase. O
  test_case.c traz os valores não determinísticos do contraexemplo; o harness é compilado com
  um cabeçalho nativo que dá semântica de execução aos intrínsecos do ESBMC.
- "driver nativo": se ao lado do alvo existir a pasta <nome>_nativo/ (ou nativo/), ela tem um
  programa que compila com o código real (ex.: o port POSIX do FreeRTOS). É o caso de harness
  com modelo do ambiente, que não tem semântica fora do ESBMC. O caso de teste não é gerado.

O sanitizer depende do defeito: ThreadSanitizer para corrida e impasse; AddressSanitizer com
UBSan para estouro, memória e asserção. O veredito compara o relato do sanitizer com o
contraexemplo: linha (ou função) da violação, ou a variável da corrida.
"""

import os
import re
import shutil
import subprocess
import time

from .compiler import _require

# Encerramento de caminho inviável: __ESBMC_assume falso numa execução real. Não é defeito.
SAIDA_INVIAVEL = 77
# Com --multi-property o ESBMC gera um caso de teste por propriedade violada.
MAX_CASOS = 5

VEREDITOS = ("REPRODUZIDO", "REPRODUZIDO_OUTRO_PONTO", "NAO_REPRODUZIDO", "SEM_CASO_DE_TESTE",
             "FALHA_COMPILACAO", "INCONCLUSIVO")

# Tipos das funções não deterministas (convenção SV-COMP e ESBMC).
_NONDET = {
    "int": "int", "uint": "unsigned int", "unsigned": "unsigned int", "char": "char",
    "uchar": "unsigned char", "short": "short", "ushort": "unsigned short", "long": "long",
    "ulong": "unsigned long", "longlong": "long long", "ulonglong": "unsigned long long",
    "bool": "_Bool", "float": "float", "double": "double", "size_t": "unsigned long",
    "u32": "unsigned int", "u16": "unsigned short", "u8": "unsigned char",
}

# Cabeçalho incluído (-include) só no harness. Dá semântica de execução ao que o ESBMC
# interpreta: asserção vira aborto com local, assume falso encerra o caminho, a seção atômica
# vira uma trava global recursiva, e nondet_* (convenção ESBMC) vira __VERIFIER_nondet_*, que é
# o nome que o test_case.c gerado implementa.
CABECALHO_NATIVO = r"""/* smart_nativo.h: gerado pelo SMART CPS (reprodutor). Não editar. */
#ifndef SMART_NATIVO_H
#define SMART_NATIVO_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
static pthread_mutex_t __smart_trava = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static void __smart_falha(const char *arq, int lin, const char *msg) {
  fprintf(stderr, "SMART_ASSERT %s:%d: %s\n", arq, lin, msg); fflush(stderr); abort();
}
static void __smart_inviavel(const char *arq, int lin) {
  fprintf(stderr, "SMART_INVIAVEL %s:%d\n", arq, lin); fflush(stderr); _exit(%(inviavel)d);
}
#define __ESBMC_assert(c, msg) ((c) ? (void)0 : __smart_falha(__FILE__, __LINE__, (msg)))
#define __ESBMC_assume(c) ((c) ? (void)0 : __smart_inviavel(__FILE__, __LINE__))
#define __VERIFIER_assume(c) __ESBMC_assume(c)
#define __VERIFIER_error() __smart_falha(__FILE__, __LINE__, "__VERIFIER_error")
#define __ESBMC_atomic_begin() pthread_mutex_lock(&__smart_trava)
#define __ESBMC_atomic_end() pthread_mutex_unlock(&__smart_trava)
#define __VERIFIER_atomic_begin() __ESBMC_atomic_begin()
#define __VERIFIER_atomic_end() __ESBMC_atomic_end()
%(nondet)s
#endif
"""


def cabecalho_nativo() -> str:
    linhas = [f"#define nondet_{t} __VERIFIER_nondet_{t}" for t in _NONDET]
    return (CABECALHO_NATIVO.replace("%(inviavel)d", str(SAIDA_INVIAVEL))
            .replace("%(nondet)s", "\n".join(linhas)))


def nondet_padrao() -> str:
    """Definições fracas: valem só quando o test_case.c não traz a função (o contraexemplo não
    usou aquela entrada). Sem elas o executável nem liga (RT3)."""
    corpo = ["/* smart_nondet_padrao.c: gerado pelo SMART CPS (reprodutor). */"]
    for t, c in _NONDET.items():
        corpo.append(f"__attribute__((weak)) {c} __VERIFIER_nondet_{t}(void) {{ return 0; }}")
    corpo.append("__attribute__((weak)) void *__VERIFIER_nondet_pointer(void) { return 0; }")
    return "\n".join(corpo) + "\n"


_CHAMADA_NONDET_RE = re.compile(r"\b(?:__VERIFIER_)?nondet_(\w+?)\s*\(")
_BOOL = {"true": "1", "false": "0", "TRUE": "1", "FALSE": "0"}


def caso_pelo_contraexemplo(raw: str | None, files) -> tuple[str, int]:
    """Caso de teste montado com os valores do contraexemplo do ESBMC, casando cada passo do
    trace com a linha do fonte onde há uma chamada nondet_*. Devolve (código C, nº de valores).

    Motivo (achado de 13/11/2026, CMSIS arm_pid_q31): o --generate-ctest-testcase do ESBMC 8.6
    põe na sequência de __VERIFIER_nondet_int também os valores de variáveis não inicializadas
    (os campos da struct local S). O valor da entrada (e = -536870912) foi para a 4ª posição, a
    1ª chamada recebeu 0 e o executável não chegou ao estouro.
    """
    from .counterexample import parse_esbmc_trace_text
    chamadas: dict[tuple[str, int], str] = {}
    for f in files:
        texto = _ler(f, 50_000_000) or ""
        for n, linha in enumerate(texto.splitlines(), 1):
            m = _CHAMADA_NONDET_RE.findall(linha)
            if len(m) == 1 and m[0] in _NONDET:
                chamadas[(os.path.basename(f), n)] = m[0]
    valores: dict[str, list[str]] = {}
    for st in (parse_esbmc_trace_text(raw or "")[0] if raw else []):
        tipo = chamadas.get((os.path.basename(str(st.get("file"))), st.get("line")))
        if not tipo or not st.get("assigns"):
            continue
        v = st["assigns"][0].split("=", 1)[1].strip()
        v = _BOOL.get(v, v)
        if re.fullmatch(r"[-+]?(\d+(\.\d*)?([eE][-+]?\d+)?|0x[0-9a-fA-F]+)[uUlLfF]*", v):
            valores.setdefault(tipo, []).append(v)
    linhas = ["/* test_case_contraexemplo.c: gerado pelo SMART CPS com os valores do",
              "   contraexemplo do ESBMC, na ordem das chamadas nondet_* do trace. */",
              "void __VERIFIER_assume(int cond) { (void)cond; }"]
    for tipo, vs in valores.items():
        c = _NONDET[tipo]
        linhas.append(f"{c} __VERIFIER_nondet_{tipo}(void) {{\n  static int i = 0;\n"
                      f"  static {c} const v[] = {{ {', '.join(vs)} }};\n"
                      f"  return i < {len(vs)} ? v[i++] : 0;\n}}")
    return "\n".join(linhas) + "\n", sum(len(v) for v in valores.values())


# --------------------------------------------------------------------------- escolha

def e_concorrencia(bug: str | None, cwe_id: str | None, violation: dict | None) -> bool:
    texto = " ".join(str(x or "") for x in (bug, (violation or {}).get("description"),
                                             (violation or {}).get("condition"))).lower()
    return cwe_id in ("CWE-362", "CWE-833") or "race" in texto or "deadlock" in texto


def sanitizer_para(bug, cwe_id, violation) -> str:
    """RT5: tsan para corrida e impasse; asan+ubsan para o resto. Os dois não se misturam."""
    return "tsan" if e_concorrencia(bug, cwe_id, violation) else "asan+ubsan"


def flags_sanitizer(san: str) -> list[str]:
    if san == "tsan":
        return ["-fsanitize=thread"]
    return ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer"]


def variavel_da_corrida(violation: dict | None) -> str | None:
    """'R/W data race on c:arq.c@xSchedulerEnd' ou '!(RACE_CHECK(&xSchedulerEnd))'."""
    v = violation or {}
    for texto, rx in ((v.get("description"), r"race on \S*?@?([A-Za-z_]\w*)\s*$"),
                      (v.get("condition"), r"RACE_CHECK\(&?\(?([A-Za-z_]\w*)")):
        m = re.search(rx, str(texto or ""))
        if m:
            return m.group(1)
    return None


def pasta_nativa(source: str | None) -> str | None:
    """RT/D2: <nome>_nativo/ ao lado do alvo; senão nativo/ na mesma pasta."""
    if not source:
        return None
    base = os.path.dirname(source)
    stem = os.path.splitext(os.path.basename(source))[0]
    for cand in (os.path.join(base, stem + "_nativo"), os.path.join(base, "nativo")):
        if os.path.isdir(cand):
            return cand
    return None


def e_pasta_nativa(nome: str) -> bool:
    """O scanner não verifica o que está dentro de uma pasta de driver nativo."""
    return nome == "nativo" or nome.endswith("_nativo")


# --------------------------------------------------------------------------- leitura

_UBSAN_RE = re.compile(r"^(\S+?):(\d+):(\d+): runtime error: (.+)$", re.M)
_ASAN_RE = re.compile(r"ERROR: (AddressSanitizer|LeakSanitizer): ([^\n]+)")
_QUADRO_RE = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+?):(\d+)")
_SMART_ASSERT_RE = re.compile(r"^SMART_ASSERT (\S+?):(\d+): (.*)$", re.M)
_ASSERT_H_RE = re.compile(r"(\S+?):(\d+): (\S+): Assertion [`'](.*)' failed", re.M)
_TSAN_BLOCO_RE = re.compile(r"WARNING: ThreadSanitizer: (.+?) \(pid=\d+\)(.*?)(?=^={10,}|\Z)",
                            re.S | re.M)
_TSAN_QUADRO_RE = re.compile(r"#\d+ (\S+) (\S+?):(\d+)")
_TSAN_LOCAL_RE = re.compile(r"Location is global '([^']+)'")
_TSAN_FATAL_RE = re.compile(r"FATAL: ThreadSanitizer: ([^\n]+)")


def _sem_lib(arq: str) -> bool:
    return "libsanitizer" not in arq and not arq.startswith("/usr/")


def ler_relatos(saida: str) -> list[dict]:
    """Achados do sanitizer (ou da asserção nativa) na saída da execução."""
    achados = []
    for m in _SMART_ASSERT_RE.finditer(saida):
        achados.append(dict(tipo="assercao", arquivo=os.path.basename(m.group(1)),
                            linha=int(m.group(2)), mensagem=m.group(3)))
    for m in _ASSERT_H_RE.finditer(saida):
        achados.append(dict(tipo="assercao", arquivo=os.path.basename(m.group(1)),
                            linha=int(m.group(2)), funcao=m.group(3), mensagem=m.group(4)))
    for m in _UBSAN_RE.finditer(saida):
        achados.append(dict(tipo="ubsan", arquivo=os.path.basename(m.group(1)),
                            linha=int(m.group(2)), mensagem=m.group(4).strip()))
    for m in _ASAN_RE.finditer(saida):
        resto = saida[m.end():]
        q = next((q for q in _QUADRO_RE.finditer(resto) if _sem_lib(q.group(2))), None)
        achados.append(dict(tipo=m.group(1).lower(), mensagem=m.group(2).strip(),
                            funcao=q.group(1) if q else None,
                            arquivo=os.path.basename(q.group(2)) if q else None,
                            linha=int(q.group(3)) if q else None))
    for m in _TSAN_BLOCO_RE.finditer(saida):
        corpo = m.group(2)
        acessos = [dict(funcao=q.group(1), arquivo=os.path.basename(q.group(2)),
                        linha=int(q.group(3)))
                   for q in _TSAN_QUADRO_RE.finditer(corpo) if _sem_lib(q.group(2))]
        loc = _TSAN_LOCAL_RE.search(corpo)
        primeiro = acessos[0] if acessos else {}
        achados.append(dict(tipo="tsan", mensagem=m.group(1).strip(),
                            variavel=loc.group(1) if loc else None, acessos=acessos,
                            funcao=primeiro.get("funcao"), arquivo=primeiro.get("arquivo"),
                            linha=primeiro.get("linha")))
    return achados


def _funcao_da_violacao(violation: dict | None) -> str | None:
    pilha = (violation or {}).get("pilha") or []
    return pilha[0].get("funcao") if pilha else None


_NAO_VARIAVEL = {"signed", "unsigned", "int", "char", "short", "long", "_Bool", "bool", "float",
                 "double", "void", "const", "volatile", "struct", "union", "sizeof", "return",
                 "overflow", "RACE_CHECK", "SAME_OBJECT", "VALID_OBJECT", "INVALID_POINTER"}


def variaveis_da_condicao(violation: dict | None) -> set[str]:
    """Identificadores da condição violada. Numa asserção sobre estado compartilhado (grbl:
    sys_rt_exec_state & (1 << 3)), a corrida que o TSan acusa nessa variável é a causa da
    falha, mesmo quando a intercalação exata não acontece na execução real."""
    cond = str((violation or {}).get("condition") or "")
    return {x for x in re.findall(r"[A-Za-z_]\w*", cond) if x not in _NAO_VARIAVEL}


def usa_threads(files) -> bool:
    return any("pthread_create" in (_ler(f, 50_000_000) or "") for f in files)


def comparar(achados: list[dict], violation: dict | None, variavel: str | None,
             variaveis_cond: set[str] | None = None) -> str:
    """RT7/D4: REPRODUZIDO se algum relato bate com a linha, a função ou a variável do
    contraexemplo; REPRODUZIDO_OUTRO_PONTO se o sanitizer acusou outra coisa."""
    if not achados:
        return "NAO_REPRODUZIDO"
    v = violation or {}
    arq, lin, func = v.get("file"), v.get("line"), _funcao_da_violacao(v)
    for a in achados:
        if variavel and a.get("variavel") == variavel:
            return "REPRODUZIDO"
        if variaveis_cond and a.get("tipo") == "tsan" and a.get("variavel") in variaveis_cond:
            return "REPRODUZIDO"
        pontos = [a] + list(a.get("acessos") or [])
        for p in pontos:
            if arq and lin and p.get("arquivo") == os.path.basename(arq) and p.get("linha") == lin:
                return "REPRODUZIDO"
            if func and p.get("funcao") == func:
                return "REPRODUZIDO"
    return "REPRODUZIDO_OUTRO_PONTO"


# --------------------------------------------------------------------------- execução

def _rodar(cmd, cwd, timeout, env=None):
    t = time.perf_counter()
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env=env, errors="replace")
        rc, out = p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as e:
        rc = -2
        out = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes)
               else (e.stdout or "")) + f"\nTIMEOUT: passou de {timeout}s"
    return rc, out, round(time.perf_counter() - t, 3)


_SETARCH_OK: bool | None = None


def setarch_disponivel() -> bool:
    """O ThreadSanitizer do gcc 13 não sobe com ASLR de 32 bits (kernel novo) sem
    `setarch -R`, e o seccomp padrão do Docker bloqueia essa chamada. O subir.sh passa o
    perfil docker/seccomp-smartcps.json, que libera só ADDR_NO_RANDOMIZE."""
    global _SETARCH_OK
    if _SETARCH_OK is None:
        exe = shutil.which("setarch")
        if not exe:
            _SETARCH_OK = False
        else:
            try:
                p = subprocess.run([exe, os.uname().machine, "-R", "true"],
                                   capture_output=True, timeout=10)
                _SETARCH_OK = p.returncode == 0
            except Exception:  # noqa: BLE001
                _SETARCH_OK = False
    return _SETARCH_OK


def _rel(p, base):
    try:
        return os.path.relpath(p, base)
    except ValueError:
        return p


def _ler(path, limite=20000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limite)
    except OSError:
        return None


def gerar(alvo_files, workdir, *, bug, cwe_id, violation, include_dirs=None,
          gerar_caso_de_teste=None, n_execucoes_tsan=5, timeout_execucao=30,
          raw_cex=None, function=None) -> dict:
    """Monta e executa o reprodutor de UM alvo com BUG. Nunca levanta exceção.

    `gerar_caso_de_teste(dir_saida) -> str` roda o ESBMC com as opções da run mais
    --generate-ctest-testcase e devolve a saída (o orquestrador fornece, para que as opções
    sejam exatamente as da verificação).
    """
    t0 = time.perf_counter()
    files = list(alvo_files) if isinstance(alvo_files, (list, tuple)) else [alvo_files]
    os.makedirs(workdir, exist_ok=True)
    san = sanitizer_para(bug, cwe_id, violation)
    nativo = pasta_nativa(files[0])
    # Programa com threads: a falha (mesmo de asserção) costuma depender da intercalação, que o
    # caso de teste não fixa. O TSan acusa a corrida que causa a falha sem precisar dela.
    if san != "tsan" and usa_threads(files + ([os.path.join(r, f) for r, _, fs in os.walk(nativo)
                                                for f in fs if f.endswith(".c")] if nativo else [])):
        san = "tsan"
    variavel = variavel_da_corrida(violation) if san == "tsan" else None
    variaveis_cond = variaveis_da_condicao(violation) if san == "tsan" else set()
    res = dict(modo="driver nativo" if nativo else "caso de teste", sanitizer=san,
               veredito=None, motivo=None, variavel=variavel, comandos=[], achados=[],
               execucoes=0, reproduziu_em=0, saida="", caso_de_teste=None,
               tempos=dict(caso_de_teste_s=None, compilacao_s=None, execucao_s=None, total_s=None),
               pasta=workdir, arquivos=[], tentativas=[], esbmc_gerou_caso=None,
               origem_reproducao=None, pasta_nativa=nativo)

    def fim(veredito, motivo=None):
        res["veredito"], res["motivo"] = veredito, motivo
        res["tempos"]["total_s"] = round(time.perf_counter() - t0, 3)
        res["arquivos"] = sorted(_rel(os.path.join(r, f), workdir)
                                 for r, _, fs in os.walk(workdir) for f in fs)
        return res

    try:
        gcc = _require("gcc")
    except Exception as e:  # noqa: BLE001
        return fim("INCONCLUSIVO", f"gcc ausente: {e}")

    base = [gcc, "-g", "-O0", "-w", "-pthread", *flags_sanitizer(san)]
    incs = []
    for d in (include_dirs or []):
        incs += ["-I", d]
    exes: list[str] = []          # um executável por caso de teste (ou o driver nativo)
    origens: dict[str, str] = {}

    if nativo:
        exe = os.path.join(workdir, "reprodutor")
        fontes = sorted(os.path.join(r, f) for r, _, fs in os.walk(nativo)
                        for f in fs if f.endswith(".c"))
        dirs_h = sorted({r for r, _, fs in os.walk(nativo) if any(f.endswith(".h") for f in fs)}
                        | {nativo})
        for d in dirs_h:
            incs += ["-I", d]
        if not fontes:
            return fim("FALHA_COMPILACAO", f"pasta nativa sem .c: {nativo}")
        cmd = base + incs + fontes + ["-o", exe]
        res["comandos"].append(" ".join(cmd))
        rc, out, dt = _rodar(cmd, workdir, 300)
        res["tempos"]["compilacao_s"] = dt
        if rc != 0:
            res["saida"] = out[-6000:]
            return fim("FALHA_COMPILACAO", "o driver nativo não compilou")
        exes.append(exe)
        origens[exe] = "driver nativo"
    else:
        ct_dir = os.path.join(workdir, "caso_de_teste")
        if gerar_caso_de_teste is None:
            return fim("SEM_CASO_DE_TESTE", "sem gerador de caso de teste")
        t = time.perf_counter()
        try:
            saida_esbmc = gerar_caso_de_teste(ct_dir) or ""
        except Exception as e:  # noqa: BLE001
            saida_esbmc = f"falha ao rodar o ESBMC: {e}"
        res["tempos"]["caso_de_teste_s"] = round(time.perf_counter() - t, 3)
        res["comandos"].append("esbmc <opções da run> --generate-ctest-testcase "
                               f"--ctest-output-dir {_rel(ct_dir, workdir)}")
        # sem --multi-property: test_case.c; com ele, um test_case_N.c por propriedade violada
        casos = sorted((f for f in (os.listdir(ct_dir) if os.path.isdir(ct_dir) else [])
                        if re.fullmatch(r"test_case(_\d+)?\.c", f)),
                       key=lambda f: int(re.sub(r"\D", "", f) or 0))[:MAX_CASOS]
        res["esbmc_gerou_caso"] = bool(casos)
        res["casos_de_teste"] = len(casos)
        motivo_sem = None
        if not casos:
            motivo_sem = "o ESBMC não gerou o caso de teste"
            if "Unimplemented" in saida_esbmc or "despejou" in saida_esbmc or "core dumped" in saida_esbmc:
                motivo_sem += " (abortou ao montar o contraexemplo)"
            res["saida_esbmc"] = saida_esbmc[-4000:]
        else:
            res["caso_de_teste"] = _ler(os.path.join(ct_dir, casos[0]), 8000)
        # 2ª fonte: valores do contraexemplo da verificação, na ordem das chamadas nondet_*
        cx_codigo, cx_n = caso_pelo_contraexemplo(raw_cex, files)
        if not casos and not cx_n and _CHAMADA_NONDET_RE.search(
                "".join(_ler(f, 50_000_000) or "" for f in files)):
            res["saida"] = saida_esbmc[-6000:]
            return fim("SEM_CASO_DE_TESTE", motivo_sem)
        cx_path = os.path.join(workdir, "test_case_contraexemplo.c")
        with open(cx_path, "w", encoding="utf-8") as f:
            f.write(cx_codigo)
        res["valores_contraexemplo"] = cx_n
        if not casos:
            res["caso_de_teste"] = cx_codigo
        cab = os.path.join(workdir, "smart_nativo.h")
        pad = os.path.join(workdir, "smart_nondet_padrao.c")
        with open(cab, "w", encoding="utf-8") as f:
            f.write(cabecalho_nativo())
        with open(pad, "w", encoding="utf-8") as f:
            f.write(nondet_padrao())
        t = time.perf_counter()

        def _obj(src):
            # test_case*.c e as definições padrão compilam SEM o cabeçalho nativo: o caso de
            # teste define __VERIFIER_assume como função e a macro quebraria a definição.
            o = os.path.join(workdir, os.path.splitext(os.path.basename(src))[0] + ".o")
            cmd = base + ["-c", src, "-o", o]
            res["comandos"].append(" ".join(cmd))
            rc, out, _ = _rodar(cmd, workdir, 120)
            return (o if rc == 0 else None), out

        # --function: o ESBMC entra pela função escolhida; fora dele é preciso um main que a
        # chame. O main do harness (se houver) é renomeado para não colidir.
        extra_harness: list[str] = []
        if function and function != "main":
            ent = os.path.join(workdir, "smart_entrada.c")
            with open(ent, "w", encoding="utf-8") as f:
                f.write("/* smart_entrada.c: gerado pelo SMART CPS (reprodutor, --function). */\n"
                        f"extern void {function}();\nint main(void) {{ {function}(); return 0; }}\n")
            ent_o, out = _obj(ent)
            if not ent_o:
                res["saida"] = out[-6000:]
                return fim("FALHA_COMPILACAO", "smart_entrada.c não compilou")
            objs_extra = [ent_o]
            extra_harness = ["-Dmain=__smart_main_do_harness"]
        else:
            objs_extra = []
        pad_o, out = _obj(pad)
        if not pad_o:
            res["saida"] = out[-6000:]
            return fim("FALHA_COMPILACAO", "smart_nondet_padrao.c não compilou")
        ultimo_erro = ""
        fontes_caso = [(os.path.join(ct_dir, c), "ctest do ESBMC") for c in casos]
        fontes_caso.append((cx_path, "valores do contraexemplo (SMART)"))
        for caminho, origem in fontes_caso:
            caso = os.path.basename(caminho)
            tc_o, out = _obj(caminho)
            if not tc_o:
                ultimo_erro = f"{caso} não compilou\n{out}"
                continue
            num = re.sub(r"\D", "", caso) or ("cx" if caminho == cx_path else "")
            exe = os.path.join(workdir, "reprodutor" + (f"_{num}" if num else ""))
            cmd = (base + incs + extra_harness + ["-include", cab] + files
                   + [tc_o, pad_o] + objs_extra + ["-o", exe])
            res["comandos"].append(" ".join(cmd))
            rc, out, _ = _rodar(cmd, workdir, 300)
            if rc != 0:
                ultimo_erro = f"o harness não compilou fora do ESBMC\n{out}"
                continue
            exes.append(exe)
            origens[exe] = origem
        res["tempos"]["compilacao_s"] = round(time.perf_counter() - t, 3)
        if not exes:
            res["saida"] = ultimo_erro[-6000:]
            return fim("FALHA_COMPILACAO", ultimo_erro.splitlines()[0] if ultimo_erro else None)

    # --- execução (RT6) ---
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=%d:abort_on_error=0" % (1 if cwe_id == "CWE-401" else 0)
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"
    env["TSAN_OPTIONS"] = "halt_on_error=0"
    prefixo = []
    if san == "tsan" and setarch_disponivel():
        prefixo = [shutil.which("setarch"), os.uname().machine, "-R"]
    n = max(1, int(n_execucoes_tsan)) if san == "tsan" else 1
    saidas, vereditos, t_exec = [], [], 0.0
    inviavel = fatal = timeout = False
    for exe in exes:
        ini = len(vereditos)
        cmd = prefixo + [exe]
        res["comandos"].append(" ".join(cmd) + (f"   ({n} execuções)" if n > 1 else ""))
        for i in range(n):
            rc, out, dt = _rodar(cmd, workdir, timeout_execucao, env=env)
            t_exec += dt
            achados = ler_relatos(out)
            v = comparar(achados, violation, variavel, variaveis_cond)
            vereditos.append(v)
            if achados and (v == "REPRODUZIDO" or not res["achados"]):
                res["achados"] = achados
            if rc == -2:
                timeout = True
            if rc == SAIDA_INVIAVEL and "SMART_INVIAVEL" in out:
                inviavel = True
            fm = _TSAN_FATAL_RE.search(out)
            if fm:
                fatal = fm.group(1)
            saidas.append(f"--- {os.path.basename(exe)}, execução {i + 1}: código {rc}, {dt} s\n{out}")
        mine = vereditos[ini:]
        melhor = next((v for v in ("REPRODUZIDO", "REPRODUZIDO_OUTRO_PONTO") if v in mine),
                      mine[0] if mine else None)
        res["tentativas"].append(dict(origem=origens.get(exe), executavel=os.path.basename(exe),
                                      veredito=melhor,
                                      reproduziu_em=sum(1 for v in mine if v == "REPRODUZIDO"),
                                      execucoes=len(mine)))
        if "REPRODUZIDO" in mine:
            res["origem_reproducao"] = origens.get(exe)
            break
    res["execucoes"] = len(vereditos)
    res["reproduziu_em"] = sum(1 for v in vereditos if v == "REPRODUZIDO")
    res["tempos"]["execucao_s"] = round(t_exec, 3)
    texto = "\n".join(saidas)
    res["saida"] = texto if len(texto) <= 12000 else texto[:6000] + "\n[...]\n" + texto[-6000:]
    with open(os.path.join(workdir, "saida_execucao.txt"), "w", encoding="utf-8") as f:
        f.write(texto)
    with open(os.path.join(workdir, "comandos.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(res["comandos"]) + "\n")

    if "REPRODUZIDO" in vereditos:
        return fim("REPRODUZIDO")
    if "REPRODUZIDO_OUTRO_PONTO" in vereditos:
        return fim("REPRODUZIDO_OUTRO_PONTO", "o sanitizer acusou outro ponto do programa")
    if fatal:
        return fim("INCONCLUSIVO", f"ThreadSanitizer não subiu: {fatal} "
                                   "(container sem o perfil seccomp do subir.sh?)")
    if timeout:
        return fim("INCONCLUSIVO", f"a execução passou de {timeout_execucao} s")
    if inviavel:
        return fim("NAO_REPRODUZIDO", "o caso de teste caiu num __ESBMC_assume falso "
                                      "(caminho inviável na execução real)")
    return fim("NAO_REPRODUZIDO", "a execução terminou sem relato do sanitizer")
