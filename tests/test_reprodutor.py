"""Reprodutor (incremento 4): caso de teste do ESBMC + executável com sanitizer."""

import os
import shutil
import textwrap

import pytest

from smart_jbmc.core import reprodutor as rp
from smart_jbmc.core import scanner

TEM_GCC = shutil.which("gcc") is not None
TEM_ESBMC = shutil.which("esbmc") is not None or os.path.isfile("/usr/local/bin/esbmc")

UBSAN = "prog.c:12:15: runtime error: signed integer overflow: 2147483647 * 3 cannot be represented in type 'int'\n"
TSAN = textwrap.dedent("""\
    ==================
    WARNING: ThreadSanitizer: data race (pid=13)
      Write of size 8 at 0x555 by thread T1:
        #0 vPortEndScheduler /src/port.c:340 (a.out+0x1)
        #1 vTaskEndScheduler /src/tasks.c:3884 (a.out+0x2)

      Previous read of size 8 at 0x555 by main thread:
        #0 xPortStartScheduler /src/port.c:295 (a.out+0x3)

      Location is global 'xSchedulerEnd' of size 8 at 0x555 (a.out+0x4)

    SUMMARY: ThreadSanitizer: data race /src/port.c:340 in vPortEndScheduler
    ==================
    """)
ASAN = textwrap.dedent("""\
    ==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602
        #0 0x4011 in ler /tmp/a.c:7
        #1 0x4012 in main /tmp/a.c:12
    """)


def test_le_ubsan_tsan_asan_e_assercao():
    a = rp.ler_relatos(UBSAN)
    assert a[0]["tipo"] == "ubsan" and a[0]["arquivo"] == "prog.c" and a[0]["linha"] == 12
    t = rp.ler_relatos(TSAN)[0]
    assert t["tipo"] == "tsan" and t["variavel"] == "xSchedulerEnd"
    assert [x["linha"] for x in t["acessos"]] == [340, 3884, 295]
    s = rp.ler_relatos(ASAN)[0]
    assert s["tipo"] == "addresssanitizer" and s["funcao"] == "ler" and s["linha"] == 7
    m = rp.ler_relatos("SMART_ASSERT h.c:79: configASSERT\n")[0]
    assert m["tipo"] == "assercao" and m["linha"] == 79
    n = rp.ler_relatos("prog: h.c:9: main: Assertion `x > 0' failed.\n")[0]
    assert n["linha"] == 9 and n["funcao"] == "main"


def test_variavel_da_corrida():
    assert rp.variavel_da_corrida(
        {"description": "R/W data race on c:endscheduler.c@xSchedulerEnd"}) == "xSchedulerEnd"
    assert rp.variavel_da_corrida(
        {"description": "x", "condition": "!(RACE_CHECK(&flag))"}) == "flag"
    assert rp.variavel_da_corrida({"description": "arithmetic overflow on add"}) is None


def test_comparar_linha_variavel_e_outro_ponto():
    viol = {"file": "/up/prog.c", "line": 12}
    assert rp.comparar(rp.ler_relatos(UBSAN), viol, None) == "REPRODUZIDO"
    assert rp.comparar(rp.ler_relatos(UBSAN), {"file": "prog.c", "line": 3}, None) == "REPRODUZIDO_OUTRO_PONTO"
    assert rp.comparar(rp.ler_relatos(TSAN), {"file": "harness.c", "line": 136}, "xSchedulerEnd") == "REPRODUZIDO"
    assert rp.comparar([], viol, None) == "NAO_REPRODUZIDO"


def test_sanitizer_pela_propriedade():
    assert rp.sanitizer_para("Data Race", "CWE-362", None) == "tsan"
    assert rp.sanitizer_para(None, None, {"description": "R/W data race on x"}) == "tsan"
    assert rp.sanitizer_para("Arithmetic Overflow", "CWE-190", None) == "asan+ubsan"
    assert "-fsanitize=thread" in rp.flags_sanitizer("tsan")
    assert "-fno-sanitize-recover=all" in rp.flags_sanitizer("asan+ubsan")


def test_cabecalho_e_nondet_padrao():
    c = rp.cabecalho_nativo()
    assert "#define nondet_int __VERIFIER_nondet_int" in c
    assert "_exit(77)" in c and "__ESBMC_atomic_begin()" in c
    assert "__attribute__((weak)) int __VERIFIER_nondet_int(void)" in rp.nondet_padrao()


def test_pasta_nativa_e_scanner_ignora(tmp_path):
    (tmp_path / "alvo.c").write_text("int main(void){return 0;}\n")
    nat = tmp_path / "alvo_nativo"
    nat.mkdir()
    (nat / "main.c").write_text("int main(void){return 0;}\n")
    assert rp.pasta_nativa(str(tmp_path / "alvo.c")) == str(nat)
    _, _, c = scanner.scan(str(tmp_path))
    assert c == [str(tmp_path / "alvo.c")]


PROG_ESTOURO = textwrap.dedent("""\
    int nondet_int(void);
    int main(void) {
      int a = nondet_int();
      __ESBMC_assume(a > 1000);
      int b = a * 3000000;
      return b != 0;
    }
    """)
CASO = textwrap.dedent("""\
    void __VERIFIER_assume(int cond) { (void)cond; }
    int __VERIFIER_nondet_int(void) {
      static int i = 0;
      static int const v[] = { 2147483647 };
      return v[i++];
    }
    """)


@pytest.mark.skipif(not TEM_GCC, reason="gcc ausente")
def test_gerar_caso_de_teste_reproduz_estouro(tmp_path):
    prog = tmp_path / "prog.c"
    prog.write_text(PROG_ESTOURO)

    def caso(d):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "test_case.c"), "w") as f:
            f.write(CASO)
        return "VERIFICATION FAILED"

    r = rp.gerar(str(prog), str(tmp_path / "rep"), bug="Arithmetic Overflow", cwe_id="CWE-190",
                 violation={"file": "prog.c", "line": 5}, gerar_caso_de_teste=caso)
    assert r["veredito"] == "REPRODUZIDO", r
    assert r["modo"] == "caso de teste" and r["sanitizer"] == "asan+ubsan"
    assert r["tempos"]["compilacao_s"] is not None and "saida_execucao.txt" in r["arquivos"]


@pytest.mark.skipif(not TEM_GCC, reason="gcc ausente")
def test_sem_caso_de_teste_e_assume_falso(tmp_path):
    prog = tmp_path / "prog.c"
    prog.write_text(PROG_ESTOURO)
    r = rp.gerar(str(prog), str(tmp_path / "a"), bug="Arithmetic Overflow", cwe_id="CWE-190",
                 violation={"file": "prog.c", "line": 5},
                 gerar_caso_de_teste=lambda d: "ERROR: Unimplemented type'd expression")
    assert r["veredito"] == "SEM_CASO_DE_TESTE" and "abortou" in r["motivo"]

    def caso_zero(d):  # sem valor: nondet padrão devolve 0 e o assume corta o caminho
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "test_case.c"), "w").write("void __VERIFIER_assume(int c){(void)c;}\n")
        return ""
    r = rp.gerar(str(prog), str(tmp_path / "b"), bug="Arithmetic Overflow", cwe_id="CWE-190",
                 violation={"file": "prog.c", "line": 5}, gerar_caso_de_teste=caso_zero)
    assert r["veredito"] == "NAO_REPRODUZIDO" and "inviável" in r["motivo"]


@pytest.mark.skipif(not TEM_GCC, reason="gcc ausente")
def test_driver_nativo_com_tsan(tmp_path):
    (tmp_path / "harness.c").write_text("int main(void){return 0;}\n")
    nat = tmp_path / "harness_nativo"
    nat.mkdir()
    (nat / "main.c").write_text(textwrap.dedent("""\
        #include <pthread.h>
        #include <unistd.h>
        int flag;
        void *t(void *p) { usleep(1000); flag = 1; return 0; }
        int main(void) { pthread_t th; pthread_create(&th, 0, t, 0);
          while (flag != 1) {} pthread_join(th, 0); return 0; }
        """))
    r = rp.gerar(str(tmp_path / "harness.c"), str(tmp_path / "rep"), bug="Data Race",
                 cwe_id="CWE-362",
                 violation={"file": "harness.c", "line": 1,
                            "description": "R/W data race on c:harness.c@flag"},
                 n_execucoes_tsan=2)
    assert r["modo"] == "driver nativo" and r["sanitizer"] == "tsan"
    if not rp.setarch_disponivel():
        assert r["veredito"] in ("REPRODUZIDO", "INCONCLUSIVO")
    else:
        assert r["veredito"] == "REPRODUZIDO" and r["reproduziu_em"] >= 1, r


@pytest.mark.skipif(not (TEM_GCC and TEM_ESBMC), reason="gcc ou esbmc ausente")
def test_run_com_reprodutor_pelo_orquestrador(tmp_path):
    from smart_jbmc.core.orchestrator import run_verification
    (tmp_path / "prog.c").write_text(PROG_ESTOURO)
    rr = run_verification(str(tmp_path), propriedade="estouro", jobs=1, timeout=60,
                          build_root=str(tmp_path / "build"), gerar_reprodutor=True)
    alvo = rr.targets[0]
    assert alvo.status == "BUG"
    assert alvo.reprodutor["veredito"] == "REPRODUZIDO", alvo.reprodutor
    assert alvo.reprodutor["caso_de_teste"] and rr.summary["reprodutor"]["REPRODUZIDO"] == 1


TRACE = textwrap.dedent("""\
    State 1 file /up/prog.c line 2 column 3 function main thread 0
    ----------------------------------------------------
      S = { .A0 = 0 }

    State 2 file /up/prog.c line 3 column 3 function main thread 0
    ----------------------------------------------------
      a = 2147483647 (01111111 11111111 11111111 11111111)

    """)


def test_caso_pelo_contraexemplo_ignora_nao_inicializadas(tmp_path):
    """Achado de 13/11: o ctest do ESBMC 8.6 mistura variáveis não inicializadas na sequência."""
    prog = tmp_path / "prog.c"
    prog.write_text(PROG_ESTOURO)
    codigo, n = rp.caso_pelo_contraexemplo(TRACE, [str(prog)])
    assert n == 1 and "{ 2147483647 }" in codigo and "__VERIFIER_nondet_int" in codigo


@pytest.mark.skipif(not TEM_GCC, reason="gcc ausente")
def test_contraexemplo_reproduz_quando_ctest_falha(tmp_path):
    prog = tmp_path / "prog.c"
    prog.write_text(PROG_ESTOURO)

    def ctest_deslocado(d):  # como o ESBMC 8.6 no CMSIS: zeros antes do valor da entrada
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "test_case_1.c"), "w").write(
            "void __VERIFIER_assume(int c){(void)c;}\n"
            "int __VERIFIER_nondet_int(void){static int i=0; static int const v[]={0,0,0,2147483647};"
            " return v[i++];}\n")
        return ""
    r = rp.gerar(str(prog), str(tmp_path / "r"), bug="Arithmetic Overflow", cwe_id="CWE-190",
                 violation={"file": "prog.c", "line": 5}, gerar_caso_de_teste=ctest_deslocado,
                 raw_cex=TRACE)
    assert r["veredito"] == "REPRODUZIDO", r
    assert [t["veredito"] for t in r["tentativas"]] == ["NAO_REPRODUZIDO", "REPRODUZIDO"]
    assert r["origem_reproducao"] == "valores do contraexemplo (SMART)"


@pytest.mark.skipif(not TEM_GCC, reason="gcc ausente")
def test_function_gera_main_de_entrada(tmp_path):
    prog = tmp_path / "ut.c"
    prog.write_text("int nondet_int(void);\nvoid unit_test(void) { int a = nondet_int();\n"
                    "  __ESBMC_assert(a != 7, \"a nao pode ser 7\"); }\n")

    def caso(d):
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "test_case.c"), "w").write(
            "void __VERIFIER_assume(int c){(void)c;}\n"
            "int __VERIFIER_nondet_int(void){ return 7; }\n")
        return ""
    r = rp.gerar(str(prog), str(tmp_path / "r"), bug="Assertion Failure", cwe_id="CWE-617",
                 violation={"file": "ut.c", "line": 3}, gerar_caso_de_teste=caso,
                 function="unit_test")
    assert r["veredito"] == "REPRODUZIDO", r


def test_corrida_na_variavel_da_assercao_conta():
    viol = {"file": "grbl.c", "line": 38,
            "condition": "(_Bool)((signed int)sys_rt_exec_state & 1 << 3)"}
    assert rp.variaveis_da_condicao(viol) == {"sys_rt_exec_state"}
    tsan = TSAN.replace("xSchedulerEnd", "sys_rt_exec_state")
    assert rp.comparar(rp.ler_relatos(tsan), viol, None, {"sys_rt_exec_state"}) == "REPRODUZIDO"
    assert rp.comparar(rp.ler_relatos(TSAN), viol, None, {"sys_rt_exec_state"}) == "REPRODUZIDO_OUTRO_PONTO"


@pytest.mark.skipif(not TEM_GCC, reason="gcc ausente")
def test_assercao_com_threads_usa_tsan(tmp_path):
    prog = tmp_path / "rmw.c"
    prog.write_text(textwrap.dedent("""\
        #include <pthread.h>
        #include <unistd.h>
        volatile int estado;
        void *isr(void *p) { usleep(500); estado |= 2; return 0; }
        int main(void) { pthread_t t; pthread_create(&t, 0, isr, 0);
          estado |= 8; usleep(2000); pthread_join(t, 0);
          __ESBMC_assert(estado & 8, "pedido nao pode se perder"); return 0; }
        """))

    def caso(d):
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "test_case.c"), "w").write("void __VERIFIER_assume(int c){(void)c;}\n")
        return ""
    r = rp.gerar(str(prog), str(tmp_path / "r"), bug="Assertion Failure", cwe_id="CWE-617",
                 violation={"file": "rmw.c", "line": 7, "condition": "(_Bool)(estado & 8)"},
                 gerar_caso_de_teste=caso, n_execucoes_tsan=2)
    assert r["sanitizer"] == "tsan"
    if rp.setarch_disponivel():
        assert r["veredito"] == "REPRODUZIDO", r


def test_cabecalho_respeita_definicao_do_programa(tmp_path):
    prog = tmp_path / "ds.c"
    prog.write_text("void __VERIFIER_assume(int expression)\n{ if (!expression) {} }\nint main(void){return 0;}\n")
    defs = rp.nomes_definidos([str(prog)])
    assert defs == {"__VERIFIER_assume"}
    cab = rp.cabecalho_nativo(defs)
    assert "#define __VERIFIER_assume(" not in cab and "#define __ESBMC_assume(" in cab


@pytest.mark.skipif(not TEM_GCC, reason="gcc ausente")
def test_cabecalho_nao_conflita_com_programa_pre_processado(tmp_path):
    """SV-COMP .i: declarações da glibc dentro do arquivo (A2 dava 'conflicting types')."""
    prog = tmp_path / "pp.c"
    prog.write_text("typedef unsigned long pthread_t;\n"
                    "extern int pthread_create(pthread_t *, const void *, void *(*)(void *), void *);\n"
                    "extern int dprintf(int __fd, const char *__restrict __fmt, ...);\n"
                    "extern void abort(void) __attribute__((__noreturn__));\n"
                    "int x;\nint main(void) { __ESBMC_atomic_begin(); x = 1; __ESBMC_atomic_end();\n"
                    "  __ESBMC_assert(x == 2, \"x\"); return 0; }\n")

    def caso(d):
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "test_case.c"), "w").write("void __VERIFIER_assume(int c){(void)c;}\n")
        return ""
    r = rp.gerar(str(prog), str(tmp_path / "r"), bug="Assertion Failure", cwe_id="CWE-617",
                 violation={"file": "pp.c", "line": 7}, gerar_caso_de_teste=caso)
    assert r["veredito"] == "REPRODUZIDO", r
