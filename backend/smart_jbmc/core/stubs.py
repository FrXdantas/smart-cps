"""Stubs de compilação para benchmarks (SV-COMP `Verifier` + `org.cprover.CProver`).

Muitos benchmarks Java (SV-COMP, jbmc-regression) importam APIs externas para
entradas não-determinísticas. Sem elas no classpath, o `javac` falha e a unidade
é descartada. Aqui fornecemos stubs mínimos para o javac compilar; os métodos
`nondet*` delegam a `org.cprover.CProver`, que o **JBMC modela nativamente como
não-determinístico** — então a semântica de verificação fica correta.

Os stubs são compilados UMA vez (cache em disco) e o diretório de classes é
adicionado ao classpath do `javac` e do `jbmc`.
"""

from pathlib import Path

from . import compiler
from .config import PROJECT_ROOT

_DIR = Path(PROJECT_ROOT) / "data" / "stubs"
_SRC = _DIR / "src"
_CLS = _DIR / "classes"
# modelos de biblioteca: só o JBMC os enxerga (ver _MODELS)
_MSRC = _DIR / "models_src"
_MCLS = _DIR / "models"

_CPROVER = """package org.cprover;
public final class CProver {
    public static boolean nondetBoolean() { return false; }
    public static byte nondetByte()       { return 0; }
    public static char nondetChar()       { return 0; }
    public static short nondetShort()     { return 0; }
    public static int nondetInt()         { return 0; }
    public static long nondetLong()       { return 0L; }
    public static float nondetFloat()     { return 0f; }
    public static double nondetDouble()   { return 0d; }
    public static <T> T nondetWithNull()    { return null; }
    public static <T> T nondetWithoutNull() { return null; }
    public static void assume(boolean b)  { }
    public static void assertEquals(Object a, Object b) { }
}
"""

_VERIFIER = """package org.sosy_lab.sv_benchmarks;
import org.cprover.CProver;
public final class Verifier {
    public static void assume(boolean cond) { CProver.assume(cond); }
    public static boolean nondetBoolean() { return CProver.nondetBoolean(); }
    public static byte nondetByte()       { return CProver.nondetByte(); }
    public static char nondetChar()       { return CProver.nondetChar(); }
    public static short nondetShort()     { return CProver.nondetShort(); }
    public static int nondetInt()         { return CProver.nondetInt(); }
    public static long nondetLong()       { return CProver.nondetLong(); }
    public static float nondetFloat()     { return CProver.nondetFloat(); }
    public static double nondetDouble()   { return CProver.nondetDouble(); }
    public static String nondetString()   { return CProver.<String>nondetWithNull(); }
    public static Object nondetObject()   { return CProver.<Object>nondetWithNull(); }
}
"""

_STUBS = {
    "org/cprover/CProver.java": _CPROVER,
    "org/sosy_lab/sv_benchmarks/Verifier.java": _VERIFIER,
}

# ---------------------------------------------------------------------------
# MODELOS de biblioteca — entram só no classpath do JBMC, nunca no do javac.
#
# O JBMC não modela `java.util.Random`: `nextInt(5)` era havocado para um Int
# qualquer, e o contraexemplo chegava a exibir `r = 6`. Consequência prática:
# `arr[new Random().nextInt(arr.size)]` era reportado como Array Out Of Bounds,
# ou seja, o verificador REJEITAVA o reparo correto e só aceitava um guard
# redundante — ensinando quem repara a contornar o oráculo em vez de corrigir.
#
# Ficam separados dos stubs de compilação de propósito: o `javac` continua
# usando o `java.util.Random` real e completo do JDK, então nenhum código de
# usuário deixa de compilar por causa de um método que o modelo não cobre.
# Método ausente aqui = comportamento de hoje (havoc), nunca erro — verificado.
# ---------------------------------------------------------------------------
_RANDOM = """package java.util;
import org.cprover.CProver;

public class Random {
    public Random() {}
    public Random(long seed) {}
    public void setSeed(long seed) {}

    public int nextInt() { return CProver.nondetInt(); }

    public int nextInt(int bound) {
        // Fiel ao contrato: bound<=0 lança, e NÃO vira caminho inalcançável.
        // Um `assume` incondicional aqui esconderia o defeito de bound inválido.
        if (bound <= 0) throw new IllegalArgumentException("bound must be positive");
        int r = CProver.nondetInt();
        CProver.assume(r >= 0 && r < bound);
        return r;
    }

    public int nextInt(int origin, int bound) {
        if (origin >= bound) throw new IllegalArgumentException("bound must be greater than origin");
        int r = CProver.nondetInt();
        CProver.assume(r >= origin && r < bound);
        return r;
    }

    public long nextLong() { return CProver.nondetLong(); }

    public long nextLong(long bound) {
        if (bound <= 0) throw new IllegalArgumentException("bound must be positive");
        long r = CProver.nondetLong();
        CProver.assume(r >= 0 && r < bound);
        return r;
    }

    public boolean nextBoolean() { return CProver.nondetBoolean(); }

    public double nextDouble() {
        double d = CProver.nondetDouble();
        CProver.assume(d >= 0.0d && d < 1.0d);
        return d;
    }

    public float nextFloat() {
        float f = CProver.nondetFloat();
        CProver.assume(f >= 0.0f && f < 1.0f);
        return f;
    }
}
"""

_MODELS = {
    "java/util/Random.java": _RANDOM,
}


def ensure_stubs() -> str | None:
    """Compila os stubs uma vez (idempotente) e devolve o dir de classes.
    Retorna None se o javac não estiver disponível ou a compilação falhar
    (a verificação então segue sem os stubs, como antes)."""
    marker = _CLS / "org" / "cprover" / "CProver.class"
    if marker.is_file():
        return str(_CLS)
    try:
        compiler._require("javac")
    except Exception:  # noqa: BLE001
        return None
    _SRC.mkdir(parents=True, exist_ok=True)
    _CLS.mkdir(parents=True, exist_ok=True)
    srcs = []
    for rel, code in _STUBS.items():
        p = _SRC / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code, encoding="utf-8")
        srcs.append(str(p))
    res = compiler.compile_java(srcs, str(_CLS))
    return str(_CLS) if res.returncode == 0 and marker.is_file() else None


def ensure_models() -> str | None:
    """Compila os MODELOS de biblioteca (idempotente) e devolve o dir de classes.

    Vai **apenas** ao classpath do JBMC — ver o comentário de `_MODELS`. Exige
    `--patch-module java.base`, porque o javac recusa compilar no pacote
    `java.util` ("prohibited package name"). Devolve None em qualquer falha, e
    aí a verificação segue exatamente como antes.
    """
    marker = _MCLS / "java" / "util" / "Random.class"
    if marker.is_file():
        return str(_MCLS)
    stubs_cp = ensure_stubs()          # os modelos chamam org.cprover.CProver
    if not stubs_cp:
        return None
    try:
        compiler._require("javac")
    except Exception:  # noqa: BLE001
        return None
    _MSRC.mkdir(parents=True, exist_ok=True)
    _MCLS.mkdir(parents=True, exist_ok=True)
    srcs = []
    for rel, code in _MODELS.items():
        p = _MSRC / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code, encoding="utf-8")
        srcs.append(str(p))
    res = compiler.compile_java_patched(srcs, str(_MCLS), str(_MSRC),
                                        classpath=stubs_cp)
    return str(_MCLS) if res.returncode == 0 and marker.is_file() else None
