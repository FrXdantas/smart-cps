"""Reparo em projeto MULTI-ARQUIVO — o defeito não está no arquivo do `main`.

Regressão do problema relatado pela cliente em 2026-07-30 sobre o benchmark
QuixBugs: a ferramenta detectava o bug corretamente, mas mandava à LLM o arquivo
do ponto de entrada (`Main.java`, só asserções de teste) em vez do arquivo com o
defeito (`LIS.java`, `BUCKETSORT.java`...). Sem enxergar a classe chamada, o
modelo a reimplementava DENTRO do harness; o oráculo compilava esse arquivo
sozinho, dava FIX_OK, e a ferramenta declarava REPAIRED — enquanto o arquivo
defeituoso continuava intacto e o patch nem se aplicava ao projeto
(`duplicate class`).

Cobre as três correções:
  1. escolha do arquivo a reparar pelo contraexemplo (+ re-verificação da unidade);
  2. guardas que barram reimplementar classe alheia / apagar asserção;
  3. classe de biblioteca (sem `main`) vira NO_ENTRY_POINT, não ERROR.
"""

import shutil
import tempfile
from pathlib import Path

import pytest

from smart_jbmc.core.config import resolve_tool
from smart_jbmc.core.orchestrator import _fault_files, run_verification
from smart_jbmc.core.repair import repair_run
from smart_jbmc.core.repair.loop import _pick_repair_file, _validate_patch
from smart_jbmc.core.verifiers import is_no_entry_point

FIXTURES = Path(__file__).parent / "fixtures"
MULTIFILE = FIXTURES / "java" / "multifile"
needs_jbmc = pytest.mark.skipif(
    resolve_tool("jbmc") is None or resolve_tool("javac") is None,
    reason="jbmc/javac indisponíveis",
)

MAIN = "/proj/Main.java"
LIB = "/proj/Lib.java"


# --- 1. escolha do arquivo a reparar ----------------------------------------

def test_pick_repair_file_prefere_arquivo_do_contraexemplo(tmp_path):
    """Com o trace apontando Lib.java, repara Lib.java — não o Main.java."""
    main = tmp_path / "Main.java"
    lib = tmp_path / "Lib.java"
    main.write_text("public class Main {}")
    lib.write_text("public class Lib {}")
    escolhido = _pick_repair_file(str(main), [str(main), str(lib)],
                                  ["Lib.java", "Main.java"])
    assert escolhido == str(lib)


def test_pick_repair_file_arquivo_unico_mantem_comportamento(tmp_path):
    """Projeto de um arquivo só: repara ele mesmo (comportamento antigo)."""
    only = tmp_path / "Solo.c"
    only.write_text("int main(){return 0;}")
    assert _pick_repair_file(str(only), [str(only)], ["Solo.c"]) == str(only)


def test_pick_repair_file_sem_pista_cai_no_alvo(tmp_path):
    """Trace só cita o entrypoint: repara o entrypoint (não inventa outro)."""
    main = tmp_path / "Main.java"
    lib = tmp_path / "Lib.java"
    main.write_text("public class Main {}")
    lib.write_text("public class Lib {}")
    assert _pick_repair_file(str(main), [str(main), str(lib)], ["Main.java"]) == str(main)


def test_fault_files_ordena_violacao_antes_do_trace():
    steps = [{"file": "Main.java"}, {"file": "Lib.java"}]
    violations = [{"file": "Lib.java"}, {"file": "-"}]
    assert _fault_files(steps, violations) == ["Lib.java", "Main.java"]


# --- 2. guardas contra patch que passa no oráculo sem consertar --------------

HARNESS = (
    "public class Main {\n"
    "    public static void main(String[] a) {\n"
    "        if (Lib.get(new int[3], 3) != 0) throw new AssertionError();\n"
    "    }\n"
    "}\n"
)


def test_guarda_rejeita_reimplementacao_de_classe_vizinha():
    """O modo de falha exato do QuixBugs: inlinear a classe do outro arquivo."""
    patch = "class Lib { static int get(int[] a, int i){ return 0; } }\n" + HARNESS
    motivo = _validate_patch(patch, HARNESS, ".java", sibling_types={"Lib"})
    assert motivo and "Lib" in motivo


def test_guarda_rejeita_remocao_de_assercao():
    patch = HARNESS.replace("if (Lib.get(new int[3], 3) != 0) throw new AssertionError();",
                            "Lib.get(new int[3], 3);")
    motivo = _validate_patch(patch, HARNESS, ".java", sibling_types={"Lib"})
    assert motivo and "asser" in motivo.lower()


def test_guarda_rejeita_remocao_de_classe_original():
    patch = "public class Outra {}\n"
    motivo = _validate_patch(patch, HARNESS, ".java", sibling_types=set())
    assert motivo and "Main" in motivo


def test_guarda_aceita_correcao_minima():
    """Guard pontual dentro do arquivo do defeito: nada a rejeitar."""
    original = "public class Lib {\n    static int get(int[] a, int i){ return a[i]; }\n}\n"
    patch = ("public class Lib {\n"
             "    static int get(int[] a, int i){ if (i < 0 || i >= a.length) return 0;"
             " return a[i]; }\n}\n")
    assert _validate_patch(patch, original, ".java", sibling_types={"Main"}) is None


def test_guarda_nao_exige_tipos_em_c():
    """Em C não há declaração de classe: só a regra das asserções vale."""
    original = "int main(void){ int x = 1; return x; }\n"
    patch = "int main(void){ int x = 2; return x; }\n"
    assert _validate_patch(patch, original, ".c", sibling_types=set()) is None


# --- 3. classe sem `main` ---------------------------------------------------

def test_is_no_entry_point_reconhece_saida_do_jbmc():
    assert is_no_entry_point("CBMC error: no entry point found")
    assert is_no_entry_point("main symbol resolution failed")
    assert not is_no_entry_point("VERIFICATION SUCCESSFUL")


@needs_jbmc
def test_classe_de_biblioteca_vira_no_entry_point_e_nao_error(tmp_path):
    """`Lib` não tem `main`: alvo inaplicável, fora do denominador de ERROR."""
    proj = tmp_path / "proj"
    shutil.copytree(MULTIFILE, proj)
    res = run_verification(str(proj), unwind=6, timeout=90, jobs=2,
                           build_root=str(tmp_path / "build"))
    por_alvo = {t.target: t.status for t in res.targets}
    assert por_alvo.get("Lib") == "NO_ENTRY_POINT", por_alvo
    assert por_alvo.get("Main") == "BUG", por_alvo
    assert res.summary["NO_ENTRY_POINT"] == 1
    assert res.summary["ERROR"] == 0


# --- ponta a ponta: o caso da cliente ---------------------------------------

@needs_jbmc
def test_repara_o_arquivo_do_defeito_e_nao_o_harness(tmp_path):
    """O bug é reportado em Main (tem o `main`), mas quem é reparado é Lib.java —
    e o oráculo aprova recompilando a UNIDADE inteira, não o arquivo isolado."""
    proj = tmp_path / "proj"
    shutil.copytree(MULTIFILE, proj)
    run = run_verification(str(proj), unwind=6, timeout=90, jobs=2,
                           build_root=str(tmp_path / "build"))
    bugs = [t for t in run.targets if t.status == "BUG"]
    assert bugs, [(t.target, t.status) for t in run.targets]
    alvo = bugs[0]
    assert Path(alvo.source).name == "Main.java"          # reportado no entrypoint
    assert "Lib.java" in alvo.fault_files                 # mas o trace aponta Lib

    correcao = ("public class Lib {\n"
                "    public static int get(int[] arr, int i) {\n"
                "        if (i < 0 || i >= arr.length) return 0;"
                " // <--- corrigido aqui: guard de OOB (CWE-125 / ARR30-C)\n"
                "        return arr[i];\n    }\n}\n")

    def patch_fn(**kw):
        # o arquivo entregue à LLM tem de ser o do defeito, com o harness só como contexto
        assert kw["file_name"] == "Lib.java", kw["file_name"]
        assert "Main.java" in (kw.get("context_files") or {})
        assert "class Lib" in kw["code"]
        return {"patch": correcao, "usage": None, "model": "fake", "ms": 1}

    from smart_jbmc.core.repair.loop import repair_target
    rr = repair_target(
        source_path=alvo.source, original_bug=alvo.bug,
        counterexample=alvo.explanation or "", unwind=6, timeout=90,
        max_iters=2, patch_fn=patch_fn,
        unit_sources=alvo.unit_sources, fault_files=alvo.fault_files,
        entry_class=alvo.target,
    )
    assert rr.status == "REPAIRED", [a["verdict"] for a in rr.attempts]
    assert Path(rr.repaired_file).name == "Lib.java"
    # o _FIXED é entregue ao lado do arquivo do defeito, não do harness
    assert Path(rr.origin_fixed_path).name == "Lib_FIXED.java"


@needs_jbmc
def test_patch_que_reimplementa_no_harness_e_recusado(tmp_path):
    """Rede de segurança: se o trace NÃO apontar outro arquivo, o reparo cai no
    harness — e aí a resposta antiga (inlinear `Lib` dentro de `Main`) é barrada
    ANTES do verificador, que a aprovaria. É este FIX_OK falso que produzia os
    'REPAIRED' que não consertavam nada."""
    proj = tmp_path / "proj"
    shutil.copytree(MULTIFILE, proj)
    run = run_verification(str(proj), unwind=6, timeout=90, jobs=2,
                           build_root=str(tmp_path / "build"))
    alvo = next(t for t in run.targets if t.status == "BUG")

    def patch_fn(**kw):
        # simula o modelo devolvendo o harness com a classe vizinha reimplementada
        assert kw["file_name"] == "Main.java"
        return {"patch": "class Lib { static int get(int[] a, int i){ return 0; } }\n"
                         + kw["code"],
                "usage": None, "model": "fake", "ms": 1}

    with tempfile.TemporaryDirectory() as work:
        res = repair_run([{
            "status": "BUG", "source": alvo.source, "bug": alvo.bug,
            "target": alvo.target, "explanation": alvo.explanation,
            "unit_sources": alvo.unit_sources,
            "fault_files": ["Main.java"],   # trace sem pista fora do entrypoint
        }], unwind=6, timeout=90, max_iters=2, work_dir=work,
            patch_fn=patch_fn)

    alvo_res = res["targets"][0]
    assert alvo_res["status"] == "NOT_REPAIRED"
    assert {a["verdict"] for a in alvo_res["attempts"]} == {"INVALID_PATCH"}
