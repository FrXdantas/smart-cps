"""SARIF 2.1.0: estrutura, config exata, arquivos testados e tempos.

Constrói o documento a partir de um registro sintético de run (sem depender de
ESBMC/JBMC instalados), checando que tudo que o usuário precisa p/ reprodutibilidade
está no lugar certo do schema.
"""

from fastapi.testclient import TestClient

from smart_jbmc.api.app import app
from smart_jbmc.core.sarif import build_sarif

client = TestClient(app)


def _fake_run():
    return {
        "id": "abc123",
        "status": "done",
        "created_at": "2026-05-31T21:00:00+00:00",
        "finished_at": "2026-05-31T21:00:42+00:00",
        "config": {
            "folder": "/tmp/proj", "unwind": 7, "timeout": 80, "jobs": 8,
            "solver": "boolector", "solver_requested": "mathsat",
            "concurrency": False, "unwinding_assertions": True,
        },
        "result": {
            "summary": {"total": 3, "BUG": 1, "SAFE": 1, "UNKNOWN": 1},
            "elapsed_s": 41.2,
            "warnings": ["solver 'mathsat' indisponível; usando 'boolector'."],
            "targets": [
                {"target": "a.c", "source": "/tmp/proj/a.c", "kind": "esbmc",
                 "status": "BUG", "bug": "Division by Zero", "cwe_id": "CWE-369",
                 "cwe_name": "Divide By Zero", "cert_priority": 9, "cert_level": "L2",
                 "elapsed_s": 0.5, "oracle": "bug"},
                {"target": "b.c", "source": "/tmp/proj/b.c", "kind": "esbmc",
                 "status": "SAFE", "bug": None, "elapsed_s": 0.3, "oracle": "safe"},
                {"target": "c.c", "source": "/tmp/proj/c.c", "kind": "esbmc",
                 "status": "UNKNOWN", "bug": None, "elapsed_s": 0.2, "oracle": "bug"},
            ],
        },
    }


def test_sarif_invocation_carries_exact_config_and_timing():
    run = build_sarif(_fake_run())["runs"][0]
    inv = run["invocations"][0]
    p = inv["properties"]
    # configurações exatas
    assert p["solver"] == "boolector" and p["solver_requested"] == "mathsat"
    assert p["unwind"] == 7 and p["timeout_s"] == 80 and p["jobs"] == 8
    assert p["mode"] == "sound"
    # tempos
    assert inv["startTimeUtc"] == "2026-05-31T21:00:00+00:00"
    assert inv["endTimeUtc"] == "2026-05-31T21:00:42+00:00"
    assert p["elapsed_s"] == 41.2
    # a linha de comando exata (flags do ESBMC)
    assert "--unwind 7" in inv["commandLine"] and "--boolector" in inv["commandLine"]
    # modo sound ⇒ NÃO leva --no-unwinding-assertions
    assert "--no-unwinding-assertions" not in inv["commandLine"]


def test_sarif_lists_every_tested_file_as_artifact():
    run = build_sarif(_fake_run())["runs"][0]
    uris = {a["location"]["uri"] for a in run["artifacts"]}
    assert len(run["artifacts"]) == 3                      # todos os testados, não só bugs
    assert any(u.endswith("/b.c") for u in uris)           # inclui o SAFE
    # cada artifact carrega status + tempo por arquivo
    a = next(a for a in run["artifacts"] if a["location"]["uri"].endswith("/a.c"))
    assert a["properties"]["status"] == "BUG"
    assert a["properties"]["elapsed_s"] == 0.5


def test_sarif_results_bug_and_unknown():
    run = build_sarif(_fake_run())["runs"][0]
    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert "CWE-369" in by_rule                            # BUG
    assert "INCOMPLETE-BOUND" in by_rule                   # UNKNOWN vira nota
    assert by_rule["INCOMPLETE-BOUND"]["level"] == "note"


def test_sarif_command_reflects_strategy():
    """A linha de comando no SARIF muda conforme a estratégia escolhida."""
    base = _fake_run()

    base["config"]["strategy"] = "incremental"
    cmd = build_sarif(base)["runs"][0]["invocations"][0]["commandLine"]
    assert "--incremental-bmc" in cmd and "--unwind" not in cmd

    base["config"]["strategy"] = "kinduction"
    run = build_sarif(base)["runs"][0]
    cmd = run["invocations"][0]["commandLine"]
    assert "--k-induction" in cmd and "--unwind" not in cmd
    assert run["invocations"][0]["properties"]["strategy"] == "kinduction"

    base["config"]["strategy"] = "bounded"
    cmd = build_sarif(base)["runs"][0]["invocations"][0]["commandLine"]
    assert "--no-unwinding-assertions" in cmd and "--unwind 7" in cmd


def test_solvers_endpoint_lists_available():
    r = client.get("/api/runs/solvers")
    assert r.status_code == 200
    body = r.json()
    assert "boolector" in body["available"]
    assert body["default"] == "boolector"


def _run_com_violacao():
    """Run JVM com o defeito num arquivo diferente do entrypoint (caso QuixBugs)."""
    return {
        "id": "r1", "status": "done",
        "created_at": "2026-08-02T00:00:00+00:00",
        "finished_at": "2026-08-02T00:00:05+00:00",
        "config": {"unwind": 5, "timeout": 60, "solver": "boolector"},
        "result": {
            "summary": {"total": 1, "BUG": 1},
            "targets": [{
                "target": "Main", "source": "/p/Main.java", "kind": "jbmc",
                "status": "BUG", "bug": "Division by Zero", "cwe_id": "CWE-369",
                "cwe_name": "Divide By Zero", "cert_priority": 9, "cert_level": "L2",
                "elapsed_s": 0.1, "oracle": "vuln",
                "unit_sources": ["/p/Main.java", "/p/Calc.java"],
                "violation": {"file": "Calc.java", "line": 42,
                              "description": "Denominator should be nonzero",
                              "condition": "integer-divide-by-zero",
                              "aproximada": False},
            }],
        },
    }


def test_achado_ancora_na_linha_do_defeito():
    """Sem `region` todo achado caía na linha 1 — a linha existia só na prosa
    da explicação. E num projeto multi-arquivo o defeito não está no entrypoint."""
    res = build_sarif(_run_com_violacao())["runs"][0]["results"][0]
    phys = res["locations"][0]["physicalLocation"]
    assert phys["region"]["startLine"] == 42
    assert phys["artifactLocation"]["uri"].endswith("/p/Calc.java")


def test_bug_provado_nunca_sai_como_note():
    """`note` não abre alerta no Code Scanning: uma violação com contraexemplo
    entraria silenciosa. CWE-369 tem severidade 'low' na tabela CERT."""
    res = build_sarif(_run_com_violacao())["runs"][0]["results"][0]
    assert res["level"] in ("warning", "error")


def test_fingerprint_estavel_entre_runs():
    """Sem fingerprint o Code Scanning reabre todo achado a cada run. Ele não
    pode depender do run_id nem do caminho de upload, que mudam sempre."""
    a = build_sarif(_run_com_violacao())["runs"][0]["results"][0]
    outra = _run_com_violacao()
    outra["id"] = "r2"
    b = build_sarif(outra)["runs"][0]["results"][0]
    assert a["partialFingerprints"] == b["partialFingerprints"]
    assert "r1" not in a["partialFingerprints"]["smartJbmcFindingV1"]


def test_commandline_registra_o_verificador_usado():
    """Alvo Java é verificado por JBMC: registrar a linha do ESBMC documentaria
    um comando que nunca rodou."""
    cmd = build_sarif(_run_com_violacao())["runs"][0]["invocations"][0]["commandLine"]
    assert cmd.startswith("jbmc") and "esbmc" not in cmd


def test_versao_da_ferramenta_e_a_revisao():
    run = build_sarif(_run_com_violacao(), tool_version="1.07")["runs"][0]
    assert run["tool"]["driver"]["version"] == "1.07"
