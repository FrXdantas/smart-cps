#!/usr/bin/env python3
"""Executor dos grupos do experimento (especificação, slide 7) sobre corpora com gabarito.

  A  detecção pura              run_verification, comparada ao gabarito (critério estrito)
  B  BMC + stack trace          reparo com ponto da falha e cadeia de chamadas, sem valores
  C  BMC + CEX estruturado      reparo normal da ferramenta (contraexemplo com valores)
  D  LLM puro, sem BMC          a LLM só vê o código: detecta e propõe correção numa chamada;
                                a correção é conferida depois pelo BMC só para registro
  C' (auditoria) não roda aqui: é a classificação humana dos patches aceitos de C.

B e C reparam os MESMOS alvos (defeito do gabarito que A detectou), com as MESMAS opções
de verificação, o mesmo modelo e o mesmo oráculo. Só muda o que vai no prompt.

Roda dentro da imagem da ferramenta (mesma imagem em todas as condições):

  docker run --rm --network host --user "$(id -u):$(id -g)" \\
    -v ~/TrbLuccas/corpora_cps/corpora:/corpora:ro -v <saida>:/saida \\
    -e SMART_LLM_API_KEY --entrypoint python smartcps:<rev> \\
    /app/tools/executar_bracos.py --corpora /corpora --saida /saida --bracos A,B,C,D --limite 4

A chave da LLM vem só do ambiente (SMART_LLM_API_KEY) e nunca é gravada.
Retomável: o que já está nos CSVs de saída não é refeito.
"""

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from smart_jbmc import APP_REVISION  # noqa: E402
from smart_jbmc.core.orchestrator import run_verification  # noqa: E402
from smart_jbmc.core.repair import llm_puro  # noqa: E402
from smart_jbmc.core.repair.loop import repair_run  # noqa: E402
from smart_jbmc.core.repair.regression import regression_check  # noqa: E402

# Opções por conjunto, as validadas no piloto da semana 4 (decisão D3 de 07/11:
# iguais em todos os braços; a divergência com k = 10 / 20 s da especificação vai
# registrada no artigo). A1 roda sem --unsigned-overflow-check (o piloto o ligou
# por engano; o gabarito do SV-COMP é só reach_error).
# `propriedade` = a do gabarito de cada conjunto (RC4; delta 4, frente 1). Com
# --todas-as-propriedades o executor volta ao modo de sempre (o do piloto).
CONFIG_POR_CONJUNTO = {
    "A1_alcancabilidade": dict(unwind=3, timeout=180, jobs=1, concurrency=True, race_check=False,
                               propriedade="assercao"),
    "A2_corrida": dict(unwind=3, timeout=180, jobs=1, concurrency=True, race_check=True,
                       propriedade="corrida"),
    "B1_assercao_usuario": dict(unwind=18, timeout=180, jobs=2, concurrency=False,
                                race_check=False, function="unit_test", propriedade="assercao"),
    "C_threads": dict(unwind=3, timeout=180, jobs=1, concurrency=True, race_check=False,
                      propriedade="assercao"),
    "C_corrida": dict(unwind=3, timeout=180, jobs=1, concurrency=True, race_check=True,
                      propriedade="corrida"),
    "C_aritmetica": dict(unwind=21, timeout=180, jobs=2, concurrency=False, race_check=False,
                         propriedade="estouro"),
}
PADRAO = dict(solver="boolector", strategy="bounded", unsigned_overflow=False,
              nan_check=False, function=None, propriedade="todas")

COLS_A = ["conjunto", "arquivo", "gabarito", "cwe_esperada", "status", "bug", "cwe_id",
          "tempo_s", "estrito"]
COLS_R = ["conjunto", "braco", "arquivo", "bug", "status", "iteracoes", "veredictos",
          "tokens", "ms_modelo", "tempo_s", "patch"]
COLS_D = ["conjunto", "arquivo", "gabarito", "cwe_esperada", "defeito", "cwe", "linha",
          "deteccao", "cwe_ok", "formato_invalido", "truncada", "tokens", "ms_modelo",
          "bmc_registro", "patch"]


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def classificar(status, cwe, gabarito, cwe_esperada):
    """Critério estrito (delta 4): TIMEOUT/ERROR = INCONCLUSIVO; BUG com CWE errada à parte."""
    if gabarito == "com_bug":
        if status == "BUG":
            return "TP" if cwe == cwe_esperada else "TP_cwe_errada"
        if status == "SAFE":
            return "FN"
    else:
        if status == "SAFE":
            return "TN"
        if status == "BUG":
            return "FP"
    return "INCONCLUSIVO"


def classificar_d(defeito, gabarito):
    if defeito is None:
        return "INCONCLUSIVO"
    if gabarito == "com_bug":
        return "TP" if defeito else "FN"
    return "FP" if defeito else "TN"


def ler_gabarito(pasta: Path) -> list[dict]:
    with open(pasta / "gabarito.csv", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def selecionar(linhas, limite, semente):
    """Amostra determinística: metade com defeito, metade sem (ordem por hash)."""
    if not limite:
        return linhas
    chave = lambda r: hashlib.sha1(f"{semente}:{r['arquivo']}".encode()).hexdigest()  # noqa: E731
    com = sorted((r for r in linhas if r["gabarito"] == "com_bug"), key=chave)
    sem = sorted((r for r in linhas if r["gabarito"] != "com_bug"), key=chave)
    n_com = min(len(com), (limite + 1) // 2)
    n_sem = min(len(sem), limite - n_com)
    return com[:n_com] + sem[:n_sem]


def copiar(origem: Path, destino: Path, arquivos):
    for rel in arquivos:
        d = destino / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        if not d.exists():
            shutil.copy2(origem / rel, d)


def feitos(caminho: Path, chave=("arquivo",)) -> set:
    if not caminho.exists():
        return set()
    with open(caminho, newline="", encoding="utf-8") as f:
        return {tuple(r[k] for k in chave) for r in csv.DictReader(f)}


def anexar(caminho: Path, cols, linha: dict):
    novo = not caminho.exists()
    with open(caminho, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        if novo:
            w.writeheader()
        w.writerow({k: linha.get(k, "") for k in cols})


def rel_de(source: str, base: Path) -> str:
    return os.path.relpath(source, base)


def grupo_a(conj, pasta, sel, saida, opts):
    """Detecção. Grava A.csv e alvos_A.json (alimenta B, C e o registro de D)."""
    alvos_json = saida / conj / "alvos_A.json"
    if alvos_json.exists():
        return json.loads(alvos_json.read_text(encoding="utf-8"))
    trab = saida / "trabalho" / conj / "A"
    arquivos = [r["arquivo"] for r in sel]
    copiar(pasta, trab, arquivos)
    log(f"{conj} A: verificando {len(arquivos)} programas")
    t0 = time.perf_counter()
    rr = run_verification(str(trab), files=arquivos,
                          build_root=str(saida / "trabalho" / conj / "build_A"),
                          **{k: v for k, v in opts.items()})
    gab = {r["arquivo"]: r for r in sel}
    alvos = {}
    for t in rr.targets:
        d = asdict(t)
        rel = rel_de(t.source, trab) if t.source else t.target
        g = gab.get(rel)
        if not g:
            continue
        alvos[rel] = d
        anexar(saida / conj / "A.csv", COLS_A, dict(
            conjunto=conj, arquivo=rel, gabarito=g["gabarito"], cwe_esperada=g["cwe_esperada"],
            status=t.status, bug=t.bug, cwe_id=t.cwe_id, tempo_s=round(t.elapsed_s, 2),
            estrito=classificar(t.status, t.cwe_id, g["gabarito"], g["cwe_esperada"])))
    alvos_json.write_text(json.dumps(alvos, ensure_ascii=False, indent=1), encoding="utf-8")
    log(f"{conj} A: {len(alvos)} alvos em {time.perf_counter() - t0:.0f} s")
    return alvos


def grupo_reparo(conj, braco, pasta, sel, alvos, saida, opts, llm_cfg, max_iters):
    """B (stack_trace) ou C (estruturado) sobre os defeitos do gabarito que A detectou."""
    modo = "stack_trace" if braco == "B" else "estruturado"
    csv_r = saida / conj / f"{braco}.csv"
    ja = {a for (a,) in feitos(csv_r)}
    trab = saida / "trabalho" / conj / braco
    base_a = saida / "trabalho" / conj / "A"
    gab = {r["arquivo"]: r for r in sel}
    candidatos = [rel for rel, a in alvos.items()
                  if a["status"] == "BUG" and gab.get(rel, {}).get("gabarito") == "com_bug"]
    for rel in candidatos:
        if rel in ja:
            continue
        copiar(pasta, trab, [rel])
        a = dict(alvos[rel])
        # o alvo aponta para a cópia DESTE braço (o reparo grava _FIXED ao lado)
        a["source"] = str(trab / rel)
        a["unit_sources"] = [str(trab / rel_de(u, base_a)) for u in a.get("unit_sources") or []]
        log(f"{conj} {braco}: reparando {rel}")
        t0 = time.perf_counter()
        res = repair_run([a], unwind=opts["unwind"], timeout=opts["timeout"],
                         solver=opts["solver"], max_iters=max_iters,
                         unsigned_overflow=opts["unsigned_overflow"], nan_check=opts["nan_check"],
                         propriedade=opts["propriedade"],
                         strategy=opts["strategy"], concurrency=opts["concurrency"],
                         race_check=opts["race_check"], function=opts.get("function"),
                         work_dir=str(saida / "trabalho" / conj / f"rep_{braco}"),
                         cex_mode=modo, **llm_cfg)
        r = (res.get("targets") or [{}])[0]
        tentativas = r.get("attempts") or []
        patch_rel = ""
        if r.get("final_code"):
            p = saida / conj / "patches" / braco / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(r["final_code"], encoding="utf-8")
            patch_rel = str(p.relative_to(saida))
        anexar(csv_r, COLS_R, dict(
            conjunto=conj, braco=braco, arquivo=rel, bug=a.get("bug"), status=r.get("status"),
            iteracoes=r.get("iterations"),
            veredictos=" ".join(t.get("verdict", "?") for t in tentativas),
            tokens=sum(t.get("tokens") or 0 for t in tentativas),
            ms_modelo=sum(t.get("ms") or 0 for t in tentativas),
            tempo_s=round(time.perf_counter() - t0, 1), patch=patch_rel))
        log(f"{conj} {braco}: {rel} -> {r.get('status')} ({r.get('iterations')} it.)")


def grupo_d(conj, pasta, sel, alvos, saida, opts, llm_cfg):
    csv_d = saida / conj / "D.csv"
    ja = {a for (a,) in feitos(csv_d)}
    trab = saida / "trabalho" / conj / "D"
    for g in sel:
        rel = g["arquivo"]
        if rel in ja:
            continue
        code = (pasta / rel).read_text(encoding="utf-8", errors="ignore")
        log(f"{conj} D: {rel}")
        r = llm_puro.detectar_e_corrigir(code, file_name=os.path.basename(rel),
                                         model=llm_cfg.get("model"),
                                         base_url=llm_cfg.get("base_url"),
                                         api_key=llm_cfg.get("api_key"))
        registro, patch_rel = "", ""
        if r["codigo"]:
            p = saida / conj / "patches" / "D" / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(r["codigo"], encoding="utf-8")
            patch_rel = str(p.relative_to(saida))
            a = alvos.get(rel)
            if a and a["status"] == "BUG":
                # registro: o mesmo oráculo dos outros braços, uma vez, sem laço
                copiar(pasta, trab, [rel])
                stem, ext = os.path.splitext(trab / rel)
                fixed = Path(f"{stem}_FIXED{ext}")
                fixed.write_text(r["codigo"], encoding="utf-8")
                reg = regression_check(str(fixed), a["bug"], opts["unwind"], opts["timeout"],
                                       opts["solver"], unsigned_overflow=opts["unsigned_overflow"],
                                       nan_check=opts["nan_check"], strategy=opts["strategy"],
                                       propriedade=opts["propriedade"],
                                       concurrency=opts["concurrency"],
                                       race_check=opts["race_check"],
                                       function=opts.get("function"),
                                       repaired_source=str(trab / rel))
                registro = reg.verdict
        anexar(csv_d, COLS_D, dict(
            conjunto=conj, arquivo=rel, gabarito=g["gabarito"], cwe_esperada=g["cwe_esperada"],
            defeito=r["defeito"], cwe=r["cwe"], linha=r["linha"],
            deteccao=classificar_d(r["defeito"], g["gabarito"]),
            cwe_ok=(r["cwe"] == g["cwe_esperada"]) if g["gabarito"] == "com_bug" else "",
            formato_invalido=r["formato_invalido"], truncada=r["truncated"],
            tokens=(r.get("usage") or {}).get("completion_tokens") or 0,
            ms_modelo=r.get("ms") or 0, bmc_registro=registro, patch=patch_rel))


def versao_esbmc() -> str:
    try:
        return subprocess.run(["esbmc", "--version"], capture_output=True, text=True,
                              timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "?"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpora", required=True, type=Path)
    ap.add_argument("--saida", required=True, type=Path)
    ap.add_argument("--bracos", default="A,B,C,D")
    ap.add_argument("--conjuntos", default=",".join(CONFIG_POR_CONJUNTO))
    ap.add_argument("--limite", type=int, default=0, help="programas por conjunto (0 = todos)")
    ap.add_argument("--semente", default="0")
    ap.add_argument("--modelo", default="deepseek-flash")
    ap.add_argument("--base-url", default="https://api.deepseek.com")
    ap.add_argument("--max-iters", type=int, default=5)
    ap.add_argument("--jobs", type=int, default=0,
                    help="verificações em paralelo no grupo A (0 = o valor de cada conjunto)")
    ap.add_argument("--todas-as-propriedades", action="store_true",
                    help="verifica todas as propriedades (modo de sempre), não só a do gabarito")
    a = ap.parse_args(argv)

    bracos = [b.strip().upper() for b in a.bracos.split(",") if b.strip()]
    if set(bracos) - {"A", "B", "C", "D"}:
        ap.error("braços válidos: A, B, C, D")
    api_key = os.environ.get("SMART_LLM_API_KEY")
    if set(bracos) & {"B", "C", "D"} and not api_key:
        ap.error("defina SMART_LLM_API_KEY no ambiente para os braços B, C e D")
    llm_cfg = dict(model=a.modelo, base_url=a.base_url, api_key=api_key)
    a.saida.mkdir(parents=True, exist_ok=True)

    meta = dict(revisao=APP_REVISION, esbmc=versao_esbmc(),
                inicio=datetime.now(timezone.utc).isoformat(), bracos=bracos,
                modelo=a.modelo, base_url=a.base_url, max_iters=a.max_iters, temperatura=0.2,
                limite=a.limite, semente=a.semente, conjuntos={})
    for conj in [c.strip() for c in a.conjuntos.split(",") if c.strip()]:
        if conj not in CONFIG_POR_CONJUNTO:
            ap.error(f"conjunto sem opções definidas: {conj}")
        pasta = a.corpora / conj
        opts = {**PADRAO, **CONFIG_POR_CONJUNTO[conj]}
        if a.todas_as_propriedades:
            opts["propriedade"] = "todas"
        if a.jobs:
            opts["jobs"] = a.jobs
        sel = selecionar(ler_gabarito(pasta), a.limite, a.semente)
        (a.saida / conj).mkdir(parents=True, exist_ok=True)
        meta["conjuntos"][conj] = dict(opcoes=opts, programas=[r["arquivo"] for r in sel])
        (a.saida / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1),
                                           encoding="utf-8")
        alvos = grupo_a(conj, pasta, sel, a.saida, opts)
        for b in ("B", "C"):
            if b in bracos:
                grupo_reparo(conj, b, pasta, sel, alvos, a.saida, opts, llm_cfg, a.max_iters)
        if "D" in bracos:
            grupo_d(conj, pasta, sel, alvos, a.saida, opts, llm_cfg)
    meta["fim"] = datetime.now(timezone.utc).isoformat()
    (a.saida / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
    log("fim")


if __name__ == "__main__":
    main()
