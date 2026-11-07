#!/usr/bin/env python3
"""Auditoria dupla dos patches aceitos (grupo C' da especificação) e kappa de Cohen.

1) Gerar a planilha a partir da saída de executar_bracos.py:
     python auditoria_experimento.py gerar <saida>
   Cria <saida>/auditoria/auditoria.csv (uma linha por patch aceito dos grupos B e C)
   e um .diff por patch. A ordem das linhas é embaralhada e o braço fica numa coluna
   separada, para que quem audita possa escondê-la (auditoria às cegas).
   Cada autor preenche SUA cópia, na coluna "classificacao": reparo_real ou contorno.

2) Calcular a concordância:
     python auditoria_experimento.py kappa <copia_autor1.csv> <copia_autor2.csv>
   Mostra o kappa de Cohen, as divergências, e grava auditoria_final.csv com a coluna
   "final" preenchida onde os dois concordam (as divergências ficam para consenso).
"""

import argparse
import csv
import difflib
import random
import sys
from pathlib import Path

COLS = ["id", "conjunto", "arquivo", "bug", "braco", "diff", "classificacao", "observacao"]
CLASSES = ("reparo_real", "contorno")


def gerar(saida: Path, semente="0"):
    pasta = saida / "auditoria"
    (pasta / "diffs").mkdir(parents=True, exist_ok=True)
    linhas = []
    for conj_dir in sorted(p for p in saida.iterdir() if p.is_dir()):
        for braco in ("B", "C"):
            arq = conj_dir / f"{braco}.csv"
            if not arq.exists():
                continue
            with open(arq, newline="", encoding="utf-8") as f:
                for r in csv.DictReader(f):
                    if r["status"] != "REPAIRED" or not r["patch"]:
                        continue
                    orig = saida / "trabalho" / conj_dir.name / "A" / r["arquivo"]
                    patch = saida / r["patch"]
                    diff = difflib.unified_diff(
                        orig.read_text(encoding="utf-8", errors="ignore").splitlines(True),
                        patch.read_text(encoding="utf-8", errors="ignore").splitlines(True),
                        fromfile=f"original/{r['arquivo']}", tofile=f"patch/{r['arquivo']}")
                    linhas.append(dict(conjunto=conj_dir.name, arquivo=r["arquivo"],
                                       bug=r["bug"], braco=braco, texto="".join(diff)))
    random.Random(semente).shuffle(linhas)
    with open(pasta / "auditoria.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for i, l in enumerate(linhas, 1):
            nome = f"diffs/{i:03d}.diff"
            (pasta / nome).write_text(l["texto"], encoding="utf-8")
            w.writerow(dict(id=i, conjunto=l["conjunto"], arquivo=l["arquivo"], bug=l["bug"],
                            braco=l["braco"], diff=nome, classificacao="", observacao=""))
    print(f"{len(linhas)} patches em {pasta / 'auditoria.csv'}")
    return len(linhas)


def kappa_cohen(r1, r2):
    """kappa para dois avaliadores e categorias nominais."""
    n = len(r1)
    if n == 0:
        return None
    cats = sorted(set(r1) | set(r2))
    po = sum(a == b for a, b in zip(r1, r2)) / n
    pe = sum((r1.count(c) / n) * (r2.count(c) / n) for c in cats)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def ler(caminho):
    with open(caminho, newline="", encoding="utf-8") as f:
        return {r["id"]: r for r in csv.DictReader(f)}


def kappa(arq1: Path, arq2: Path):
    a, b = ler(arq1), ler(arq2)
    ids = [i for i in a if i in b and a[i]["classificacao"] in CLASSES
           and b[i]["classificacao"] in CLASSES]
    faltam = [i for i in a if i not in ids]
    r1 = [a[i]["classificacao"] for i in ids]
    r2 = [b[i]["classificacao"] for i in ids]
    k = kappa_cohen(r1, r2)
    print(f"Patches classificados pelos dois: {len(ids)} (sem classificação: {len(faltam)})")
    print(f"Concordância: {sum(x == y for x, y in zip(r1, r2))}/{len(ids)}  kappa = "
          f"{'n/d' if k is None else f'{k:.3f}'}")
    div = [i for i in ids if a[i]["classificacao"] != b[i]["classificacao"]]
    for i in div:
        print(f"  divergência id {i}: {a[i]['arquivo']} ({a[i]['classificacao']} x "
              f"{b[i]['classificacao']})")
    final = arq1.parent / "auditoria_final.csv"
    with open(final, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS + ["final"])
        w.writeheader()
        for i, r in a.items():
            fin = r["classificacao"] if i in ids and i not in div else ""
            w.writerow({**{c: r.get(c, "") for c in COLS}, "final": fin})
    print(f"Gravado {final} (divergências com 'final' vazio, para consenso).")
    return k


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gerar")
    g.add_argument("saida", type=Path)
    k = sub.add_parser("kappa")
    k.add_argument("autor1", type=Path)
    k.add_argument("autor2", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "gerar":
        return gerar(a.saida)
    return kappa(a.autor1, a.autor2)


if __name__ == "__main__":
    sys.exit(0 if main() is not None else 1)
