#!/usr/bin/env python3
"""Testes estatísticos do experimento (entregável E4), sobre a saída de executar_bracos.py.

  RQ1  C x B, reparo (REPAIRED), McNemar exato pareado, odds ratio e IC 95%
  RQ4  o mesmo, separado por direção (concorrência, ponto fixo)
  RQ2  proporção de contornos entre os patches aceitos, IC de Clopper-Pearson
       (lê a auditoria: auditoria.csv com a classificação final)
  RQ3  F1 de detecção do pipeline (A) x LLM puro (D): diferença com IC por bootstrap
       (10 000 reamostragens dos programas) e Wilcoxon pareado nos acertos por programa
  Holm-Bonferroni sobre os p-valores de RQ1, RQ3 e RQ4.

Só biblioteca padrão. Uso:
  python estatistica_experimento.py <saida_do_executor> [--auditoria auditoria.csv]
"""

import argparse
import csv
import json
import math
import random
from pathlib import Path

DIRECAO = {
    "A1_alcancabilidade": "concorrencia", "A2_corrida": "concorrencia",
    "C_threads": "concorrencia", "C_corrida": "concorrencia",
    "B1_assercao_usuario": "ponto_fixo", "C_aritmetica": "ponto_fixo",
}


# ---------- distribuições ----------

def binom_cdf(k, n, p=0.5):
    return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, k + 1))


def mcnemar_exato(b, c):
    """p bilateral exato. b = só C reparou, c = só B reparou."""
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * binom_cdf(min(b, c), n))


def _betacf(a, b, x):
    """Fração contínua da Beta incompleta (Numerical Recipes, betacf)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1, a - 1
    c, d = 1.0, 1 - qab * x / qap
    d = 1 / (tiny if abs(d) < tiny else d)
    h = d
    for m in range(1, 400):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1 + aa * d
        d = 1 / (tiny if abs(d) < tiny else d)
        c = 1 + aa / c
        c = tiny if abs(c) < tiny else c
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1 + aa * d
        d = 1 / (tiny if abs(d) < tiny else d)
        c = 1 + aa / c
        c = tiny if abs(c) < tiny else c
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-14:
            break
    return h


def betai(a, b, x):
    """Beta incompleta regularizada I_x(a, b)."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                  + a * math.log(x) + b * math.log(1 - x))
    if x < (a + 1) / (a + b + 2):
        return bt * _betacf(a, b, x) / a
    return 1 - bt * _betacf(b, a, 1 - x) / b


def _beta_inv(q, a, b):
    lo, hi = 0.0, 1.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if betai(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(k, n, alfa=0.05):
    if n == 0:
        return (0.0, 1.0)
    lo = 0.0 if k == 0 else _beta_inv(alfa / 2, k, n - k + 1)
    hi = 1.0 if k == n else _beta_inv(1 - alfa / 2, k + 1, n - k)
    return (lo, hi)


def odds_ratio_ic(b, c, alfa=0.05):
    """OR condicional b/c com IC exato pela proporção b/(b+c) (Clopper-Pearson)."""
    if b + c == 0:
        return (None, None, None)
    lo, hi = clopper_pearson(b, b + c, alfa)
    conv = lambda p: math.inf if p >= 1 else p / (1 - p)  # noqa: E731
    orr = math.inf if c == 0 else b / c
    return (orr, conv(lo), conv(hi))


def wilcoxon_pareado(dif):
    """Wilcoxon signed-rank, aproximação normal com correção de empates; zeros descartados."""
    d = [x for x in dif if x != 0]
    n = len(d)
    if n == 0:
        return 1.0
    ordem = sorted(range(n), key=lambda i: abs(d[i]))
    postos = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[ordem[j + 1]]) == abs(d[ordem[i]]):
            j += 1
        media = (i + j) / 2 + 1
        for k in range(i, j + 1):
            postos[ordem[k]] = media
        i = j + 1
    w_mais = sum(p for p, x in zip(postos, d) if x > 0)
    mu = n * (n + 1) / 4
    grupos = {}
    for x in d:
        grupos[abs(x)] = grupos.get(abs(x), 0) + 1
    empates = sum(t ** 3 - t for t in grupos.values()) / 48
    sigma = math.sqrt(max(n * (n + 1) * (2 * n + 1) / 24 - empates, 0))
    if sigma == 0:
        return 1.0
    z = (abs(w_mais - mu) - 0.5) / sigma
    return min(1.0, math.erfc(max(z, 0) / math.sqrt(2)))


def holm(pvals: dict):
    itens = sorted(pvals.items(), key=lambda kv: kv[1])
    m, ajust, maior = len(itens), {}, 0.0
    for i, (k, p) in enumerate(itens):
        maior = max(maior, min(1.0, (m - i) * p))
        ajust[k] = maior
    return ajust


def f1(rotulos):
    """rotulos: lista de TP/FP/TN/FN/INCONCLUSIVO (INCONCLUSIVO conta como erro: FN ou FP)."""
    tp = sum(r == "TP" for r in rotulos)
    fp = sum(r in ("FP", "INC_SEM") for r in rotulos)
    fn = sum(r in ("FN", "INC_COM") for r in rotulos)
    return 0.0 if tp == 0 else 2 * tp / (2 * tp + fp + fn)


# ---------- leitura ----------

def ler(caminho: Path):
    if not caminho.exists():
        return []
    with open(caminho, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def pares_bc(saida: Path, direcao=None):
    b = c = ambos = nenhum = 0
    for conj, d in DIRECAO.items():
        if direcao and d != direcao:
            continue
        rb = {r["arquivo"]: r["status"] == "REPAIRED" for r in ler(saida / conj / "B.csv")}
        rc = {r["arquivo"]: r["status"] == "REPAIRED" for r in ler(saida / conj / "C.csv")}
        for arq in rb.keys() & rc.keys():
            if rc[arq] and not rb[arq]:
                b += 1
            elif rb[arq] and not rc[arq]:
                c += 1
            elif rb[arq]:
                ambos += 1
            else:
                nenhum += 1
    return dict(so_C=b, so_B=c, ambos=ambos, nenhum=nenhum)


def rotulo_det(r, campo):
    v = r[campo]
    if v == "INCONCLUSIVO":
        return "INC_COM" if r["gabarito"] == "com_bug" else "INC_SEM"
    return "TP" if v.startswith("TP") else v


def rq3(saida: Path, reamostras=10000, semente=0):
    pares = []
    for conj in DIRECAO:
        a = {r["arquivo"]: r for r in ler(saida / conj / "A.csv")}
        d = {r["arquivo"]: r for r in ler(saida / conj / "D.csv")}
        for arq in a.keys() & d.keys():
            pares.append((rotulo_det(a[arq], "estrito"), rotulo_det(d[arq], "deteccao")))
    if not pares:
        return None
    fa, fd = f1([p[0] for p in pares]), f1([p[1] for p in pares])
    rnd = random.Random(semente)
    difs = []
    for _ in range(reamostras):
        am = [pares[rnd.randrange(len(pares))] for _ in pares]
        difs.append(f1([p[0] for p in am]) - f1([p[1] for p in am]))
    difs.sort()
    acerto = lambda r: 1 if r in ("TP", "TN") else 0  # noqa: E731
    p = wilcoxon_pareado([acerto(x) - acerto(y) for x, y in pares])
    return dict(n=len(pares), f1_pipeline=fa, f1_llm_puro=fd, diferenca=fa - fd,
                ic95=(difs[int(0.025 * reamostras)], difs[int(0.975 * reamostras) - 1]), p=p)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("saida", type=Path)
    ap.add_argument("--auditoria", type=Path)
    a = ap.parse_args(argv)
    out, pvals = {}, {}
    for nome, direcao in (("RQ1", None), ("RQ4_concorrencia", "concorrencia"),
                          ("RQ4_ponto_fixo", "ponto_fixo")):
        t = pares_bc(a.saida, direcao)
        orr, lo, hi = odds_ratio_ic(t["so_C"], t["so_B"])
        t.update(p=mcnemar_exato(t["so_C"], t["so_B"]), odds_ratio=orr, ic95=(lo, hi))
        out[nome] = t
        pvals[nome] = t["p"]
    r3 = rq3(a.saida)
    if r3:
        out["RQ3"] = r3
        pvals["RQ3"] = r3["p"]
    if a.auditoria and a.auditoria.exists():
        linhas = [r for r in ler(a.auditoria) if r.get("final")]
        k = sum(r["final"] == "contorno" for r in linhas)
        out["RQ2"] = dict(n=len(linhas), contornos=k,
                          proporcao=(k / len(linhas)) if linhas else None,
                          ic95=clopper_pearson(k, len(linhas)))
    out["holm"] = holm(pvals)
    print(json.dumps(out, ensure_ascii=False, indent=1, default=str))
    return out


if __name__ == "__main__":
    main()
