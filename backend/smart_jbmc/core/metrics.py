"""Métricas: CASTLE Score (TASE2025) e distribuição CWE.

Portado de castle_bonus / castle_score / aggregate_cwe / infer_oracle_from_path.
`results` é uma lista de dicts com pelo menos: bug, n_findings, oracle.
"""

from .classify import CWE_INFO


def castle_bonus(top25_rank, b_max: int = 5) -> int:
    if top25_rank is None or not (1 <= top25_rank <= 25):
        return 0
    return b_max - ((top25_rank - 1) // b_max)


def castle_score(results: list[dict]) -> dict:
    """Pontuação CASTLE + TP/TN/FP/FN/precision/recall/accuracy (só com oracle).

    Sem nenhum alvo com gabarito não existe matriz de confusão: as taxas voltam
    `None`, nunca 0.0 — zero é um resultado medido ("errou tudo") e seria
    indistinguível de "não havia o que medir". `n_avaliados` diz sobre quantos
    alvos a matriz foi calculada.
    """
    score = 0
    tp = tn = fp = fn = 0
    avaliados = 0
    for r in results:
        if r.get("oracle") is None:
            continue
        avaliados += 1
        oracle_vuln = r["oracle"] == "vuln"
        detected = r.get("bug") is not None
        n_findings = max(1, r.get("n_findings", 1)) if detected else 0
        if oracle_vuln and detected:
            info = CWE_INFO.get(r["bug"], CWE_INFO["Unknown Failure"])
            score += 5 - (n_findings - 1) + castle_bonus(info["top25_rank"])
            tp += 1
        elif (not oracle_vuln) and (not detected):
            score += 2
            tn += 1
        elif (not oracle_vuln) and detected:
            score += -n_findings
            fp += 1
        else:
            fn += 1
    if not avaliados:
        return {
            "tp": 0, "tn": 0, "fp": 0, "fn": 0,
            "precision": None, "recall": None, "accuracy": None,
            "castle_score": None,
            "n_avaliados": 0, "n_total": len(results),
        }
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / avaliados
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "accuracy": accuracy,
        "castle_score": score,
        "n_avaliados": avaliados, "n_total": len(results),
    }


def aggregate_cwe(results: list[dict]) -> dict:
    """Distribuição de CWE entre os resultados com bug."""
    dist: dict[str, int] = {}
    for r in results:
        if r.get("bug"):
            cwe = CWE_INFO.get(r["bug"], CWE_INFO["Unknown Failure"])["cwe_id"]
            dist[cwe] = dist.get(cwe, 0) + 1
    return dist


# Nomes de PASTA que carregam o gabarito. Casamento é por componente inteiro,
# nunca por substring: "sem_bug" contém "bug", e um `in` ingênuo inverteria o
# ground truth — pior que não ter gabarito nenhum. Por isso, também, as pastas
# negativas são testadas antes das positivas.
_DIR_SAFE = {
    "safe", "sem_bug", "sembug", "sem-bug", "no_bug", "nobug",
    "sem_defeito", "correct", "correto", "corrigido", "fixed",
}
_DIR_VULN = {
    "bug", "bugs", "com_bug", "combug", "com-bug", "vuln", "vulnerable",
    "buggy", "unsafe", "com_defeito", "defeito",
}


def infer_oracle_from_path(path) -> str | None:
    """Deduz o ground truth do caminho pelas pastas (SV-COMP usa safe/ e bug/;
    os corpora daqui usam com_bug/ e sem_bug/).

    Só os DIRETÓRIOS contam: o nome do arquivo é ignorado, senão um
    `Foo_FIXED.java` dentro de `com_bug/` se contradiria com a própria pasta.
    Vale a pasta mais próxima do arquivo, que é a mais específica.
    """
    if not path:
        return None
    partes = [p.strip().lower() for p in str(path).replace("\\", "/").split("/")]
    for nome in reversed(partes[:-1]):          # [:-1] descarta o arquivo
        if nome in _DIR_SAFE:
            return "safe"
        if nome in _DIR_VULN:
            return "vuln"
    return None
