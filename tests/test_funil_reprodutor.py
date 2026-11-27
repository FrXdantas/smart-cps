"""Funil do reprodutor (2.9-cps): taxa de confirmação por etapa da cadeia
contraexemplo -> caso de teste -> compilação -> execução -> reprodução."""

from smart_jbmc.api.runs import _completar_funil
from smart_jbmc.core.reprodutor import VEREDITOS, funil


def _contagem(**kw):
    c = {v: 0 for v in VEREDITOS}
    c.update(kw)
    c["total"] = sum(c[v] for v in VEREDITOS)
    return c


def test_funil_a2_da_rodada_de_13_11():
    # A2_corrida, run e6a567868bca: 43 BUG, 26 reproduzidos, 3 outro ponto, 9 não, 5 inconclusivos
    f = funil(_contagem(REPRODUZIDO=26, REPRODUZIDO_OUTRO_PONTO=3, NAO_REPRODUZIDO=9,
                        INCONCLUSIVO=5))
    assert [e["etapa"] for e in f] == ["bug", "caso_de_teste", "compilou", "executou",
                                       "reproduzido"]
    assert [e["n"] for e in f] == [43, 43, 43, 38, 26]
    assert f[-1]["pct_bug"] == 60.5
    assert f[-1]["pct_etapa"] == 68.4
    assert f[-1]["outro_ponto"] == 3


def test_funil_dsverifier_para_no_caso_de_teste():
    f = funil(_contagem(SEM_CASO_DE_TESTE=10, FALHA_COMPILACAO=1))
    assert [e["n"] for e in f] == [11, 1, 0, 0, 0]
    assert f[2]["pct_etapa"] == 0.0
    assert f[3]["pct_etapa"] == 0.0  # etapa anterior vazia não divide por zero


def test_funil_vazio_sem_reprodutor():
    assert funil(None) == []
    assert funil({"total": 0}) == []


def test_run_antiga_ganha_funil_na_leitura():
    rec = {"result": {"summary": {"total": 4, "BUG": 1,
                                  "reprodutor": _contagem(REPRODUZIDO=1)}}}
    _completar_funil(rec)
    assert rec["result"]["summary"]["reprodutor_funil"][-1]["n"] == 1


def test_run_sem_reprodutor_nao_ganha_funil():
    rec = {"result": {"summary": {"total": 4, "BUG": 1}}}
    _completar_funil(rec)
    assert "reprodutor_funil" not in rec["result"]["summary"]
