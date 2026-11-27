"""'conflicting definition for variable stdin' (ESBMC em .i do SV-COMP) não é ERROR (achado de 27/11)."""

from smart_jbmc.core.classify import classify, has_error

AVISOS = ("ERROR: conflicting definition for variable 'stderr'\n"
          "ERROR: conflicting definition for variable 'stdin'\n"
          "ERROR: conflicting definition for variable 'stdout'\n")


def test_aviso_de_stdin_com_sucesso_vira_safe():
    raw = AVISOS + "Generated 12 VCC(s)\nVERIFICATION SUCCESSFUL\n"
    assert not has_error(raw)
    assert classify(raw).status == "SAFE"


def test_outro_error_continua_erro():
    assert has_error(AVISOS + "ERROR: PARSING ERROR\n")
    assert has_error("ERROR: conflicting definition for variable 'contador'\n")
