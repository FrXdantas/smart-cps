"""ensure_c_headers não injeta #include em C pré-processado (achado de 27/11, A1/A2 do SV-COMP)."""

from smart_jbmc.core.repair.loop import codigo_preprocessado, ensure_c_headers

SVCOMP_I = """typedef unsigned char __u_char;
__extension__ typedef signed long long int __int64_t;
typedef unsigned int size_t;
extern void *malloc (size_t __size);
int main(void) { int *p = malloc(4); if (p == NULL) return 1; printf("x"); return 0; }
"""


def test_svcomp_i_nao_ganha_include():
    assert codigo_preprocessado(SVCOMP_I)
    assert ensure_c_headers(SVCOMP_I) == SVCOMP_I


def test_marcador_de_linha_do_cpp_conta_como_preprocessado():
    code = '# 1 "main.c"\nint main(void){ return INT_MAX; }\n'
    assert ensure_c_headers(code) == code


def test_fonte_comum_continua_ganhando_include():
    code = "int main(void){ int *p = malloc(4); return p == NULL; }\n"
    out = ensure_c_headers(code)
    assert out.startswith("#include <stdlib.h>\n")
    assert not codigo_preprocessado(code)


def test_arquivo_que_declara_size_t_nao_ganha_include():
    code = "typedef unsigned int size_t;\nvoid *malloc(size_t);\nint main(void){ return malloc(1) == NULL; }\n"
    assert ensure_c_headers(code) == code
