/*
 * Exemplo com defeito: leitura fora dos limites do vetor (CWE-125 / ARR30-C).
 *
 * O laço usa `i <= N` em vez de `i < N`. Na última volta, i == N e o programa
 * lê notas[5], uma posição além do fim do vetor. O ESBMC deve responder BUG e
 * o contraexemplo deve mostrar i = 5 no momento da leitura.
 */
#include <stdio.h>

#define N 5

int soma_notas(const int notas[N]) {
    int soma = 0;
    for (int i = 0; i <= N; i++) {  /* defeito: deveria ser i < N */
        soma += notas[i];
    }
    return soma;
}

int main(void) {
    int notas[N] = {7, 8, 6, 9, 10};
    int soma = soma_notas(notas);
    printf("media = %d\n", soma / N);
    return 0;
}
