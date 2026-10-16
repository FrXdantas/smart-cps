# Exemplos com defeito

Dois programas pequenos, cada um com um defeito conhecido, para conferir a
ferramenta de ponta a ponta (verificação, contraexemplo e reparo).

| Arquivo | Defeito | Resultado esperado |
|---|---|---|
| `c/notas.c` | laço `i <= N` lê `notas[5]` | BUG, CWE-125, `notas.c` linha 15, `array bounds violated` |
| `kotlin/Media.kt` | `soma / notas.size` com a lista vazia | BUG, CWE-369, `Media.kt` linha 14, `Denominator should be nonzero` |

## Como usar

1. Em Nova verificação, enviar os dois arquivos (ou a pasta `exemplos/`). Com o
   Docker, o campo Pasta enxerga só o que está dentro do container, então o
   caminho deste repositório no seu PC não funciona ali; use o envio de arquivos.
2. Verificar com **unwind 6 ou mais**. O laço do C dá 6 voltas e o defeito está
   na última; com o unwind padrão (5) o C sai `SAFE`, porque o verificador não
   chega até ela. É o limite do BMC: `SAFE` vale só até o bound escolhido.
3. Em Resultados, clicar no alvo para abrir o contraexemplo: o ponto exato da
   violação (arquivo, linha, descrição) e, no Kotlin, os valores de cada passo
   até a divisão.
4. Pedir o reparo. Um reparo aceito (`FIX_OK`) corrige o limite do laço ou trata
   a lista vazia; um `if` que só torna o trecho inalcançável é rejeitado como
   `INVALID_PATCH`.
