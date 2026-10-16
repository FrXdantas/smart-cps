/*
 * Exemplo com defeito: divisão inteira por zero (CWE-369).
 *
 * `media` divide a soma pela quantidade de notas sem conferir se a lista está
 * vazia. A turma "B" não tem notas, então a divisão é 0 / 0 e lança
 * ArithmeticException. O JBMC deve responder BUG e o contraexemplo deve mostrar
 * notas.size == 0 no momento da divisão.
 */
fun media(notas: IntArray): Int {
    var soma = 0
    for (n in notas) {
        soma += n
    }
    return soma / notas.size  // defeito: notas.size pode ser 0
}

fun main() {
    val turmaA = intArrayOf(7, 8, 6)
    val turmaB = IntArray(0)
    println(media(turmaA))
    println(media(turmaB))
}
