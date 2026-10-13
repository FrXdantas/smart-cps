/* Fixture multi-arquivo (forma do QuixBugs): o DEFEITO mora aqui.
 * `get` lê uma posição além do fim quando i == arr.length (CWE-125 / ARR30-C).
 * Quem tem o `main` é Main.java — logo é lá que o JBMC reporta o bug, e era lá
 * que o reparo tentava (errado) corrigir. */
public class Lib {
    public static int get(int[] arr, int i) {
        return arr[i];
    }
}
