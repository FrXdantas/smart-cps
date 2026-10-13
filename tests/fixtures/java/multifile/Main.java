/* Fixture multi-arquivo: harness de teste, SEM defeito. Só chama Lib.get.
 * É o único arquivo com `main`, então é o alvo que o JBMC consegue verificar. */
public class Main {
    public static void main(String[] args) {
        int[] arr = new int[3];
        int x = Lib.get(arr, 3);   // fora dos limites -> a violação acontece dentro de Lib
        if (x != 0) throw new AssertionError();
    }
}
