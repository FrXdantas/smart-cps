/* Fixture: acesso a array fora dos limites (CWE-125 / ARR30-C). */
public class ArrayOob {
    public static void main(String[] args) {
        int[] arr = new int[2];
        int i = 5;
        int x = arr[i]; // índice fora dos limites
        System.out.println(x);
    }
}
