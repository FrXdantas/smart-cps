/* Fixture: laço de 10 iterações — NÃO cabe num unwind pequeno.
   Serve para distinguir as estratégias da via JVM:
     bounded -> SAFE  (garantia só até o bound)
     sound   -> UNKNOWN (o bound não cobriu o laço; não mente SAFE) */
public class LoopBound {
    public static void main(String[] args) {
        int soma = 0;
        for (int i = 0; i < 10; i++) {
            soma += i;
        }
        System.out.println(soma);
    }
}
