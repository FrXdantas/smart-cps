/* Fixture p/ --function: NÃO tem main. `risky` recebe um divisor; quando o ESBMC
 * verifica esta função como PONTO DE ENTRADA, havoca `x` (nondet) e acha a
 * divisão por zero em x==0. Sem --function (sem main) não haveria o que verificar. */
int risky(int x) {
    return 100 / x;   /* div-by-zero quando x==0 (arg havocado pelo --function) */
}
