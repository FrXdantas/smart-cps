/* Fixture: divisão por zero garantida (CWE-369 / INT33-C). */
int main(void) {
    int x = 10;
    int y = 0;
    return x / y;
}
