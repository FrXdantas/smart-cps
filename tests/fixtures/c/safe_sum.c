/* Fixture: programa seguro — nenhuma violação até o bound. */
int main(void) {
    int a = 2;
    int b = 3;
    int c = a + b;
    return c - 5; /* sempre 0 */
}
