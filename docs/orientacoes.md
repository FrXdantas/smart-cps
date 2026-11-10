# Orientações recebidas

Registro do que o orientador pediu em cada apresentação, com a data. O texto de "Pedido"
é o que foi dito; "Interpretação" é como entendemos e o que fazer.

## 10/11/2026: apresentação do delta da semana 5

**Pedido**

1. Focar em issues e relatá-las.
2. Usar o ESBMC para gerar o caso de teste que verifica a issue.
3. Gerar o executável junto com o sanitizer.

**Interpretação**

- Prioridade passa a ser achar defeitos reais nos projetos de produção (FreeRTOS-Kernel, grbl,
  CMSIS-DSP) e reportá-los aos mantenedores. Primeira candidata: a corrida em `xSchedulerEnd`
  (rascunho da issue pronto, ainda não enviado).
- Cadeia de evidência para cada issue: o ESBMC acha o defeito → o ESBMC gera o caso de teste a
  partir do contraexemplo → um executável compilado com o caso de teste e com sanitizer reproduz
  o defeito numa execução real. A issue vai com esse reprodutor.
- Opções do ESBMC já disponíveis na imagem: `--generate-testcase` (XML) e
  `--generate-ctest-testcase` (testes em C).
- Sanitizer conforme a propriedade: ThreadSanitizer (`-fsanitize=thread`) para corrida;
  AddressSanitizer e UBSan (`-fsanitize=address,undefined`) para memória e estouro aritmético.
- Na semana 5 a reprodução com ThreadSanitizer foi feita à mão (programa mínimo escrito por nós).
  O pedido é que o caso de teste saia do ESBMC.

**A confirmar com o orientador**

- Se o executável deve ser gerado pela própria ferramenta SMART (nova funcionalidade) ou se basta
  o procedimento documentado para cada issue.
