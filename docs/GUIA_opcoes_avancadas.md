# Guia — Opções de projeto (avançado)

Guia de consulta dos três campos da seção **"Opções de projeto (avançado)"** da
tela *Nova verificação*. Cada campo destrava a verificação de **código real**
(unidades de projetos maiores), além dos benchmarks self-contained.

Os exemplos marcados **▶ rodável** usam arquivos que existem neste repositório;
os marcados **◇ ilustrativo** mostram o formato com um projeto típico (ex.: llama.cpp)
que não está versionado aqui.

| Campo | Flag ESBMC | Para quê |
|---|---|---|
| **include paths (-I)** | `-I <dir>` | achar headers que não estão na pasta do alvo |
| **unidade multi-arquivo (link)** | (linka vários `.c`) | dar corpo às dependências (senão viram *havoc*) |
| **função-entrada (--function)** | `--function <nome>` | verificar uma função sem `main`, com args nondet |

**Formato dos campos:** include paths e multi-arquivo aceitam **uma entrada por
linha**. Caminhos relativos resolvem contra a **Pasta do projeto**. Campos vazios
são ignorados (comportamento padrão).

---

## 1. include paths (`-I`)

### O que faz
Passa `-I <dir>` ao ESBMC para ele encontrar os `#include` de um arquivo que faz
parte de um projeto maior, cujos headers vivem em outras pastas. **Sem isto**, o
frontend dá `PARSING ERROR` (`fatal error: 'X.h' file not found`) **antes** de
verificar qualquer coisa.

### Quando usar
- Você aponta para **um arquivo** (ou poucos) de um projeto, mas ele inclui
  headers de `include/`, `src/`, etc.
- Não quer (nem precisa) **buildar o projeto inteiro**: funções externas sem corpo
  o ESBMC abstrai (*havoc*), então só os **headers** (tipos/protótipos) bastam.

### Quando NÃO ajuda
- Projeto **C++ de produção** (ex.: llama.cpp): mesmo com os `-I` certos, o frontend
  C++ do ESBMC **trava na STL** (`std::map`, `std::initializer_list`). `-I` resolve
  o *parse dos headers*, não a STL. ⟹ isolar a rotina (ver `--function`) é o caminho.

### Exemplo ◇ ilustrativo — uma unidade do llama.cpp (camada C do ggml)
```
Pasta do projeto:   /caminho/llama.cpp/ggml/src
include paths (-I):
    /caminho/llama.cpp/ggml/include
    /caminho/llama.cpp/ggml/src
```
Verifica `ggml-quants.c` (C puro) sem compilar todo o ggml. Headers achados → o
ESBMC checa overflow/OOB/memsafety da unidade.

### Exemplo ◇ ilustrativo — header numa subpasta do seu projeto
```
Pasta do projeto:   /meu/projeto/src
include paths (-I):  /meu/projeto/include
```

---

## 2. unidade multi-arquivo (link)

### O que faz
Em vez de verificar **um `.c` por vez** (o padrão), linka uma lista de `.c`
(`main` + dependências) numa **única unidade**, como o compilador faria. Assim as
funções das dependências têm **corpo real** — não viram *havoc*.

### Por que importa (o problema do *havoc*)
Quando um `.c` chama `f()` definida em **outro** arquivo e você verifica só o
primeiro, o ESBMC não tem o corpo de `f` e **abstrai** o retorno dela (qualquer
valor possível). Isso gera **falsos positivos**: bugs que dependem de um retorno
absurdo que a função real nunca produziria.

### Exemplo ▶ rodável — tinyexpr (o havoc em ação)
Pasta real: `/home/franklin/TrbLuccas/alvo/tinyexpr`

**Sem link (per-file, padrão):** ao verificar `example2.c` sozinho, `te_compile`
(definida em `tinyexpr.c`) fica **sem corpo** → `err` vira irrestrito → o
`err - 1` no caminho de erro estoura. *(Verificado:* `VERIFICATION FAILED`,
`arithmetic overflow on sub` em `example2.c:33`*.)* **É um artefato de
sub-restrição do havoc** — numa execução real `te_compile` nunca devolve `INT_MIN`.

**Com link (corpo real das deps):**
```
Pasta do projeto:           /home/franklin/TrbLuccas/alvo/tinyexpr
unidade multi-arquivo:
    example2.c
    tinyexpr.c
```
Agora `te_compile` tem corpo → o falso `overflow on sub` **não aparece mais** (o
havoc foi resolvido). **Porém** — e aqui está a lição dupla — `tinyexpr.c` é um
**parser recursivo-descendente**, então a unidade linkada **estoura o estado do BMC
e dá `TIMEOUT`** (verificado). Ou seja: linkar **eliminou o falso positivo** mas
**expôs a parede de tratabilidade**. Não troque um problema (havoc) por uma
ilusão de "passou": um TIMEOUT é **inconclusivo**, não SAFE.

### ⚠️ Gotcha (tratabilidade) — também rodável
```
unidade multi-arquivo:
    repl.c
    tinyexpr.c
```
`repl.c` (laço de `stdin`) + o mesmo parser recursivo → **TIMEOUT** (verificado).
Lição: linkar é **necessário mas não suficiente**; alvos BMC-tratáveis são
**C puro, laço limitado sobre buffer, sem recursão profunda** (decoders de tamanho
fixo: base64/hex/checksum/cabeçalho). Para o caso pesado, **isole uma rotina
tratável com `--function`** em vez de linkar o projeto com seu parser/`main`.

---

## 3. função-entrada (`--function`)

### O que faz
Verifica **uma função** como ponto de entrada, **sem precisar de `main`**. O ESBMC
**havoca os argumentos** (nondet) de graça — escalares viram "qualquer valor",
ponteiros viram "qualquer ponteiro". É o ingrediente nº 1 de um harness, sem
escrever harness.

### Quando usar
- Isolar **uma rotina** de um arquivo/projeto grande (ex.: o cálculo de tamanho de
  uma alocação) em vez de verificar tudo.
- O arquivo **não tem `main`** (biblioteca/módulo).

### Exemplo ▶ rodável — `sum_first_n` (sem main, args havocados)
Arquivo real: `harness_prototype/examples/sum_first_n.c` (uma função, sem `main`).
```
Pasta do projeto:    /home/franklin/TrbLuccas/harness_prototype/examples
função-entrada:      sum_first_n
```
O ESBMC entra em `sum_first_n(const int*, int)` havocando `arr` e `n`, e acha a
violação (`VERIFICATION FAILED`) sem nenhum `main`. *(Validado: é o caso do teste
`test_esbmc_function_entry_havocs_args` da suíte.)*

### ⚠️ Cuidado com a fidelidade (a parte de julgamento)
Args 100% havocados podem ser **irreais**: um ponteiro havocado é "qualquer
endereço", então o ESBMC pode acusar *invalid pointer* que um chamador real nunca
passaria. `--function` é ótimo para **triagem rápida**; para um veredito fiel,
muitas vezes você precisa de **pré-condições** (que exigem um harness escrito —
ver `harness_prototype/`). Regra prática: um BUG do `--function` é uma **pista**,
não uma prova final, até você confirmar que a entrada é alcançável.

---

## Combinações úteis

**Rotina de um projeto com headers externos** (`-I` + `--function`):
```
Pasta do projeto:    /caminho/projeto/src
include paths (-I):  /caminho/projeto/include
função-entrada:      nome_da_rotina
```

**Programa multi-arquivo verificado pela entrada certa** (link + `--function`):
```
unidade multi-arquivo:
    api.c
    core.c
função-entrada:      processa_pacote     (em vez do main interativo)
```

**Caçar overflow de tamanho (CWE-190)** — combine com o checkbox
*checar overflow unsigned* (fora da seção avançada):
```
Pasta do projeto:    /home/franklin/TrbLuccas/contexto/Outros2
função-entrada:      (deixe vazio — esses arquivos têm main)
[x] checar overflow unsigned
```
▶ rodável: `gguf_cve_2025_53630_vuln.c` tem o cálculo de tamanho vulnerável; o
overflow é `unsigned`, então **só aparece** com o checkbox ligado.

---

## Tabela de decisão rápida

| Sintoma / objetivo | Use |
|---|---|
| `PARSING ERROR: 'X.h' file not found` | **include paths (-I)** com a pasta do header |
| Bug suspeito que some "se a função vizinha fosse real" | **multi-arquivo (link)** com o `.c` da dependência |
| Arquivo **sem `main`** / quero checar **uma** função | **função-entrada (--function)** |
| Achou bug com valor de entrada **impossível** | restrinja: link (corpo real) ou harness com pré-condições |
| `TIMEOUT` ao linkar | alvo não-tratável p/ BMC — isole com `--function`, reduza o escopo |
| Overflow de `size_t`/`unsigned` (cálculo de alocação) | ligue **checar overflow unsigned** (não é desta seção) |
| Projeto **C++** de produção (STL) | nenhuma destas resolve — frontend C++ trava; isole rotina C pura |

---

## Notas finais
- Todos os campos são **opcionais**; vazios = verificação padrão (per-file, com `main`).
- Caminhos relativos resolvem contra a **Pasta do projeto**; absolutos também valem.
- O relatório (e o SARIF) registram a configuração efetiva, então dá para reproduzir.
- Fundamentação: estes campos são a peça **real** da direção "verificar código bruto";
  a geração automática de *harness* (com pré-condições/fidelidade) é roadmap futuro —
  ver `estado_e_roadmap/Harness_gap_analysis.md`.
