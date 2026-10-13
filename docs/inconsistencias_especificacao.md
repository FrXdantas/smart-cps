# Inconsistências da especificação × ferramenta real

Documento conferido: `contexto/Outros 3/SMART_ESBMC_JBMC.pdf` (especificação, out/2026).
Base de comparação: o código da rv. 1.10 (`smart-jbmc/`) e o que foi medido e
registrado no projeto. Conferido em 09/10/2026.

Este documento **só aponta** onde o texto e a ferramenta divergem, com a evidência
de cada caso. Como corrigir o texto, ou qual dos dois lados mudar, fica a cargo dos
autores (ver as diretrizes de uso de LLM do professor, na mesma pasta).

Legenda de gravidade:
- 🔴 afeta a validade de um resultado ou de uma pergunta de pesquisa;
- 🟠 promessa que a ferramenta não cumpre hoje;
- 🟡 dado desatualizado.

---

## 🔴 1. "FP = 0 reportado em versões preliminares" pode ser efeito de um defeito

**p. 10:** *"FP = 0 reportado em versões preliminares é verificação de sanidade
(consequência da soundness para refutação), não mérito do pipeline."*

**Real:** até 02/08/2026, `core/metrics.py → infer_oracle_from_path` só reconhecia
pastas `/bug/` e `/safe/`, em inglês. Os corpora usam `com_bug/` e `sem_bug/`, então o
gabarito **nunca foi lido**. A matriz saía `tp=tn=fp=fn=0` em **todas** as 23 runs de
28/05 a 02/08. Um FP = 0 tirado da matriz desse período não mede nada; a explicação
pela soundness pode até ser verdadeira, mas não vem desse número.

**Conferir:** de que run e de que data saiu o FP = 0 citado, e se foi contado à mão
ou lido da matriz.

## 🔴 2. Os "32 patches aceitos / 23 editam a implementação" são de uma versão com três defeitos já corrigidos

**p. 1 e p. 12:** *"a auditoria dos 32 patches aceitos revela que apenas 23 editam a
implementação"*.

**Real:** antes de 02/08/2026, a ferramenta:
- aceitava como reparo a asserção reescrita (`assert false` → `assert true`), o
  `assume` novo e o defeito tornado inalcançável;
- não modelava `java.util.Random` no JBMC, o que **rejeitava o reparo correto** e
  aceitava a guarda redundante;
- antes de 30/07, reparava o **arquivo errado** em projetos com vários arquivos.

O 32/23 pode estar certo como fotografia daquela versão, mas não descreve a ferramenta
atual. **Conferir** de qual versão e de qual data ele veio.

## 🔴 3. A RQ2 e a H2 medem algo que a rv. 1.10 já não deixa acontecer

**p. 4 (RQ2) e p. 9 (H2):** *"Entre os patches aceitos pelo BMC (FIX_OK até bound k),
qual a proporção que [...] satisfaz o oráculo por meios espúrios"*; H2 espera ≥ 20%.

**Real:** desde a rv. 1.10, três guardas (`core/repair/loop.py` e
`core/repair/reachability.py`) rejeitam esses patches como **`INVALID_PATCH`
antes** de virarem FIX_OK. Com as guardas ligadas, a proporção de contornos entre os
FIX_OK tende a zero **por construção**, e não porque a LLM deixou de contornar.

O dado que mede a mesma coisa hoje é a contagem de `INVALID_PATCH` e o motivo de cada
um, nos `attempts`. A outra forma é rodar com as guardas apenas registrando, sem
bloquear. É uma decisão de desenho experimental.

## 🔴 4. A taxonomia de contornos tem duas categorias, e já encontramos quatro

**p. 8 (§4.3) e p. 10 (E3):** reparo real × *"contorno por asserção enfraquecida"* ×
*"contorno por restrição de pré-condição"*.

**Real**, com casos que passaram como REPARADO:
1. asserção reescrita (TC13 `== 44` → `== 43`; athrow1 `assert false` → `assert true`);
2. `assume` / `assume_abort_if_not` inserido (caso SV-COMP);
3. **defeito tornado inalcançável**: `if (y == 0) return 0` com `y = 0` constante
   (TC4), ou `if (100 in arr.indices)` num array de 2 posições (TC6). Não é nenhuma das
   duas categorias da especificação: não mexe em asserção nem em `assume`;
4. **troca de constante** (TC12 × TC14): estruturalmente idênticas; uma é reparo e a
   outra é contorno, e nada no código as separa automaticamente.

## 🔴 5. "Re-invocado com a mesma estratégia da execução original": falso para C

**p. 8 (§4.2, item 3):** *"o BMC é re-invocado com a mesma estratégia da execução
original"*.

**Real:** só na via JVM. Em C, `core/repair/regression.py → _verify_fixed_c` **não
recebe** a estratégia: o patch é sempre re-verificado em `bounded`, mesmo que a run
tenha usado `sound` ou `kinduction`. Na prática, um patch em C pode ser aprovado por um
SAFE vazio (o laço passou do bound), que é justamente o falso negativo da §1.2 (iii).
**Corrigido no fork `smart-cps`.**

## 🔴 6. Condição de corrida "reparada" sem mudar o código

Não está no texto, mas afeta qualquer resultado de concorrência em C.

**Real:** a verificação aceita `concurrency` (`--data-races-check`), mas o oráculo do
reparo não herda essa opção. Teste feito em 09/10: um C com duas threads fazendo `x++`
dá **BUG / Race Condition**; o reparo em dry-run (código **idêntico**) dá
**REPAIRED / FIX_OK**. **Corrigido no fork `smart-cps`.**

## 🟠 7. Seeds e top-p não existem na ferramenta

**p. 9–10:** *"temperatura 0,2; top-p 0,95; seeds 42, 123, 456, 789, 1024 (cinco
execuções independentes por programa)"*.

**Real:** `core/repair/llm.py` fixa só `temperature=0.2`. Não há `top_p` nem `seed` no
payload enviado à API, e o código não tem nenhum mecanismo de repetir a execução com
seeds diferentes. Também é preciso conferir se o provedor (DeepSeek) aceita `seed`.

## 🟠 8. "Detecção de ciclo" no laço de reparo não existe

**p. 7 (Figura 1) e p. 8 (§4.2):** *"com teto de cinco iterações e detecção de
ciclo"*; *"O laço termina ao atingir FIX_OK, ao detectar ciclo, ou ao esgotar o teto"*.

**Real:** `core/repair/loop.py` para no FIX_OK ou no teto de iterações. Não há
comparação com patches anteriores. O próprio estudo de ablação registra o sintoma: a
T = 0,2 o braço cego repete o mesmo patch, gastando 5 chamadas com o efeito de 1.

## 🟠 9. O grupo B ("stack trace") não é o que o estudo de ablação implementa

**p. 9 (Tabela 4):** grupo B = BMC + *"stack trace"*, para isolar o efeito do
contraexemplo.

**Real:** `estudo_ablacao/ferramenta/backend/smart_jbmc/core/repair/ablacao.py` tem
os braços `guiado`, `cego_cwe` (só a categoria CWE, sem contraexemplo) e `cego_total`.
Nenhum deles manda stack trace. E o estudo vive num **clone separado**, não na
ferramenta principal.

## 🟠 10. "Grupos D, E", mas o grupo D não existe

**p. 10–11 (E5):** *"baselines externos (grupos D, E)"*. A Tabela 4 (p. 9) define A, B,
C, C′ e E. O grupo D não aparece em nenhum outro lugar.

## 🟠 11. Os vereditos do oráculo são sete, não cinco

**p. 7:** *"Os quatro vereditos de saída do laço"*. **p. 8:** *"um dos cinco vereditos
(Tabela 3)"*. Ou seja, o próprio texto diz quatro numa página e cinco na outra.

**Real:** além de FIX_OK, STILL_VULNERABLE, DIFFERENT_BUG, TIMEOUT e ERROR, a
ferramenta produz **`INVALID_PATCH`** (as guardas) e **`PROVIDER_ERROR`** (cota/429,
excluído das métricas).

## 🟠 12. "14 categorias da CWE Top-25"

**p. 6 (§3.4):** *"uma das 14 categorias da CWE Top-25 [21] cobertas pela tabela
interna"*.

**Real:** `core/classify.py` tem **13 entradas**: 12 CWEs mais `CWE-Other`. Delas,
só **5** têm posição no Top-25 no próprio código (787, 125, 416, 476 e 369).
CWE-190, 401, 415, 833, 362, 617 e 248 estão com `top25_rank: None`.

## 🟡 13. Versões e ambiente desatualizados

| Página | Texto | Real |
|---|---|---|
| p. 11 | *"ESBMC 8.2.0 e JBMC 5.12 instalados"* | **cbmc/jbmc 6.9.0**. A paridade com 6.9.0 é requisito: o parser de contraexemplo foi validado contra ela, e o apt do Ubuntu traz 5.95.1 |
| p. 7 e p. 10 | *"implementado em Python 3.11"* | `pyproject.toml` pede ≥ 3.10; o Docker usa **3.12** |
| p. 10 | *"hardware uniformizado (Intel i7-1165G7, 16 GB RAM)"* | o servidor usado era **i7-8550U, 12 GB**, e está desligado. A RAM interessa porque o teto de memória do JBMC é rateado por ela |
| p. 9 | *"bound k = 10 [...] timeout 30 s para Java/Kotlin e 20 s para C"* | os padrões da ferramenta são `unwind 5` e `timeout 60/120`. Não é erro, mas o roteiro de execução tem de passar esses valores explicitamente |
| — | o manual do professor é do **ESBMC 8.5.0** (solver padrão Bitwuzla) | usamos 8.2.0 (padrão Boolector). Os comandos do manual podem dar vereditos diferentes aqui |

## 🟡 14. Corpora: dados a confirmar antes de citar

- **"452 programas"** (p. 1, 3 e 11): não consegui conferir. Os corpora foram apagados
  de `data/` em 02/08 e o servidor está desligado. Conferir a contagem numa fonte.
- **"Kotlin TC0–TC20"** (p. 3): o braço cego acertou 20 de 21 em **uma** iteração
  (efeito de teto). Esse corpus não consegue separar os grupos B e C da H1.
- **"Doze dos vinte alvos Java vêm de jbmc-regression"** (p. 10): não conferido.
- **JBMC não verifica overflow de inteiro** (no JVM o wraparound é definido). A
  especificação não declara essa limitação; ela afeta qualquer comparação Java × C
  por categoria de defeito.
- **Coleções `java.util` são havocadas** pelo JBMC: nesses casos até o código correto
  dá BUG, e nenhum patch chega a FIX_OK. Também não está declarado.

## Fora do escopo da lista, mas relevante

A especificação não toca **sistemas ciberfísicos nem embarcados**, que são o tema da
disciplina (critério 1 da avaliação, 0,5 ponto). Ver as opções de expansão discutidas
à parte.
