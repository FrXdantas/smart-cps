# SMART-CPS: documentação técnica

Revisão 2.2-cps. Este documento complementa o [README](../README.md) principal e
descreve a arquitetura, a execução sem Docker, a configuração das ferramentas e o
ciclo de reparo.

Trabalho da disciplina PGENE601 / PPGINF554 (UFAM, 2026/2), sob a supervisão do
Prof. Lucas Cordeiro.


## Origem

O SMART-CPS deriva do SMART ESBMC/JBMC (rv. 1.10), plataforma de verificação formal
com JBMC e ESBMC, classificação CWE/CERT-C, reparo guiado por contraexemplo e
interface web. A derivação foi criada em 09/10/2026 e roda ao lado da versão
original sem conflito: imagem `smartcps`, container `smartcps`, volume
`smartcps-dados` e porta 8100.

Em relação à rv. 1.10, o oráculo de reparo passou a reverificar o código corrigido
com a mesma configuração da verificação que encontrou o defeito, incluindo
`concurrency`, `strategy` (em C), `include_dirs` e `function`. Antes dessa
correção, uma condição de corrida com o código inalterado era aceita como
`FIX_OK`. O teste correspondente está em `tests/test_repair_herda_config.py`.

As divergências conhecidas entre a especificação do projeto e a ferramenta estão
em [inconsistencias_especificacao.md](inconsistencias_especificacao.md).


## Arquitetura

```
smart-cps/
├── backend/smart_jbmc/
│   ├── core/            motor de verificação
│   │   ├── config.py          resolução das ferramentas (.env, tools/, PATH)
│   │   ├── scanner.py         localização dos arquivos-fonte e alvos
│   │   ├── compiler.py        compilação Java/Kotlin para bytecode
│   │   ├── verifiers/         chamadas ao JBMC e ao ESBMC
│   │   ├── classify.py        classificação CWE/CERT-C
│   │   ├── counterexample.py  leitura do contraexemplo
│   │   ├── metrics.py         métricas da verificação
│   │   ├── sarif.py           relatório no formato SARIF
│   │   ├── orchestrator.py    coordenação de uma verificação completa
│   │   └── repair/            heuristic, llm, loop, regression, reachability
│   ├── api/             API REST (FastAPI), sob /api
│   └── auth/            autenticação e usuários
├── frontend/            interface web (HTML, JavaScript, Bootstrap)
├── tests/               testes automatizados (pytest)
├── docs/                documentação
└── tools/               binários opcionais do ESBMC/JBMC (não versionados)
```

O backend expõe uma API REST sob `/api`, e a interface web, servida em `/`, consome
essa API. As duas partes são independentes.


## Execução sem Docker

A forma recomendada de execução é o Docker, descrita no [README](../README.md) e em
[DOCKER.md](../DOCKER.md). Para executar diretamente na máquina, é preciso instalar
as ferramentas externas listadas ao final deste documento. O guia completo está em
[INSTALL.pdf](INSTALL.pdf).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # ajustar os caminhos das ferramentas

cd backend
uvicorn smart_jbmc.api.app:app --port 8000
```

A interface fica disponível em http://localhost:8000.


## Configuração das ferramentas

Cada ferramenta externa é localizada em três níveis de prioridade, o que permite
levar o projeto entre máquinas diferentes:

1. `.env`: caminho explícito, por exemplo `ESBMC_PATH=/opt/esbmc/bin/esbmc`;
2. `tools/`: binário copiado para dentro do projeto, detectado automaticamente;
3. `PATH`: ferramenta instalada no sistema.

```ini
ESBMC_PATH=/opt/esbmc/bin/esbmc
JBMC_PATH=/usr/bin/jbmc
KOTLINC_PATH=/opt/kotlinc/bin/kotlinc
DEEPSEEK_MODEL=deepseek-v4-flash
```

O endpoint `/api/health` informa, para usuários autenticados, se cada ferramenta foi
encontrada, o caminho resolvido e a origem (`env`, `vendored` ou `path`).

Para levar o projeto a outro computador sem Docker, copia-se a pasta sem `.venv/`,
`tools/` e `.env`, instalam-se as ferramentas na máquina de destino e recria-se o
`.env`. Em máquinas Linux x86_64 equivalentes, os binários `esbmc` e `jbmc` podem ser
copiados para `tools/`. O `kotlinc` exige sempre o SDK Kotlin e uma JRE instalados.


## Uso da interface

Na tela inicial, o painel Ambiente mostra quais ferramentas foram encontradas. Em
Nova verificação:

* Pasta: caminho do projeto, digitado ou escolhido pelo botão Procurar, que mostra
  as subpastas e a quantidade de arquivos-fonte em cada uma. Também é possível
  enviar arquivos.
* Verificar: inicia a verificação. Uma barra de progresso mostra a fase atual
  (leitura, compilação, verificação) e os alvos concluídos.
* Resultados: resumo (BUG, SAFE, TIMEOUT, ERROR e CASTLE Score), distribuição por
  CWE e tabela de alvos. Cada alvo abre o respectivo contraexemplo.
* Histórico: lista das verificações anteriores, com download do relatório e do
  SARIF.

### Parâmetros de verificação

| Parâmetro | Faixa | Função | Efeito |
|---|---|---|---|
| unwind | 1 a cerca de 100 | limite de desenrolamento dos laços | valores maiores exploram laços mais profundos, com mais tempo e memória; valores menores são rápidos, mas podem não alcançar defeitos profundos. Usual: 5 a 20 |
| timeout | 1 a 3600 s | tempo máximo do solver por alvo | valores maiores reduzem resultados `TIMEOUT` em alvos difíceis; valores menores encerram alvos pesados mais cedo. Usual: 30 a 120 |
| jobs | 1 ao número de núcleos | verificações em paralelo | mais rapidez em processadores com vários núcleos, com maior uso de memória; `1` executa em sequência |
| solver | boolector, z3, mathsat | solver SMT do ESBMC | `boolector` é o padrão e o mais rápido; `z3` é mais forte em aritmética; `mathsat` oferece interpolação. O JBMC usa o MiniSat, independentemente desta opção |


## Reparo guiado por contraexemplo

Após uma verificação com defeitos, a interface oferece a opção Reparar. O ciclo é:

```
defeito + contraexemplo ──> modelo de linguagem propõe correção ──> arquivo *_FIXED
        ^                                                                │
        │                                                                v
  novo contraexemplo <──────── verificador analisa a correção ─────── resultado
```

O verificador é o oráculo: a correção só é aceita quando ele prova que o defeito
deixou de existir. Os resultados possíveis são:

| Resultado | Significado |
|---|---|
| `FIX_OK` | a correção foi provada pelo verificador |
| `STILL_VULNERABLE` | o defeito permanece; o novo contraexemplo alimenta a próxima tentativa |
| `DIFFERENT_BUG` | a correção introduziu outro defeito |
| `INVALID_PATCH` | a correção apenas esconde o defeito (verificação removida, código tornado inalcançável) |
| `TIMEOUT` | a reverificação excedeu o tempo limite |
| `ERROR` | falha de compilação ou de execução da ferramenta |
| `PROVIDER_ERROR` | falha na comunicação com o modelo de linguagem |

São feitas até 5 tentativas por alvo. O modo de simulação (`dry_run`) percorre o
ciclo completo sem chamar o modelo de linguagem, o que permite testar o
funcionamento sem custo. O reparo real exige a chave do próprio usuário,
informada em "Configurar LLM", ou um modelo local pelo Ollama. O servidor não guarda
chave compartilhada.

Endpoints: `POST /api/repair` (parâmetros `run_id`, `max_iters`, `unwind`, `timeout`,
`solver`, `dry_run`), `GET /api/repair/{run_id}` e `POST /api/repair/{run_id}/cancel`.


## Testes

```bash
pytest tests/
```

Com Docker: `./subir.sh testes`. A suíte executa sem acesso à internet.


## Requisitos externos (execução sem Docker)

`jbmc` (CBMC 6.9.0), `esbmc` 8.6.0, `javac` e `java` (OpenJDK 21), `kotlinc` 2.3.21,
`gcc` e Python 3.12. Instruções de instalação em [INSTALL.pdf](INSTALL.pdf).
