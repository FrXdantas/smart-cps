# SMART-JBMC — fork `smart-cps` (rv. 1.11-cps)

> **Fork de `smart-jbmc` (rv. 1.10), criado em 09/10/2026** para a disciplina
> PGENE601 (Verificação e Síntese de Sistemas Ciberfísicos e Embarcados). Roda ao
> lado do original sem conflito: imagem `smartcps`, container `smartcps`, volume
> `smartcps-dados`, porta **8100**.
>
> Correções em relação à rv. 1.10: o oráculo do reparo agora re-verifica com a
> MESMA configuração da run que achou o bug — `concurrency`, `strategy` (em C),
> `include_dirs` e `function`. Antes, uma race com código idêntico saía FIX_OK.
> Teste: `tests/test_repair_herda_config.py`. Divergências entre a especificação
> e a ferramenta: `docs/inconsistencias_especificacao.md`.

Plataforma de verificação formal (JBMC + ESBMC) com classificação CWE/CERT-C,
reparo guiado por contraexemplo (DeepSeek V4) e front-end web.

> Reescrita modular e profissional do protótipo `JBMC_Projeto.py`.
> Disciplina de Verificação de Software — Mestrado. Orientador: Prof. Lucas Cordeiro.

> **Jeito mais fácil de rodar: Docker.** Um comando (`./subir.sh`) sobe tudo,
> inclusive num computador sem internet. Veja [DOCKER.md](DOCKER.md).

## Arquitetura

```
smart-jbmc/
├── backend/smart_jbmc/      # motor de verificação + API FastAPI
│   ├── core/
│   │   ├── config.py        # resolução de ferramentas (.env → tools/ → PATH)
│   │   ├── scanner/compiler/verifiers/classify/counterexample/metrics/orchestrator
│   │   └── repair/          # heuristic.py · regression.py · llm.py · loop.py
│   └── api/                 # FastAPI: health · runs · browse · repair (sob /api)
├── frontend/                # SPA (Bootstrap, tema claro/azul) consumindo o REST
├── tools/                   # binários vendorizados opcionais (esbmc/jbmc) — não versionados
├── data/{benchmarks,runs}/  # entradas e saídas de cada execução
├── docs/                    # INSTALL.pdf (guia de instalação) + fontes
├── tests/                   # pytest
├── .env / .env.example      # caminhos das ferramentas + chave DeepSeek (NÃO versionar .env)
├── requirements.txt · pyproject.toml
```

- **Backend:** FastAPI (REST sob `/api`, docs em `/api/docs`).
- **Front-end:** SPA estática (HTML/JS/Bootstrap) servida em `/`, consome o REST.
- Backend e front-end são **desacoplados** (CORS habilitado).

## Instalação

O guia completo está em **[`docs/INSTALL.pdf`](docs/INSTALL.pdf)** (ferramentas externas,
projeto, configuração e portabilidade). Resumo:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # ajuste os caminhos das ferramentas para a sua máquina

cd backend
uvicorn smart_jbmc.api.app:app --reload --port 8000
```

Abra <http://localhost:8000> (SPA) e <http://localhost:8000/api/docs> (API).

## Configuração de ferramentas (`.env`)

Cada ferramenta externa é resolvida em **3 níveis de prioridade**, o que torna o
projeto portátil entre máquinas:

1. **`.env`** — caminho explícito (ex.: `ESBMC_PATH=/home/.../esbmc`);
2. **`tools/`** — binário copiado dentro do projeto (auto-detectado);
3. **`PATH`** — fallback no sistema.

```ini
ESBMC_PATH=/home/franklin/esbmc/bin/esbmc
JBMC_PATH=/usr/bin/jbmc
KOTLINC_PATH=/home/franklin/.sdkman/candidates/kotlin/current/bin/kotlinc
DEEPSEEK_API_KEY=          # só para o reparo-LLM (etapa futura)
DEEPSEEK_MODEL=deepseek-v4-flash
```

O endpoint `/api/health` reporta, para cada ferramenta, se está disponível, o caminho
resolvido e a origem (`env` / `vendored` / `path`).

## Levar para outro computador

Copie a pasta `smart-jbmc/` **sem** `.venv/`, `tools/` e `.env`. Na nova máquina:
instale as ferramentas (ver `docs/INSTALL.pdf`), recrie o `.env` com os caminhos locais
e rode `pip install -r requirements.txt`. Em outra máquina **Linux x86_64 igual**, os
binários `esbmc`/`jbmc` podem ser copiados para `tools/` e são detectados sem `.env`
(o `kotlinc` sempre exige o SDK Kotlin + JRE instalados).

## Uso da interface

Abra <http://localhost:8000>. No topo, o card **Ambiente** mostra quais ferramentas
foram encontradas. Em **Nova verificação**:

- **Pasta** — digite o caminho ou clique em **Procurar** para navegar pelos diretórios
  da máquina (mostra subpastas e quantos arquivos-fonte há em cada pasta).
- Clique **Verificar** — uma **barra de progresso** mostra a fase (escanear → compilar →
  verificar) e os alvos concluídos em tempo real.
- Os **Resultados** trazem o resumo (BUG/SAFE/TIMEOUT/ERROR + CASTLE Score), a
  distribuição CWE e a tabela de alvos; clique num alvo para ver o **contraexemplo**.
- O **Histórico** lista as runs; clicar abre o relatório (o item ativo fica destacado e
  o cabeçalho dos resultados identifica a run).

### Parâmetros de verificação

| Parâmetro | Mín | Máx | O que faz | Implicação |
|-----------|----:|----:|-----------|-----------|
| **unwind** | 1 | ~100 | Limite de desenrolamento de loops (bound do BMC) | ↑ explora loops mais fundo → mais confiança, porém mais lento e mais memória. ↓ rápido, mas pode não alcançar bugs profundos (BMC é incompleto além do bound). Típico: 5–20. |
| **timeout** | 1 s | 3600 s | Tempo máximo do solver por alvo | ↑ menos `TIMEOUT` em alvos difíceis, porém run mais demorada. ↓ corta alvos pesados cedo. Típico: 30–120. |
| **jobs** | 1 | nº de núcleos | Verificações em paralelo | ↑ mais rápido em multi-core, porém usa mais CPU/RAM. `1` = sequencial (bom para depurar). |
| **solver** | — | — | Backend SMT do ESBMC | `boolector`: rápido, bit-blasting (padrão); `z3`: forte em aritmética/teorias; `mathsat`: interpolação. O JBMC usa MiniSat (independe desta opção). |

## Reparo guiado por contraexemplo (a contribuição de pesquisa)

Depois de uma verificação com bugs, a SPA mostra **"Reparar bugs"**. O ciclo:

```
BUG + contraexemplo → [LLM (DeepSeek V4) propõe patch] → grava *_FIXED
        ▲                                                      │
        │                                                      ▼
   novo contraexemplo ◀──────── [JBMC/ESBMC re-verifica] ──── FIX_OK?
   (realimenta a LLM)                    │                       │
                                    (refina: ↓ unwind)           ▼
                                                       patch FORMALMENTE VALIDADO
```

- O **verificador é o oráculo**: só conta como reparado (`FIX_OK`) o que o BMC prova
  `SAFE`. Patches que não fecham (`STILL_VULNERABLE`) ou abrem outro bug
  (`DIFFERENT_BUG`) realimentam o **novo contraexemplo** para a próxima iteração.
- **Métricas** (a tabela-headline do artigo): taxa de reparo verificado e iterações
  médias, por categoria — a comparar com o baseline heurístico.
- **`dry-run`** (chave `dry_run` / switch na SPA): executa todo o loop **sem chamar a
  API** (não consome saldo), útil para testar a fiação. O reparo real precisa de
  `DEEPSEEK_API_KEY` no `.env` e saldo na conta DeepSeek.
- REST: `POST /api/repair {run_id, max_iters, unwind, timeout, solver, dry_run}` e
  `GET /api/repair/{run_id}`.

> Posicionamento: o EVA (Prof. Cordeiro) faz *detecção* orquestrada por LLM; este
> reparo verificado é o passo seguinte — para onde o *future work* do próprio artigo
> aponta — aplicado nativamente a Java/Kotlin/C.

## Roadmap

1. ✅ **Esqueleto + slice vertical** (`/api/health` + SPA) — concluído
2. ✅ **Configuração portátil de ferramentas** (`core/config.py`, `.env`) — concluído
3. ✅ **Motor `core`** (scanner, compiler, verifiers JBMC/ESBMC, classify CWE/CERT) — concluído, paridade testada
4. ✅ **Análise + regressão + métricas** (contraexemplo, explicação, CASTLE Score, reparo heurístico, ciclo de regressão) — concluído, 22/22 testes
   - ⏳ pendência curta: geração de testes unitários (templates JUnit/C)
5. ✅ **Orquestração + API REST** (`core/orchestrator.py`, `POST/GET /api/runs`, persistência em `data/runs/<id>/`) — concluído, 26/26 testes
6. ✅ **SPA completa** (formulário de run, barra de progresso real animada, resultados, distribuição CWE, detalhe do alvo com contraexemplo, histórico) — concluído
7. ✅ **Reparo guiado por contraexemplo (DeepSeek V4)** (`core/repair/{llm,loop}.py`, `POST /api/repair`, botão na SPA com dry-run) — concluído

## Requisitos externos

`jbmc` (suite CBMC), `esbmc` ≥ 8, `javac`, `kotlinc`, `java`, `gcc`.
Versões testadas e instruções de instalação: **[`docs/INSTALL.pdf`](docs/INSTALL.pdf)**.
