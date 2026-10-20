# SMART ESBMC / JBMC — rodar com Docker (inclusive sem internet)

Tudo o que a verificação precisa já vem dentro da imagem, nas **mesmas versões
do servidor de produção**:

| Ferramenta | Versão |
|---|---|
| ESBMC (C) | 8.6.0 — solvers boolector, z3, bitwuzla |
| cbmc / jbmc (Java, Kotlin) | 6.9.0 |
| OpenJDK (javac/java) | 21 |
| Kotlin (kotlinc) | 2.3.21 |
| Python + FastAPI | 3.12 |

No computador de destino só precisa ter o **Docker** instalado. Não é preciso
instalar Python, Java, ESBMC nem nada mais, e não é preciso internet.

---

## 1. Subir num computador (o caso comum)

Copie a pasta `smartcps-offline/` (pendrive, rede, etc.) e, dentro dela:

**Linux / macOS**

```bash
./subir.sh
```

**Windows** (com o Docker Desktop aberto): dê dois cliques em `subir.bat`.

Na primeira vez ele carrega a imagem do arquivo `smartcps-imagem.tar.gz`
(1–2 minutos); nas próximas sobe em segundos. Depois abra:

> **http://localhost:8100** — login **`admin`**, senha **`admin123`**

Troque a senha padrão logo no primeiro acesso (tela de administração), ou
defina outra **antes** do primeiro uso em `smartcps.env` (ver seção 3).

O sistema volta sozinho se o computador reiniciar (enquanto o Docker estiver
ativo). Para parar: `./subir.sh parar`.

### Comandos do `subir.sh`

| Comando | O que faz |
|---|---|
| `./subir.sh` | sobe (e carrega a imagem na 1ª vez) |
| `./subir.sh parar` | para; os dados continuam guardados |
| `./subir.sh logs` | log ao vivo (Ctrl+C sai) |
| `./subir.sh status` | se está no ar + versões das ferramentas |
| `./subir.sh testes` | roda a suíte de testes (113) dentro do container |
| `./subir.sh admin add-user ana` | cria usuário (pede a senha) |
| `./subir.sh admin list` | lista usuários |
| `./subir.sh backup` | salva usuários/runs/uploads em `smartcps-dados-<data>.tar.gz` |
| `./subir.sh restaurar <arquivo>` | restaura um backup |
| `./subir.sh remover` | apaga o container (os dados **ficam**) |

Outra porta: `PORTA=8080 ./subir.sh` (no Windows, edite `set PORTA=` no `subir.bat`).

---

## 2. Onde ficam os dados

Usuários, runs, uploads e SARIFs ficam no **volume Docker `smartcps-dados`**,
não dentro do container. Por isso dá para parar, remover e atualizar a imagem
sem perder nada. Para levar os dados a outro computador: `./subir.sh backup`
lá, copiar o `.tar.gz`, `./subir.sh restaurar <arquivo>` cá.

Apagar **tudo**, inclusive os dados (irreversível):
`docker rm -f smartcps && docker volume rm smartcps-dados`.

---

## 3. Configuração opcional (`smartcps.env`)

Copie `smartcps.env.exemplo` para `smartcps.env` e ajuste. Esse arquivo tem
senha e chave: **nunca vai para o git**.

- `ADMIN_LOGIN` / `ADMIN_PASSWORD`: admin criado **só no primeiro uso**.
- `PORTA`: porta no seu computador.
- `DEEPSEEK_API_KEY`: reparo pela LLM na nuvem (**precisa de internet**).
- `SMART_JBMC_MAX_MEM_TOTAL_MB`: teto de memória dos verificadores. Vazio =
  70% da RAM. Existe porque, sem teto, o JBMC já chegou a 26 GB num caso e
  travou a máquina.

---

## 4. Reparo por LLM sem internet (Ollama)

A **verificação** (ESBMC/JBMC) é 100% offline. O **reparo** precisa de uma LLM:

- **Com internet:** chave DeepSeek no `smartcps.env`.
- **Sem internet:** Ollama instalado no próprio computador, com um modelo já
  baixado (ex.: `qwen2.5-coder:7b`). Na tela de reparo escolha **Local (Ollama)**.
  - **Linux:** o `./subir.sh` já sobe o container na rede do próprio PC, e ele
    enxerga o Ollama em `localhost:11434` sem precisar reconfigurá-lo. Se o
    container foi criado por uma versão anterior, rode `./subir.sh remover` e
    `./subir.sh`. Para voltar à rede isolada, `OLLAMA_NO_PC=0 ./subir.sh`; nesse
    caso, e também com `docker compose`, o Ollama precisa escutar em `0.0.0.0`.
  - **Windows / macOS:** funciona direto (o container acessa o Ollama do PC
    por `host.docker.internal`).

Modelos locais pequenos (7B) reparam bem menos que a DeepSeek. As guardas
rejeitam como `INVALID_PATCH` o "reparo" que só esconde o defeito (por exemplo,
um `if` que torna a divisão inalcançável). Isso é esperado.

Sem LLM nenhuma, o botão de reparo funciona em **dry-run** (testa a fiação
sem chamar IA).

---

## 5. Gerar o pacote offline (máquina COM internet)

Na pasta do projeto (`smart-jbmc/`):

```bash
./smartcps.sh tudo
```

Isso **constrói** a imagem (baixa cbmc 6.9.0, Kotlin 2.3.21 e, se esta máquina
não tiver, o ESBMC 8.6) e **exporta** para `dist/smartcps-offline/`:

```
dist/smartcps-offline/
├── smartcps-imagem.tar.gz   ← a imagem inteira (~900 MB)
├── SHA256SUMS               ← confira com: sha256sum -c SHA256SUMS
├── subir.sh                 ← Linux / macOS
├── subir.bat                ← Windows
├── smartcps.env.exemplo
└── LEIA-ME.md               ← este guia
```

Copie essa pasta inteira para o pendrive. Também dá para rodar em etapas:
`./smartcps.sh construir` e depois `./smartcps.sh exportar`.

Se o computador tiver o ESBMC 8.6.0 em `~/esbmc/bin/esbmc` (ou no PATH),
o `construir` usa **esse** binário (paridade exata com o servidor). Senão, baixa
o release oficial 8.6 do GitHub, que é a mesma versão com os mesmos solvers.

### Sem script (Docker puro)

```bash
docker build -t smartcps:2.1-cps .
docker run -d --name smartcps -p 8100:8000 -v smartcps-dados:/app/data smartcps:2.1-cps
```

ou `docker compose up -d` (usa o `docker-compose.yml`).

---

## 6. Limitações conhecidas

- **Imagem x86_64 (amd64).** O ESBMC só tem binário Linux x86_64. Em Mac com
  chip Apple (M1/M2/M3) roda por emulação, bem mais lento.
- **Windows:** precisa do Docker Desktop com WSL2.
- Linux: se der "permission denied" no Docker, rode
  `sudo usermod -aG docker $USER`, saia da sessão e entre de novo.
