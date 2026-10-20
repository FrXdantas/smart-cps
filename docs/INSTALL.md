# SMART-JBMC — Guia de Instalação (máquina nova)

Plataforma de verificação formal (JBMC + ESBMC) com classificação CWE/CERT-C e
reparo guiado por contraexemplo. Este guia foi escrito para **levantar o sistema
do zero em uma máquina Linux x86_64** (testado: Linux Mint 22.2 / Ubuntu 24.04).

> Versão em PDF/LaTeX equivalente: [`INSTALL.pdf`](INSTALL.pdf) / [`INSTALL.tex`](INSTALL.tex).

---

## 0. Estado desta máquina (conferido em 2026-05-28)

| Ferramenta | Necessário | Estado aqui | Ação |
|---|---|---|---|
| `python3` ≥ 3.10 | sim | `3.12.3` | ok |
| `pip` | sim | `24.0` | ok |
| `gcc` | só p/ C | `13.3.0` | ok |
| `javac` + `java` (JDK ≥ 17) | sim p/ JVM | OpenJDK `17.0.19` | ok (guia oficial cita 21, mas 17 atende) |
| `esbmc` ≥ 8 | sim p/ C | `8.3.0` em `~/opt/esbmc/bin/esbmc` | instalado |
| `jbmc` (suíte CBMC ≥ 6) | sim p/ JVM | `6.9.0` em `/usr/bin/jbmc` | instalado |
| `kotlinc` | só p/ Kotlin | `2.3.21` em `~/.sdkman/candidates/kotlin/current/bin/kotlinc` | instalado |
| GPU NVIDIA + Ollama | só p/ LLM local | RTX 5070 12 GB + Ollama `0.18.2` | instalado |
| `deepseek-coder-v2:16b` | só p/ LLM local | 8.9 GB baixado | instalado |

Como o projeto resolve cada ferramenta em **3 níveis** (`.env` → `tools/` → `PATH`),
basta deixar o caminho correto em **um** desses lugares.

---

## 1. Requisitos de sistema

- Linux x86_64 (Ubuntu 24.04 / Linux Mint 22.x ou equivalente).
- Python 3.10+ com `venv`.
- Acesso `sudo` (para `apt install` e instalar a suíte CBMC).
- Internet (downloads do ESBMC, CBMC e SDKMAN).

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential curl unzip zip
```

---

## 2. Obter o projeto

O projeto **já está** em `/home/iartes/TrbLuccas/smart-jbmc/` nesta máquina. Se
precisar levar para outra:

```bash
# em outra máquina, copie a pasta SEM .venv/, tools/ e .env
rsync -a --exclude='.venv' --exclude='tools' --exclude='.env' \
      smart-jbmc/ usuario@destino:~/TrbLuccas/smart-jbmc/
```

---

## 3. Instalar as ferramentas externas

### 3.1 ESBMC (verificação de C)

Baixe a release Linux x86_64 oficial e descompacte em um diretório estável:

```bash
mkdir -p ~/opt && cd ~/opt
# Verifique a versão mais recente em https://github.com/esbmc/esbmc/releases
# Exemplo (ajuste a URL para a release atual):
curl -L -o esbmc.zip \
  https://github.com/esbmc/esbmc/releases/download/v8.6/esbmc-linux.zip
unzip -q esbmc.zip && mv release esbmc   # o zip do 8.6 traz a pasta release/
chmod +x ~/opt/esbmc/bin/esbmc

~/opt/esbmc/bin/esbmc --version    # esperado: ESBMC version 8.x ...
```

Anote o caminho: `~/opt/esbmc/bin/esbmc` (você vai colocá-lo no `.env` na §5).

### 3.2 JBMC (verificação de Java/Kotlin, parte da suíte CBMC)

O `jbmc` **vem na suíte CBMC** (Diffblue), separada do ESBMC.

```bash
# Verifique a release atual em https://github.com/diffblue/cbmc/releases
cd /tmp
curl -L -O https://github.com/diffblue/cbmc/releases/download/cbmc-6.9.0/ubuntu-24.04-cbmc-6.9.0-Linux.deb
sudo apt install -y ./ubuntu-24.04-cbmc-6.9.0-Linux.deb

jbmc --version    # esperado: 6.9.0 (cbmc-6.9.0)
which jbmc        # esperado: /usr/bin/jbmc
```

> Linux Mint 22.2 é baseado em Ubuntu 24.04 — o pacote `.deb` para 24.04 funciona.

### 3.3 Kotlin (`kotlinc`) — via SDKMAN

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install kotlin

kotlinc -version   # esperado: kotlinc-jvm 2.x.x (JRE 17/21...)
which kotlinc      # ex.: /home/iartes/.sdkman/candidates/kotlin/current/bin/kotlinc
```

> Pode pular se você **não** for verificar alvos Kotlin.

### 3.4 (Opcional) Atualizar para JDK 21

A versão de referência do guia é JDK 21; o JDK 17 atual atende. Se quiser alinhar:

```bash
sudo apt install -y openjdk-21-jdk
sudo update-alternatives --config java    # selecione o 21
sudo update-alternatives --config javac
```

---

## 4. Instalar as dependências Python

```bash
cd /home/iartes/TrbLuccas/smart-jbmc

# Já existe .venv/ aqui — para reaproveitar:
source .venv/bin/activate
pip install -r requirements.txt

# Ou recriar do zero:
# rm -rf .venv && python3 -m venv .venv && source .venv/bin/activate
# pip install -U pip && pip install -r requirements.txt

# (opcional) extras de desenvolvimento (pytest, httpx):
pip install -e '.[dev]'
```

Dependências mínimas (de `requirements.txt`): `fastapi`, `uvicorn[standard]`,
`requests`, `pydantic`, `python-multipart`.

---

## 5. Configurar o `.env`

Copie o modelo e preencha com os caminhos **desta máquina**:

```bash
cd /home/iartes/TrbLuccas/smart-jbmc
cp -n .env.example .env       # -n: não sobrescreve um .env já presente
```

Edite `.env` com algo equivalente a:

```ini
# Caminhos das ferramentas (ajuste para o que você instalou na §3)
ESBMC_PATH=/home/iartes/opt/esbmc/bin/esbmc
JBMC_PATH=/usr/bin/jbmc
KOTLINC_PATH=/home/iartes/.sdkman/candidates/kotlin/current/bin/kotlinc

# JAVAC_PATH / JAVA_PATH / GCC_PATH normalmente vêm do PATH — deixe em branco.

# Reparo guiado por LLM (DeepSeek V4) — só para a etapa de repair
DEEPSEEK_API_KEY=
DEEPSEEK_MODEL=deepseek-v4-flash
```

> **Segurança**: o `.env` **não** é versionado (está no `.gitignore`). Nunca
> compartilhe a chave da API.

### Resolução em 3 níveis (lembrete)

Para cada ferramenta, o sistema tenta nesta ordem:

1. caminho explícito em `.env` (`ESBMC_PATH`, `JBMC_PATH`, …);
2. binário copiado em `smart-jbmc/tools/<nome>`;
3. `PATH` do sistema (`which esbmc`, etc.).

Isso é o que torna o projeto portátil entre máquinas.

---

## 5.1 Autenticação (servidor de intranet)

A API é protegida por sessão (cookie HttpOnly) para humanos e por **API key
Bearer** para clientes programáticos. `/api/health` fica aberto; tudo o mais
exige autenticação.

### Bootstrap do admin inicial

```bash
cd /home/iartes/TrbLuccas/smart-jbmc
source .venv/bin/activate
pip install -q bcrypt          # dep nova; já está em requirements.txt

# Cria o primeiro usuário (papel admin). Sem --password, pergunta interativamente.
python tools/smart-jbmc-admin.py create-admin franklin
```

Arquivos criados pelo backend na primeira execução:
- `data/auth.db` — SQLite com tabelas `users` e `login_history`.
- `data/.session_secret` — segredo HMAC do cookie (chmod 600, gerado se
  `SESSION_SECRET` não estiver no `.env`).

### Variáveis opcionais no `.env`

```ini
# Cookie de sessão (assinatura HMAC). Se ausente, é gerado em data/.session_secret.
SESSION_SECRET=

# Marque como Secure quando rodar atrás de HTTPS/reverse proxy. Em HTTP plain, deixe 0.
AUTH_COOKIE_SECURE=0
```

### Usando o CLI admin

```bash
python tools/smart-jbmc-admin.py list                      # listar usuários
python tools/smart-jbmc-admin.py add-user aluno1           # criar usuário comum
python tools/smart-jbmc-admin.py add-user gerente --role admin
python tools/smart-jbmc-admin.py rotate-key 2              # gera/rotaciona API key (mostrada UMA vez)
python tools/smart-jbmc-admin.py revoke-key 2              # revoga
python tools/smart-jbmc-admin.py delete 3                  # exclui usuário
python tools/smart-jbmc-admin.py history --limit 50        # auditoria de logins
```

### Endpoints REST de autenticação

| Endpoint | Quem | O que faz |
|---|---|---|
| `POST /api/auth/login` | aberto | `{login, password}` → cookie HttpOnly |
| `POST /api/auth/logout` | aberto | apaga o cookie |
| `GET  /api/auth/me` | logado | identidade do usuário corrente |
| `GET  /api/auth/users` | admin | lista usuários |
| `POST /api/auth/users` | admin | cria usuário |
| `DELETE /api/auth/users/{id}` | admin | exclui |
| `POST /api/auth/users/{id}/api-key` | admin | gera/rotaciona API key |
| `DELETE /api/auth/users/{id}/api-key` | admin | revoga |
| `GET  /api/auth/history` | admin | últimos logins (com IP/UA) |

### Cliente programático (CLI / "pacote de teste")

As máquinas clientes na intranet usam a API key:

```bash
curl -H "Authorization: Bearer sjk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
     http://servidor:8000/api/runs
```

A key é mostrada **uma única vez** no momento da emissão (ou via `rotate-key`).
O servidor guarda apenas o hash bcrypt.

### Telas

- `http://servidor:8000/login.html` — login (2 colunas: ilustração bug+lupa, formulário).
- `http://servidor:8000/` — painel principal (redireciona pro login se não autenticado).
- `http://servidor:8000/admin.html` — só admin: Usuários + Histórico de logins.

---

## 5.3 Upload de pasta (cliente → servidor)

A SPA `/api/browse` lista o disco **do servidor**, então máquinas clientes da
intranet não enxergam o disco delas. Para essas máquinas, o painel oferece um
botão **"Enviar pasta"** que faz o upload da pasta selecionada para o servidor
antes de lançar a verificação.

### Como o usuário usa

1. Em `http://<servidor>:8000`, no card **Nova verificação**, clica em
   **☁ Enviar pasta**.
2. O picker do navegador abre permitindo escolher uma **pasta inteira**
   (Chrome/Firefox/Edge/Safari modernos).
3. A SPA filtra para `.c`, `.java`, `.kt`, envia via multipart com barra de
   progresso (% e KB/MB) e popula automaticamente o campo **Pasta** com o
   caminho que o servidor gerou em `data/uploads/<id>/`.
4. Clicar em **Verificar** roda normalmente sobre esses arquivos.

O botão **"Procurar no servidor"** (antigo "Procurar") continua disponível
para o admin local apontar para benchmarks já no disco do servidor.

### Endpoint REST (clientes programáticos)

```bash
# multipart: campos files (arquivos) e paths (caminhos relativos correspondentes)
curl -H "Authorization: Bearer <api-key>" \
     -F "files=@projeto/src/Foo.java" \
     -F "files=@projeto/main.c" \
     -F "paths=projeto/src/Foo.java" \
     -F "paths=projeto/main.c" \
     http://<servidor>:8000/api/uploads
# resposta: {"upload_id","folder","count","total_bytes"}

# em seguida, dispare a run com o folder devolvido:
curl -H "Authorization: Bearer <api-key>" -H "Content-Type: application/json" \
     -d '{"folder":"/.../data/uploads/<id>","unwind":5,"timeout":60,"jobs":4}' \
     http://<servidor>:8000/api/runs
```

### Limites (configuráveis no `.env`)

```ini
UPLOAD_MAX_FILES=5000               # padrão
UPLOAD_MAX_BYTES=524288000          # padrão = 500 MB
```

### Retenção

Os uploads vivem em `data/uploads/<owner_id>/<upload_id>/` (subpasta por
usuário) até o cliente clicar em **Limpar histórico** na SPA (ou chamar
`DELETE /api/runs`). A limpeza atinge **apenas os dados do próprio
usuário** — runs e uploads de outros não são tocados.

### Segurança

- Caminhos relativos são sanitizados: `..`, `/absolutos` e caracteres fora
  de `[A-Za-z0-9._\-/]` são recusados (HTTP 400).
- O endpoint exige autenticação (cookie ou Bearer); usuário anônimo recebe 401.
- O arquivo é gravado em chunks de 1 MB e o limite de tamanho é checado durante
  o stream — passar do limite aborta e remove a pasta parcial.

---

## 5.4 Isolamento por usuário (intranet multiusuário)

Cada usuário **só enxerga os próprios dados** — runs, reparos e uploads
ficam estritamente isolados. Isso vale **inclusive para o admin**: o papel
`admin` dá privilégio sobre gestão de contas e `/api/browse`, **não** "vê
tudo de todos".

### O que está separado

| Recurso | Como é isolado |
|---|---|
| `data/runs/<id>/run.json` | gravado com `owner_id` e `owner_login`. |
| `GET /api/runs` | retorna **só** as runs cujo `owner_id == current_user.id`. |
| `GET /api/runs/{id}` / `cancel` / `sarif` | retorna **404** se a run não for do usuário. |
| `POST /api/repair` / `GET /api/repair/{id}` | só se a run subjacente for do usuário. |
| `DELETE /api/runs` (Limpar histórico) | só apaga runs+uploads **do usuário**. |
| `data/uploads/<owner_id>/<upload_id>/` | subpasta exclusiva por usuário. |
| `POST /api/runs` (campo `folder`) | user comum **só pode** apontar para `data/uploads/<id_dele>/...`; outro caminho → **HTTP 403**. |
| `/api/browse` | exige papel **admin** (vaza estrutura do servidor); 403 para `user`. |
| SPA: botão **"Procurar no servidor"** | escondido para `user` (só admin vê). |

### Como subir mais usuários

```bash
# no servidor
python tools/smart-jbmc-admin.py add-user aluno1                 # papel "user"
python tools/smart-jbmc-admin.py add-user gerente --role admin   # outro admin

# clientes acessam http://<servidor>:8000/login.html com login+senha próprios.
# Cada um faz "Enviar pasta" → roda → vê só o histórico dele.
```

### Verificar isolamento (rápido)

```bash
BASE=http://10.208.2.168:8000
curl -s -c /tmp/cA -X POST -H "Content-Type: application/json" \
     -d '{"login":"aluno1","password":"…"}'  $BASE/api/auth/login
curl -s -c /tmp/cB -X POST -H "Content-Type: application/json" \
     -d '{"login":"aluno2","password":"…"}'  $BASE/api/auth/login

curl -s -b /tmp/cA $BASE/api/runs   # mostra só as runs do aluno1
curl -s -b /tmp/cB $BASE/api/runs   # mostra só as runs do aluno2
```

---

## 5.2 LLM local de reparo (Ollama na GPU do servidor)

O reparo guiado por contraexemplo aceita qualquer provedor OpenAI-compatível.
Quando o cliente **não tem chave externa**, o sistema usa **Ollama** rodando
local na GPU do servidor. Aparece como provedor **"Local (Ollama, GPU desta
máquina)"** na janela _Configurar LLM_ da SPA.

### Instalar Ollama

```bash
# (Linux) instalação oficial
curl -fsSL https://ollama.com/install.sh | sh

# Sobe automaticamente como serviço systemd em http://localhost:11434
systemctl --user status ollama   # ou: systemctl status ollama
```

### Baixar o modelo padrão

```bash
ollama pull deepseek-coder-v2:16b   # ~8.9 GB, MoE, cabe em 12 GB de VRAM
# alternativas:
# ollama pull qwen2.5:14b           # ~9 GB, mais rápido
# ollama pull qwen3-coder:30b       # ~18 GB, NÃO cabe em 12 GB (offload p/ CPU)
```

### Requisitos de GPU

Testado: NVIDIA RTX 5070 (12 GB VRAM, driver 580.159, CUDA 13.0). Em GPU menor,
escolha um modelo `7b` (~4.7 GB) em vez de 16 B.

### Usar no painel

No SPA, clique em **Configurar LLM** e selecione **"Local (Ollama, GPU desta
máquina)"**:

- `base_url` fica **fixo e readonly** em `http://localhost:11434/v1`.
- Campo `API key` é desabilitado (Ollama não exige).
- O campo **Modelo** vira um **`<select>` dropdown** populado em runtime por
  `GET /api/llm/local/status` — lista **exatamente** o que `ollama list`
  retorna no servidor (sem nada chumbado no JS).
- Pré-seleção: o primeiro modelo cujo nome contenha "deepseek" ou "coder",
  senão o primeiro da lista.

### Adicionar novos modelos

Quando o admin baixar mais modelos no servidor, eles aparecem
**automaticamente** no dropdown da próxima vez que o cliente abrir a
janela de configuração — não precisa mexer no código nem reiniciar nada
da SPA.

```bash
# no servidor:
ollama pull qwen2.5-coder:32b
ollama pull codellama:13b
ollama list                       # confirma

# no cliente: reabre Configurar LLM → o select mostra os novos modelos.
```

### "Localhost" significa o servidor — não o PC do cliente

Confusão comum: o cliente vê `localhost:11434` no campo Base URL e pensa que
a SPA vai tentar chamar um Ollama **na máquina dele**. Não é o caso —
quem dispara a request HTTP é o **backend**, que roda no servidor. Logo,
`localhost` = máquina servidora = Ollama. **Nenhum cliente precisa ter
Ollama instalado.**

Para deixar isso óbvio na interface, o painel mostra esses elementos quando
o provider é `local`:

- aviso sob a Base URL: *"Endereço fixo: o reparo é executado pelo servidor,
  que chama o seu próprio Ollama."*
- texto sob o select de Provider: *"Sem custo, sem chave. O reparo roda na
  GPU do servidor."*
- bandeira verde/vermelha indicando se o `/api/llm/local/status` reportou
  `available=true`.

### Endpoint REST de diagnóstico

```bash
curl -H "Authorization: Bearer <api-key>" \
     http://<servidor>:8000/api/llm/local/status
# -> {"available": true, "base_url": "http://localhost:11434/v1",
#     "models": ["deepseek-coder-v2:16b","qwen2.5:14b",...]}
```

### Diagnóstico

```bash
ollama list           # modelos baixados
ollama ps             # modelo carregado em GPU e VRAM em uso
curl -s http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"deepseek-coder-v2:16b","messages":[{"role":"user","content":"ping"}]}' \
  | python3 -m json.tool
```

---

## 5.5 Patches comentados inline (`// <--- corrigido aqui:`)

Cada patch gerado pelo LLM (`<arquivo>_FIXED.{c,java,kt}`) traz um comentário
**na linha exata da correção** indicando o que foi alterado e por quê,
no formato:

```
// <--- corrigido aqui: <razão curta com CWE/CERT-C>
```

Funciona em **C, Java e Kotlin** (todas as três usam `//`). Quando a mudança
ocupa várias linhas contíguas (ex.: um bloco `if`), só a primeira linha leva
a marca. `#include`/`import` novo é marcado na própria linha do include.

### Como é garantido

1. **Prompt do reparo** (`core/repair/llm.py` → `SYSTEM_PROMPT`, regra #5)
   exige a marca em toda linha alterada, citando o CWE/CERT-C que veio no
   contexto e **proibindo outros comentários explicativos**.
2. **Normalização determinística pós-LLM** (`_strip_fences()`): modelos
   menores às vezes geram `<--`, `<-`, `<-----`. Um regex
   (`<-{1,6}\s*corrigido aqui`) normaliza tudo para `<---` antes de gravar
   o patch.

### Exemplos reais (deepseek-coder-v2:16b)

```c
int main(){
    int a = INT_MAX, b = 1;
    // <--- corrigido aqui: guard de overflow (CWE-190 / ARITHMETIC_OVERFLOW)
    if ((a > 0 && b > 0 && a + b <= 0) || (a < 0 && b < 0 && a + b >= 0)) {
        return INT_MAX;
    }
    return a + b;
}
```

```java
public class Foo {
    public static int get(int[] a, int i) {
        if (i < 0 || i >= a.length) { // <--- corrigido aqui: guard de OOB (CWE-787 / ARR30-C)
            throw new IndexOutOfBoundsException("Index out of bounds");
        }
        return a[i];
    }
}
```

```kotlin
// <--- corrigido aqui: CWE-476 NULL Pointer Dereference (EXP34-C)
fun len(s: String?): Int {
    if (s == null) {
        return 0
    }
    return s.length
}
```

### Encontrar todas as correções com `grep`

```bash
grep -n 'corrigido aqui' data/uploads/<id>/<projeto>_FIXED.*
# ou, em toda a árvore de uma run:
grep -rn 'corrigido aqui' data/runs/<run_id>/repairs/
```

### Garantia (oráculo)

As marcas só aparecem em patches que o verificador (BMC) provou seguros
(`FIX_OK`). Patches que falharam (`STILL_VULNERABLE` ou `DIFFERENT_BUG`)
são realimentados ao LLM, mas não viram arquivo `*_FIXED` final.

---

## 6. Subir o servidor

### 6.1 Modo desenvolvimento (só local)

```bash
cd /home/iartes/TrbLuccas/smart-jbmc
source .venv/bin/activate
uvicorn smart_jbmc.api.app:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Abra no navegador:

- SPA: <http://localhost:8000>
- API docs (Swagger): <http://localhost:8000/api/docs>

### 6.2 Modo intranet (outras máquinas da rede acessam)

Por padrão o uvicorn escuta só em `127.0.0.1`. Para clientes da intranet,
escute em `0.0.0.0`:

```bash
uvicorn smart_jbmc.api.app:app --app-dir backend --host 0.0.0.0 --port 8000
```

Descubra o IP do servidor na rede e use nas máquinas clientes:

```bash
hostname -I            # ex.: 10.208.2.168 172.17.0.1
ip -br -4 addr show    # detalhe por interface
```

URLs para as máquinas clientes (substitua pelo IP/hostname real):

- Navegador: `http://10.208.2.168:8000/login.html`
- API: `http://10.208.2.168:8000/api/runs` com `Authorization: Bearer <api-key>`

Se houver firewall, libere a porta:

```bash
# UFW (Ubuntu/Mint)
sudo ufw allow 8000/tcp
sudo ufw status

# firewalld (Fedora/RHEL)
sudo firewall-cmd --add-port=8000/tcp --permanent && sudo firewall-cmd --reload
```

### 6.3 Rodar como serviço (systemd) — sobe no boot

Recomendado para o servidor de intranet. Cria um serviço **systemd usuário**
que sobe sozinho, reinicia em caso de crash e registra log em
`data/server.log`. Com `loginctl enable-linger`, sobe mesmo sem ninguém
logado.

Crie `~/.config/systemd/user/smart-jbmc.service`:

```ini
[Unit]
Description=SMART-JBMC backend (FastAPI/uvicorn)
After=network-online.target ollama.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/iartes/TrbLuccas/smart-jbmc
ExecStart=/home/iartes/TrbLuccas/smart-jbmc/.venv/bin/uvicorn smart_jbmc.api.app:app --app-dir backend --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=3
StandardOutput=append:/home/iartes/TrbLuccas/smart-jbmc/data/server.log
StandardError=append:/home/iartes/TrbLuccas/smart-jbmc/data/server.log

[Install]
WantedBy=default.target
```

Ative:

```bash
systemctl --user daemon-reload
systemctl --user enable --now smart-jbmc.service
sudo loginctl enable-linger "$USER"    # subir no boot sem precisar de login

systemctl --user status smart-jbmc     # confirmar
```

Comandos do dia a dia:

```bash
systemctl --user restart smart-jbmc    # após editar código
systemctl --user stop smart-jbmc
systemctl --user disable smart-jbmc    # tirar do boot
journalctl --user -u smart-jbmc -f     # logs em tempo real
tail -f data/server.log
```

> Importante: depois disso, **não mate o `uvicorn` à mão** — o systemd
> respawna. Use sempre `systemctl --user restart smart-jbmc`.

---

## 7. Validar a instalação

### 7.1 Endpoint `/api/health`

Cada ferramenta deve aparecer com `"available": true`:

```bash
curl -s http://localhost:8000/api/health | python3 -m json.tool
```

Na SPA, o card **Ambiente** mostra os badges verdes e o caminho ao passar o mouse.

### 7.2 Suíte de testes

```bash
cd /home/iartes/TrbLuccas/smart-jbmc
source .venv/bin/activate
python -m pytest -q
```

### 7.3 Verificação real

Na SPA, em **Nova verificação** → **Procurar** → escolha uma pasta com fontes
(ex.: um dos benchmarks em `data/benchmarks/`) → **Verificar**.

---

## 8. Parâmetros principais da verificação

| Parâmetro | Faixa | O que faz |
|---|---|---|
| `unwind` | 1 – ~100 | Bound do BMC (loops). Maior = mais confiança, mais lento. Típico 5–20. |
| `timeout` | 1 s – 3600 s | Limite do solver por alvo. Típico 30–120. |
| `jobs` | 1 – nº de núcleos | Paralelismo. `1` = sequencial (debug). |
| `solver` | `boolector` / `z3` / `mathsat` | Backend SMT do ESBMC. `boolector` é o padrão. JBMC usa MiniSat. |

---

## 9. Reparo guiado por contraexemplo (DeepSeek V4)

Após uma verificação com bugs, a SPA mostra **Reparar bugs**. O ciclo:
`BUG + contraexemplo → LLM propõe patch → JBMC/ESBMC re-verifica → FIX_OK ou
novo contraexemplo realimenta a LLM`. Requisitos:

- `DEEPSEEK_API_KEY` preenchido no `.env` e saldo na conta DeepSeek.
- `DEEPSEEK_MODEL`: `deepseek-v4-flash` (padrão, econômico) ou `deepseek-v4-pro`.
- **`dry-run`** (interruptor na tela): roda o loop completo **sem** chamar a API
  — útil para validar a fiação sem gastar.

Endpoints REST: `POST /api/repair` e `GET /api/repair/{run_id}`.

---

## 10. Problemas comuns

| Sintoma | Solução |
|---|---|
| `jbmc` aparece como indisponível | Instale a suíte CBMC (§3.2) e/ou defina `JBMC_PATH` no `.env`. |
| `kotlinc` indisponível | Instale via SDKMAN (§3.3); aponte `KOTLINC_PATH` para `…/kotlin/current/bin/kotlinc`. |
| `Address already in use` na porta 8000 | `pkill -f "uvicorn smart_jbmc"` ou suba com `--port 8001`. |
| SPA carrega mas mostra "offline" | O backend não subiu — veja o terminal do `uvicorn`. |
| Pylance/VSCode não acha `fastapi` | Selecione o interpretador do `.venv` no editor. |
| `apt install ./...cbmc...deb` falha por dependências | `sudo apt --fix-broken install` e repita. |
| ESBMC reclama de libs ao rodar | Use a release `linux-static` ou instale `libgomp1`. |
| Cliente faz upload e recebe HTTP `413` | Tamanho/quantidade excede limite — ajuste `UPLOAD_MAX_BYTES` ou `UPLOAD_MAX_FILES` no `.env` e reinicie. |
| Upload diz "nenhum arquivo .c/.java/.kt" | A SPA filtra por extensão antes de enviar; confira se a pasta selecionada tem fontes suportadas. |
| Botão "Enviar pasta" não abre o picker | Use Chrome/Firefox/Edge/Safari atuais (depende de `webkitdirectory`). |
| Botão "Reparar bugs" abre o modal "Configurar LLM" em vez de iniciar | Caso resolvido em 2026-05-28: a checagem de `api_key` agora pula `provider=local`. Force-reload do navegador (Ctrl+Shift+R) para pegar o JS novo. |
| Provider "Local" diz "Ollama indisponível no servidor" | No servidor: `systemctl status ollama` (ou `ollama serve`) e `ollama list` para conferir que tem modelos. O backend testa `GET http://localhost:11434/api/tags` com timeout 2s. |

---

## 11. Checklist rápido (TL;DR)

```bash
# 1. Dependências do SO
sudo apt update && sudo apt install -y python3-venv build-essential curl unzip

# 2. ESBMC
mkdir -p ~/opt && cd ~/opt
curl -L -o esbmc.zip https://github.com/esbmc/esbmc/releases/download/v8.6/esbmc-linux.zip
unzip -q esbmc.zip && mv release esbmc && chmod +x ~/opt/esbmc/bin/esbmc

# 3. CBMC/JBMC
cd /tmp
curl -L -O https://github.com/diffblue/cbmc/releases/download/cbmc-6.9.0/ubuntu-24.04-cbmc-6.9.0-Linux.deb
sudo apt install -y ./ubuntu-24.04-cbmc-6.9.0-Linux.deb

# 4. Kotlin (opcional)
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh" && sdk install kotlin

# 5. Projeto
cd /home/iartes/TrbLuccas/smart-jbmc
source .venv/bin/activate || (python3 -m venv .venv && source .venv/bin/activate)
pip install -r requirements.txt
cp -n .env.example .env   # depois edite os *_PATH

# 6. Admin inicial
python tools/smart-jbmc-admin.py create-admin franklin

# 7. (opcional) LLM local de reparo
curl -fsSL https://ollama.com/install.sh | sh
ollama pull deepseek-coder-v2:16b

# 8. Subir (intranet) — escuta em todas as interfaces
uvicorn smart_jbmc.api.app:app --app-dir backend --host 0.0.0.0 --port 8000
# ou, em produção, ative o systemd unit da §6.3:
#   systemctl --user enable --now smart-jbmc.service
#   sudo loginctl enable-linger "$USER"

# 9. Validar (do servidor e de uma máquina cliente)
hostname -I                                              # descobrir o IP
curl -s http://localhost:8000/api/health | python3 -m json.tool
# e abra no navegador da outra máquina: http://<IP>:8000/login.html
```
