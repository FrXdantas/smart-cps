# SMART-CPS

Verificação formal de código com conserto por IA, conferido pelo verificador.
Revisão 1.11-cps.

Trabalho da disciplina **PGENE601 / PPGINF554, Verificação e Síntese Automática
de Sistemas Ciberfísicos e Embarcados** (UFAM, 2026/2), feito sob a supervisão do
Prof. Lucas Cordeiro.


## Égua, mas o que é isso?

Olha, maninho, é assim. Tu tens um código em C, Java ou Kotlin e queres saber se
ele tem bug escondido: divisão por zero, acesso fora do vetor, estouro de número,
ponteiro nulo, essas leseiras.

O SMART-CPS pega teu código e entrega para dois verificadores formais, o ESBMC
(para C) e o JBMC (para Java e Kotlin). Eles não ficam no "acho que tá certo":
testam todos os caminhos possíveis até um limite e, se acharem o bug, mostram o
contraexemplo, que é o passo a passo com os valores que fazem o programa cair.

Aí vem a parte pai d'égua:

1. O sistema mostra o bug e diz qual é o tipo dele (CWE, a classificação oficial
   de falhas de segurança).
2. Se tu quiseres, uma IA tenta consertar o código usando o contraexemplo.
3. O conserto não vale só porque a IA disse. O verificador roda de novo no
   código consertado. Só se ele provar que o bug sumiu é que sai `FIX_OK`.
4. Se a IA tentar dar um jeitinho, tipo apagar o teste ou deixar o trecho com bug
   sem nunca ser executado, as guardas pegam e o resultado vira `INVALID_PATCH`.
   Aqui não tem conversa de pescador.

Tudo isso por uma página no navegador, com login, histórico das verificações e
relatório para baixar.


## Do que tu precisas

Só do Docker. Mais nada. Nem Python, nem Java, nem ESBMC: tudo isso já vem
dentro da imagem, nas versões certas.

| Sistema | O que instalar |
|---|---|
| Linux | Docker Engine (`sudo apt install docker.io`) |
| Windows | Docker Desktop, com WSL2 ligado |
| Mac | Docker Desktop (em Mac M1/M2/M3 roda, mas devagar, porque emula) |

O computador precisa ser x86_64 (os PCs comuns) e ter pelo menos 8 GB de RAM.
O verificador é guloso que só.


## Como instalar, no passo a passo

### 1. Baixar o projeto

O repositório é privado, então tua conta do GitHub precisa ter sido convidada.

```bash
git clone https://github.com/FrXdantas/smart-cps.git
cd smart-cps
```

### 2. Construir a imagem (só na primeira vez, precisa de internet)

No Linux ou no Mac:

```bash
./smartcps.sh construir
```

No Windows (abre o PowerShell dentro da pasta):

```powershell
docker build -t smartcps:1.11-cps .
```

Vai baixar as ferramentas e montar tudo. Demora uns minutos, então vai tomar um
café com tapioquinha que já volta.

### 3. Subir o sistema

No Linux ou no Mac:

```bash
./subir.sh
```

No Windows, dá dois cliques no `subir.bat`.

### 4. Abrir no navegador

> **http://localhost:8100**
>
> usuário **`admin`**, senha **`admin123`**

Troca essa senha logo no primeiro acesso, não deixa assim não.

Pronto, tá no ar.


## O Docker, explicado sem frescura

Pensa no Docker como uma caixa de isopor fechada. Dentro dela já vai o peixe,
o gelo e o limão: o sistema, o ESBMC, o JBMC, o Java, o Kotlin e o Python, tudo
nas versões que foram testadas juntas. Tu não precisas instalar nada disso no teu
computador, só abrir a caixa.

Três nomes que tu vais ver por aí:

* Imagem (`smartcps:1.11-cps`): é a caixa montada, pronta para usar. Tu
  constrói uma vez.
* Container (`smartcps`): é a caixa aberta, rodando. É ele que atende no
  `localhost:8100`.
* Volume (`smartcps-dados`): é onde ficam guardados os usuários, as
  verificações e os relatórios. Fica fora do container, então tu podes parar,
  apagar e subir de novo que não perde nada.

### Os comandos do dia a dia

| Comando | O que faz |
|---|---|
| `./subir.sh` | sobe o sistema |
| `./subir.sh parar` | para (os dados ficam guardados) |
| `./subir.sh status` | diz se tá no ar e mostra as versões |
| `./subir.sh logs` | mostra o que tá acontecendo, ao vivo (Ctrl+C sai) |
| `./subir.sh admin add-user ana` | cria um usuário novo |
| `./subir.sh backup` | salva os dados num arquivo `.tar.gz` |
| `./subir.sh restaurar <arquivo>` | traz os dados de volta de um backup |
| `./subir.sh testes` | roda os testes automáticos dentro do container |

Quer outra porta? `PORTA=8080 ./subir.sh`.

### E num computador sem internet?

Também dá. Num PC com internet roda `./smartcps.sh tudo`. Isso cria a pasta
`dist/smartcps-offline/`, com a imagem inteira dentro (uns 900 MB). Copia essa
pasta para um pendrive, leva para o outro PC e lá dentro roda `./subir.sh` (ou
dois cliques no `subir.bat`). Funciona até no meio do rio, sem sinal.

O detalhe completo está no [DOCKER.md](DOCKER.md).


## E a IA do conserto?

A verificação funciona 100% offline. O conserto precisa de uma IA, e tu
escolhes qual:

* DeepSeek, na nuvem: copia `smartcps.env.exemplo` para `smartcps.env`, põe
  tua chave em `DEEPSEEK_API_KEY` e sobe de novo. Precisa de internet.
* Ollama, no teu PC: instala o Ollama, baixa um modelo (por exemplo
  `qwen2.5-coder:7b`) e escolhe "Local (Ollama)" na tela. No Linux, sobe com
  `OLLAMA_NO_PC=1 ./subir.sh`.
* Sem IA nenhuma: liga o dry-run. Ele roda o caminho todo sem chamar IA,
  só para ver se a engrenagem está girando.

O `smartcps.env` tem senha e chave, então nunca vai para o git. Isso já está
garantido no `.gitignore`.


## Deu ruim? Calma, mano

| O que aparece | O que fazer |
|---|---|
| `permission denied` no Docker (Linux) | `sudo usermod -aG docker $USER`, sai da sessão e entra de novo |
| `o Docker não está rodando` | Linux: `sudo systemctl start docker`. Windows/Mac: abre o Docker Desktop e espera ficar verde |
| A porta 8100 já está ocupada | `PORTA=8200 ./subir.sh` |
| A verificação demorou e deu `TIMEOUT` | Aumenta o `timeout` na tela, ou diminui o `unwind` |
| O PC ficou lento que só | Usa `jobs = 1`. O teto de memória já vem ligado (70% da RAM) |


## Onde fica cada coisa

```
smart-cps/
├── backend/        o motor: verificação, classificação, conserto e a API
├── frontend/       a página que tu abres no navegador
├── tests/          os testes automáticos
├── docs/           documentação técnica
├── Dockerfile      a receita da caixa de isopor
├── subir.sh        sobe o sistema (Linux/Mac)
├── subir.bat       sobe o sistema (Windows)
└── smartcps.sh     constrói a imagem e o pacote offline
```

Para ir mais fundo:

* [docs/README_tecnico.md](docs/README_tecnico.md): arquitetura, parâmetros da
  verificação e como rodar sem Docker.
* [DOCKER.md](DOCKER.md): tudo sobre o Docker e o pacote offline.
* [docs/INSTALL.pdf](docs/INSTALL.pdf): instalação manual das ferramentas.
* [docs/inconsistencias_especificacao.md](docs/inconsistencias_especificacao.md):
  onde a especificação e a ferramenta ainda não batem.


## Créditos

Trabalho acadêmico da disciplina PGENE601 / PPGINF554 (UFAM, 2026/2), sob a
supervisão do Prof. Lucas Cordeiro.

As ferramentas de verificação usadas aqui são o
[ESBMC](https://github.com/esbmc/esbmc) e o
[CBMC/JBMC](https://github.com/diffblue/cbmc), cada uma com a sua licença.
