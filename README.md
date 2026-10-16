# SMART-CPS

Verificação formal de código com reparo automático conferido pelo próprio verificador.
Revisão 1.11-cps.

Trabalho desenvolvido na disciplina PGENE601 / PPGINF554, Verificação e Síntese
Automática de Sistemas Ciberfísicos e Embarcados (UFAM, 2026/2), sob a supervisão
do Prof. Lucas Cordeiro.


## O que é

O SMART-CPS é uma ferramenta que procura defeitos em programas escritos em C, Java
e Kotlin, como divisão por zero, acesso fora dos limites de um vetor, estouro de
valores numéricos e uso de ponteiro nulo.

Para isso, o código é entregue a dois verificadores formais: o ESBMC, para C, e o
JBMC, para Java e Kotlin. Diferente de um teste comum, que experimenta apenas
alguns valores de entrada, o verificador analisa todos os caminhos possíveis do
programa até um limite definido pelo usuário. Quando encontra um defeito, ele
apresenta o contraexemplo, isto é, a sequência de passos e de valores que leva o
programa ao erro.

O funcionamento segue quatro etapas:

1. O verificador encontra o defeito e a ferramenta o classifica segundo o CWE,
   catálogo padronizado de falhas de software.
2. A pedido do usuário, um modelo de linguagem (LLM) propõe uma correção a partir
   do contraexemplo.
3. A correção só é aceita se o verificador, executado novamente sobre o código
   corrigido, provar que o defeito deixou de existir. Nesse caso o resultado é
   `FIX_OK`.
4. Correções que apenas escondem o defeito, como remover a verificação ou tornar
   o trecho defeituoso inalcançável, são rejeitadas com o resultado
   `INVALID_PATCH`.

Todo o uso é feito por uma página no navegador, com controle de acesso, histórico
das verificações e relatórios para download.


## Requisitos

É necessário apenas o Docker. Python, Java, ESBMC, JBMC e as demais ferramentas
já estão incluídos na imagem, nas versões em que foram testados em conjunto.

| Sistema | O que instalar |
|---|---|
| Linux | Docker Engine (`sudo apt install docker.io`) |
| Windows | Docker Desktop, com o WSL2 habilitado |
| macOS | Docker Desktop (em processadores Apple M1/M2/M3 funciona por emulação, com desempenho menor) |

Recomenda-se um computador com processador x86_64 e pelo menos 8 GB de memória,
pois a verificação formal consome bastante memória.


## Instalação

### 1. Obter o código

O repositório é privado, portanto a conta do GitHub precisa ter sido convidada.

```bash
git clone https://github.com/FrXdantas/smart-cps.git
cd smart-cps
```

### 2. Construir a imagem

Este passo é feito apenas uma vez e exige conexão com a internet, pois as
ferramentas de verificação são baixadas durante a construção. Leva alguns minutos.

Linux ou macOS:

```bash
./smartcps.sh construir
```

Windows (PowerShell, dentro da pasta do projeto):

```powershell
docker build -t smartcps:1.11-cps .
```

### 3. Iniciar o sistema

Linux ou macOS:

```bash
./subir.sh
```

Windows: executar o arquivo `subir.bat` com dois cliques.

### 4. Acessar

Abrir no navegador o endereço http://localhost:8100 e entrar com o usuário
`admin` e a senha `admin123`. Recomenda-se trocar a senha no primeiro acesso.


## Sobre o Docker

O Docker permite distribuir um sistema junto com tudo de que ele precisa para
funcionar. Em vez de instalar cada ferramenta no computador, instala-se apenas o
Docker, e o sistema roda isolado, sempre com as mesmas versões, em qualquer máquina.

Três termos aparecem com frequência:

* Imagem (`smartcps:1.11-cps`): o pacote pronto, com o sistema e todas as
  ferramentas. É construída uma única vez.
* Container (`smartcps`): a imagem em execução. É ele que atende no endereço
  `localhost:8100`.
* Volume (`smartcps-dados`): o espaço onde ficam guardados os usuários, as
  verificações e os relatórios. Fica separado do container, de modo que o sistema
  pode ser parado, removido e iniciado novamente sem perda de dados.

### Comandos principais

| Comando | Função |
|---|---|
| `./subir.sh` | inicia o sistema |
| `./subir.sh parar` | interrompe o sistema, mantendo os dados |
| `./subir.sh status` | informa se o sistema está em execução e as versões das ferramentas |
| `./subir.sh logs` | exibe o registro de execução em tempo real (Ctrl+C encerra) |
| `./subir.sh admin add-user <login>` | cria um novo usuário |
| `./subir.sh backup` | salva os dados em um arquivo `.tar.gz` |
| `./subir.sh restaurar <arquivo>` | restaura os dados a partir de um backup |
| `./subir.sh testes` | executa os testes automatizados dentro do container |

Para usar outra porta: `PORTA=8080 ./subir.sh`.

### Uso em computador sem internet

Em uma máquina com internet, o comando `./smartcps.sh tudo` gera a pasta
`dist/smartcps-offline/`, que contém a imagem completa (cerca de 900 MB). Essa
pasta pode ser copiada para outro computador, onde basta executar `./subir.sh`
(ou `subir.bat` no Windows). Nenhuma conexão é necessária.

Os detalhes estão em [DOCKER.md](DOCKER.md).


## Reparo por modelo de linguagem

A verificação funciona inteiramente sem internet. O reparo depende de um modelo de
linguagem, com três opções:

* DeepSeek (serviço na nuvem): copiar `smartcps.env.exemplo` para `smartcps.env`,
  preencher `DEEPSEEK_API_KEY` e reiniciar o sistema. Requer internet.
* Ollama (modelo local): instalar o Ollama, baixar um modelo, por exemplo
  `qwen2.5-coder:7b`, e selecionar "Local (Ollama)" na tela de reparo. No Linux,
  o `./subir.sh` já usa a rede do próprio PC para enxergar o Ollama; se o sistema
  foi iniciado por uma versão anterior, executar `./subir.sh remover` e depois
  `./subir.sh`.
* Modo de simulação (dry-run): percorre todo o ciclo de reparo sem chamar nenhum
  modelo, útil para testar o funcionamento.

O arquivo `smartcps.env` contém senhas e chaves e não deve ser versionado; ele já
está listado no `.gitignore`.


## Problemas comuns

| Situação | Solução |
|---|---|
| `permission denied` ao usar o Docker (Linux) | `sudo usermod -aG docker $USER`, depois encerrar a sessão e entrar novamente |
| Mensagem de que o Docker não está rodando | Linux: `sudo systemctl start docker`. Windows/macOS: abrir o Docker Desktop e aguardar a inicialização |
| Porta 8100 ocupada | `PORTA=8200 ./subir.sh` |
| Verificação termina em `TIMEOUT` | aumentar o `timeout` ou reduzir o `unwind` na tela de verificação |
| Computador lento durante a verificação | usar `jobs = 1`; o limite de memória já vem ativado (70% da RAM) |


## Organização do repositório

```
smart-cps/
├── backend/        verificação, classificação, reparo e API
├── frontend/       interface web
├── tests/          testes automatizados
├── docs/           documentação técnica
├── Dockerfile      receita de construção da imagem
├── subir.sh        inicia o sistema (Linux/macOS)
├── subir.bat       inicia o sistema (Windows)
└── smartcps.sh     constrói a imagem e o pacote offline
```

Documentação complementar:

* [docs/README_tecnico.md](docs/README_tecnico.md): arquitetura, parâmetros de
  verificação e execução sem Docker.
* [DOCKER.md](DOCKER.md): uso do Docker e do pacote offline em detalhe.
* [docs/INSTALL.pdf](docs/INSTALL.pdf): instalação manual das ferramentas.
* [docs/inconsistencias_especificacao.md](docs/inconsistencias_especificacao.md):
  pontos em que a especificação e a ferramenta ainda divergem.


## Créditos

Trabalho acadêmico da disciplina PGENE601 / PPGINF554 (UFAM, 2026/2), sob a
supervisão do Prof. Lucas Cordeiro.

As ferramentas de verificação utilizadas são o
[ESBMC](https://github.com/esbmc/esbmc) e o
[CBMC/JBMC](https://github.com/diffblue/cbmc), cada uma sob sua respectiva licença.
