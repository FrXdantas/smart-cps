#!/usr/bin/env bash
#
# subir.sh — sobe o SMART ESBMC / JBMC com UM comando, em qualquer Linux/macOS
# com Docker. Não precisa de internet.
#
#   ./subir.sh            sobe (carrega a imagem do .tar.gz na 1ª vez)
#   ./subir.sh parar      para o sistema (os dados ficam guardados)
#   ./subir.sh logs       acompanha o log ao vivo (Ctrl+C sai)
#   ./subir.sh status     mostra se está no ar e as versões das ferramentas
#   ./subir.sh testes     roda a suíte de testes dentro do container
#   ./subir.sh admin ...  gestão de usuários: add-user <login>, list, delete <id>
#   ./subir.sh backup     salva os dados (usuários, runs) em smartcps-dados-<data>.tar.gz
#   ./subir.sh remover    apaga o container (os DADOS continuam no volume)
#
# Configuração opcional: copie smartcps.env.exemplo para smartcps.env.
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

IMAGEM="${SMARTCPS_IMAGEM:-smartcps:2.1-cps}"
NOME="smartcps"
VOLUME="smartcps-dados"
PORTA="${PORTA:-8100}"

[[ -f smartcps.env ]] && { set -a; . ./smartcps.env; set +a; PORTA="${PORTA:-8100}"; }

docker info >/dev/null 2>&1 || {
  echo "ERRO: o Docker não está rodando (ou falta permissão)." >&2
  echo "      Linux: sudo systemctl start docker   e/ou   sudo usermod -aG docker \$USER (depois saia e entre)" >&2
  echo "      Windows/macOS: abra o Docker Desktop e espere ficar verde." >&2
  exit 1
}

carregar_imagem() {
  docker image inspect "$IMAGEM" >/dev/null 2>&1 && return
  local tar
  tar=$(ls -1 smartcps-imagem*.tar.gz smartcps-imagem*.tar 2>/dev/null | head -1 || true)
  if [[ -z "$tar" ]]; then
    echo "ERRO: imagem $IMAGEM não existe e não achei smartcps-imagem*.tar.gz nesta pasta." >&2
    echo "      Com internet, construa com:  ./smartcps.sh construir" >&2
    exit 1
  fi
  echo "==> Carregando a imagem de $tar (só na 1ª vez, ~1-2 min)..."
  docker load -i "$tar"
}

rodando() { [[ "$(docker inspect -f '{{.State.Running}}' "$NOME" 2>/dev/null)" == "true" ]]; }

subir() {
  carregar_imagem
  if rodando; then
    echo "Já está no ar: http://localhost:$PORTA"; return
  fi
  docker rm -f "$NOME" >/dev/null 2>&1 || true
  local envf=() rede=()
  [[ -f smartcps.env ]] && envf=(--env-file smartcps.env)
  # Linux com Docker Engine: por padrão o container usa a rede do próprio PC.
  # O Ollama do Linux escuta só em 127.0.0.1, que o host.docker.internal não
  # alcança. No Docker Desktop (Windows/macOS/WSL) o host.docker.internal já
  # chega ao Ollama. OLLAMA_NO_PC=0 força a rede isolada.
  local padrao=0
  if [[ "$(uname -s)" == "Linux" ]] && ! docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'docker desktop'; then
    padrao=1
  fi
  if [[ "${OLLAMA_NO_PC:-$padrao}" == "1" ]]; then
    # O container enxerga o Ollama em localhost:11434 sem reconfigurá-lo para 0.0.0.0.
    rede=(--network host -e PORT="$PORTA" -e SMART_JBMC_OLLAMA_URL=http://localhost:11434/v1)
  else
    rede=(-p "$PORTA:8000" --add-host host.docker.internal:host-gateway)
  fi
  docker run -d --name "$NOME" \
    --restart unless-stopped \
    "${rede[@]}" \
    -e HOST_PORT="$PORTA" \
    -v "$VOLUME:/app/data" \
    "${envf[@]}" \
    "$IMAGEM" >/dev/null
  echo -n "==> Subindo"
  for _ in $(seq 1 60); do
    if curl -fsS "http://localhost:$PORTA/api/health" >/dev/null 2>&1; then
      echo; echo
      docker logs "$NOME" 2>&1 | grep -E "admin criado|senha padrão" || true
      echo "✔ No ar:  http://localhost:$PORTA"
      echo "  Parar:  ./subir.sh parar     Log: ./subir.sh logs"
      return
    fi
    echo -n "."; sleep 1
  done
  echo; echo "Não respondeu em 60 s. Log:" >&2
  docker logs --tail 50 "$NOME" >&2
  exit 1
}

case "${1:-subir}" in
  subir|up|start)  subir ;;
  parar|stop)      docker stop "$NOME" >/dev/null && echo "Parado. Dados preservados (volume $VOLUME)." ;;
  logs)            docker logs -f --tail 100 "$NOME" ;;
  status)
    if rodando; then echo "No ar: http://localhost:$PORTA"; else echo "Parado."; fi
    carregar_imagem; docker run --rm "$IMAGEM" ferramentas ;;
  testes)          carregar_imagem; docker run --rm "$IMAGEM" testes "${@:2}" ;;
  admin)
    shift
    if rodando; then docker exec -it "$NOME" smartcps-entrypoint admin "$@"
    else carregar_imagem; docker run --rm -it -v "$VOLUME:/app/data" "$IMAGEM" admin "$@"; fi ;;
  backup)
    f="smartcps-dados-$(date +%Y%m%d-%H%M%S).tar.gz"
    carregar_imagem
    # roda como root para ler o volume e devolve o arquivo ao seu usuário
    docker run --rm --user 0 -v "$VOLUME:/dados:ro" -v "$PWD:/saida" --entrypoint sh "$IMAGEM" \
      -c "tar czf /saida/$f -C /dados . && chown $(id -u):$(id -g) /saida/$f"
    echo "Backup: $f ($(du -h "$f" | cut -f1))" ;;
  restaurar)
    [[ -f "${2:-}" ]] || { echo "uso: ./subir.sh restaurar <smartcps-dados-*.tar.gz>" >&2; exit 2; }
    carregar_imagem
    if rodando; then docker stop "$NOME" >/dev/null; fi
    docker run --rm --user 0 -v "$VOLUME:/dados" -v "$(cd "$(dirname "$2")" && pwd):/entrada:ro" \
      --entrypoint sh "$IMAGEM" -c "tar xzf '/entrada/$(basename "$2")' -C /dados && chown -R smart:smart /dados"
    echo "Restaurado. Suba com ./subir.sh" ;;
  remover)         docker rm -f "$NOME" >/dev/null 2>&1 || true; echo "Container removido. Dados preservados (volume $VOLUME)." ;;
  -h|--help|ajuda) sed -n '2,17p' "$0" ;;
  *) echo "comando desconhecido: $1  (veja ./subir.sh ajuda)" >&2; exit 2 ;;
esac
