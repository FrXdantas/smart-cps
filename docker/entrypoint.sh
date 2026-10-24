#!/usr/bin/env bash
#
# Entrypoint do container SMART ESBMC / JBMC.
#
#   servidor (padrão)   prepara data/, cria o admin no 1º uso e sobe o uvicorn
#   admin <args>        CLI de usuários (create-admin, add-user, list, delete...)
#   testes              roda a suíte pytest (só se a pasta tests/ foi montada)
#   ferramentas         mostra as versões das ferramentas embarcadas
#   <qualquer outro>    executa como comando (ex.: bash)
#
set -euo pipefail
cd /app

admin() { python3 /app/tools/smart-jbmc-admin.py "$@"; }

ferramentas() {
  echo "esbmc   : $(esbmc --version 2>&1 | head -1)"
  echo "jbmc    : $(jbmc --version 2>&1 | head -1)"
  echo "cbmc    : $(cbmc --version 2>&1 | head -1)"
  echo "java    : $(java -version 2>&1 | head -1)"
  echo "javac   : $(javac -version 2>&1 | head -1)"
  echo "kotlinc : $(kotlinc -version 2>&1 | grep -o 'kotlinc-jvm [^ ]*' | head -1)"
  echo "python  : $(python3 --version 2>&1)"
}

# Orçamento de memória dos verificadores: se ninguém definiu, usa 70% da RAM
# que o container enxerga (limite do cgroup, ou a RAM do PC). Sem teto o JBMC
# já consumiu 26 GB num caso e travou a máquina inteira.
orcamento_memoria() {
  [[ -n "${SMART_JBMC_MAX_MEM_TOTAL_MB:-}" ]] && return
  local total_kb lim mb
  total_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
  mb=$(( total_kb / 1024 ))
  if [[ -r /sys/fs/cgroup/memory.max ]]; then
    lim=$(cat /sys/fs/cgroup/memory.max)
    if [[ "$lim" =~ ^[0-9]+$ ]] && (( lim / 1048576 < mb )); then mb=$(( lim / 1048576 )); fi
  fi
  export SMART_JBMC_MAX_MEM_TOTAL_MB=$(( mb * 70 / 100 ))
}

servidor() {
  mkdir -p /app/data/runs /app/data/uploads /app/data/logs
  if [[ ! -w /app/data ]]; then
    echo "ERRO: /app/data não é gravável pelo usuário $(id -un) (uid $(id -u))." >&2
    echo "      Se montou uma pasta do PC, rode: sudo chown -R $(id -u):$(id -g) <pasta>" >&2
    exit 1
  fi

  # Primeiro uso: cria o admin. Idempotente — com usuários já cadastrados não faz nada.
  local n
  n=$(cd /app/backend && python3 -c 'from smart_jbmc.auth.db import user_count; print(user_count())')
  if [[ "$n" == "0" ]]; then
    local login="${ADMIN_LOGIN:-admin}" senha="${ADMIN_PASSWORD:-admin123}"
    admin create-admin "$login" --password "$senha" >/dev/null
    echo "==> Primeiro uso: admin criado  →  login: $login   senha: $senha"
    [[ -z "${ADMIN_PASSWORD:-}" ]] && echo "    (senha padrão — troque criando outro admin ou defina ADMIN_PASSWORD no smartcps.env)"
  fi

  orcamento_memoria
  echo "==> SMART ESBMC / JBMC"
  ferramentas | sed 's/^/    /'
  echo "    memória p/ verificadores: ${SMART_JBMC_MAX_MEM_TOTAL_MB} MB"
  echo "    reparo LLM: cada usuário informa a própria chave na tela, ou usa 'Local (Ollama)'"
  echo "    abra no navegador: http://localhost:${HOST_PORT:-$PORT}"

  cd /app/backend
  exec uvicorn smart_jbmc.api.app:app --host 0.0.0.0 --port "$PORT" --proxy-headers
}

case "${1:-servidor}" in
  servidor)     shift || true; servidor "$@" ;;
  admin)        shift; cd /app/backend && admin "$@" ;;
  ferramentas)  ferramentas ;;
  testes)
    shift
    [[ -d /app/tests ]] || { echo "monte a pasta tests/ em /app/tests" >&2; exit 2; }
    exec python3 -m pytest -q -p no:cacheprovider /app/tests "$@" ;;
  *)            exec "$@" ;;
esac
