#!/usr/bin/env bash
#
# smartcps.sh — CONSTRUIR a imagem e gerar o PACOTE OFFLINE (máquina com internet).
#
#   ./smartcps.sh construir   constrói a imagem smartcps:<rv> (baixa JBMC, Kotlin, ...)
#   ./smartcps.sh exportar    gera dist/smartcps-offline/ pronto para pendrive
#   ./smartcps.sh tudo        construir + exportar
#
# Na máquina de destino (sem internet), basta copiar a pasta
# dist/smartcps-offline/ e rodar ./subir.sh (Linux/macOS) ou subir.bat (Windows).
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

REV=$(sed -nE 's/^APP_REVISION = "([^"]+)"/\1/p' backend/smart_jbmc/__init__.py)
IMAGEM="smartcps:${REV}"
DIST="dist/smartcps-offline"

construir() {
  # Usa o binário ESBMC desta máquina quando existe (paridade exata com o
  # servidor); senão o Dockerfile baixa o release oficial 8.2.
  if [[ ! -x docker/vendor/esbmc ]]; then
    for cand in "${ESBMC_BIN:-}" "$HOME/esbmc/bin/esbmc" "$(command -v esbmc 2>/dev/null || true)"; do
      if [[ -n "$cand" && -x "$cand" ]] && "$cand" --version 2>/dev/null | grep -q "8.2.0"; then
        cp "$(readlink -f "$cand")" docker/vendor/esbmc; echo "==> ESBMC local: $cand"; break
      fi
    done
  fi
  [[ -x docker/vendor/esbmc ]] || echo "==> ESBMC: será baixado do GitHub (release 8.2)"
  docker build --platform linux/amd64 -t "$IMAGEM" -t smartcps:latest .
  echo "✔ imagem $IMAGEM"
  docker run --rm "$IMAGEM" ferramentas
}

exportar() {
  docker image inspect "$IMAGEM" >/dev/null 2>&1 || { echo "imagem $IMAGEM não existe — rode ./smartcps.sh construir" >&2; exit 1; }
  rm -rf "$DIST"; mkdir -p "$DIST"
  echo "==> Salvando a imagem (alguns minutos)..."
  docker save "$IMAGEM" | gzip -1 > "$DIST/smartcps-imagem.tar.gz"
  cp subir.sh subir.bat smartcps.env.exemplo "$DIST/"
  cp DOCKER.md "$DIST/LEIA-ME.md"
  # os lançadores procuram a revisão certa
  sed -i "s/^IMAGEM=\"\${SMARTCPS_IMAGEM:-smartcps:[^}]*}\"/IMAGEM=\"\${SMARTCPS_IMAGEM:-$IMAGEM}\"/" "$DIST/subir.sh"
  sed -i "s/^set IMAGEM=.*/set IMAGEM=$IMAGEM\r/" "$DIST/subir.bat"
  ( cd "$DIST" && sha256sum smartcps-imagem.tar.gz > SHA256SUMS )
  echo "✔ pacote offline: $DIST  ($(du -sh "$DIST" | cut -f1))"
  ls -lh "$DIST"
}

case "${1:-tudo}" in
  construir) construir ;;
  exportar)  exportar ;;
  tudo)      construir; exportar ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
