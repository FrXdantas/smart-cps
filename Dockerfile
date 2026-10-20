# syntax=docker/dockerfile:1
#
# SMART ESBMC / JBMC — imagem autocontida (roda OFFLINE depois de construída).
#
# Traz tudo o que a verificação precisa, nas MESMAS versões do servidor de
# produção. Paridade de versão é requisito: o parser de contraexemplo e a
# `strategy` foram validados contra a saída destas versões.
#   ESBMC 8.6.0 · cbmc/jbmc 6.9.0 · OpenJDK 21 · Kotlin 2.3.21 · Python 3.12
#
# Construir (precisa de internet SÓ nesta etapa):   ./smartcps.sh construir
# Na máquina offline:                                ./subir.sh
#
FROM ubuntu:24.04

ARG CBMC_VERSION=6.9.0
ARG KOTLIN_VERSION=2.3.21
ARG ESBMC_URL=https://github.com/esbmc/esbmc/releases/download/v8.6/esbmc-linux.zip

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=America/Sao_Paulo

# --- sistema: Python, JDK 21 (javac/java), gcc (pré-processamento de C) ---
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates curl unzip tzdata tini \
      openjdk-21-jdk-headless gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# --- cbmc/jbmc 6.9.0 (o apt do 24.04 traz 5.95.1 — NÃO serve) ---
RUN curl -fsSL -o /tmp/cbmc.deb \
      "https://github.com/diffblue/cbmc/releases/download/cbmc-${CBMC_VERSION}/ubuntu-24.04-cbmc-${CBMC_VERSION}-Linux.deb" \
 && apt-get update \
 && apt-get install -y --no-install-recommends /tmp/cbmc.deb \
 && rm -rf /tmp/cbmc.deb /var/lib/apt/lists/* \
 && jbmc --version

# --- Kotlin 2.3.21 ---
RUN curl -fsSL -o /tmp/kotlin.zip \
      "https://github.com/JetBrains/kotlin/releases/download/v${KOTLIN_VERSION}/kotlin-compiler-${KOTLIN_VERSION}.zip" \
 && unzip -q /tmp/kotlin.zip -d /opt \
 && rm /tmp/kotlin.zip \
 && ln -s /opt/kotlinc/bin/kotlinc /usr/local/bin/kotlinc

# --- ESBMC 8.6.0 (binário estático) ---
# Se docker/vendor/esbmc existir (o construir.sh copia o binário da máquina de
# dev, garantindo o MESMO arquivo do servidor), usa ele; senão baixa o release
# oficial 8.6 do GitHub (mesma versão e mesmos solvers: boolector, z3, bitwuzla).
# A revisão 2.0-cps, com o ESBMC 8.2.0, ficou congelada na imagem smartcps:2.0-cps.
COPY docker/vendor/ /tmp/vendor/
RUN if [ -x /tmp/vendor/esbmc ]; then \
        install -m 0755 /tmp/vendor/esbmc /usr/local/bin/esbmc; \
    else \
        curl -fsSL -o /tmp/esbmc.zip "$ESBMC_URL" \
     && unzip -q -j /tmp/esbmc.zip release/bin/esbmc -d /usr/local/bin \
     && chmod 0755 /usr/local/bin/esbmc \
     && rm /tmp/esbmc.zip; \
    fi \
 && rm -rf /tmp/vendor \
 && esbmc --version

# --- aplicação ---
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt "pytest>=8.0" "httpx>=0.27"

COPY backend/  /app/backend/
COPY frontend/ /app/frontend/
COPY tools/smart-jbmc-admin.py /app/tools/smart-jbmc-admin.py
# suíte de testes embarcada: `./subir.sh testes` valida a instalação offline
COPY tests/ /app/tests/
COPY pyproject.toml /app/pyproject.toml
COPY docker/entrypoint.sh /usr/local/bin/smartcps-entrypoint

# Usuário sem privilégios. data/ (banco de usuários, runs, uploads, stubs) é
# o ÚNICO estado — vai num volume para sobreviver a recriar/atualizar o container.
# (a ubuntu:24.04 já traz o usuário "ubuntu" com uid 1000; ele sai para o
# "smart" ficar com 1000, o uid do usuário comum na maioria dos PCs Linux)
RUN (userdel -r ubuntu 2>/dev/null || true) \
 && useradd -m -u 1000 -s /bin/bash smart \
 && mkdir -p /app/data /app/backend/build_verify \
 && chown -R smart:smart /app/data /app/backend/build_verify \
 && chmod 0755 /usr/local/bin/smartcps-entrypoint

ENV PATH="/opt/venv/bin:${PATH}" \
    ESBMC_PATH=/usr/local/bin/esbmc \
    JBMC_PATH=/usr/bin/jbmc \
    KOTLINC_PATH=/opt/kotlinc/bin/kotlinc \
    SMART_JBMC_OLLAMA_URL=http://host.docker.internal:11434/v1 \
    PORT=8000

USER smart
VOLUME ["/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${PORT}/api/health" >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "smartcps-entrypoint"]
CMD ["servidor"]
