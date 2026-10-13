"""Gerador de patch guiado por contraexemplo. Opt-in.

A LLM apenas PROPÕE; quem aceita o patch é a fase de regressão (o BMC). Funciona
com qualquer provedor compatível com a API OpenAI de chat/completions (DeepSeek,
Groq, OpenRouter, ...): a UI fornece `base_url`/`api_key`/`model` por requisição;
o .env (DEEPSEEK_API_KEY/DEEPSEEK_MODEL) é só fallback. A chave nunca é
impressa/logada nem persistida em disco.
"""

import os
import re

from ..config import load_env

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"
# Onde está o Ollama "da máquina servidora". Dentro de um container Docker,
# `localhost` é o próprio container: a imagem define SMART_JBMC_OLLAMA_URL para
# apontar ao Ollama do computador hospedeiro (host.docker.internal).
_DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
LOCAL_BASE_URL = (os.environ.get("SMART_JBMC_OLLAMA_URL") or _DEFAULT_LOCAL_BASE_URL).rstrip("/")
LOCAL_DEFAULT_MODEL = "deepseek-coder-v2:16b"

# Timeout (s) da chamada HTTP ao provedor. Padrão alto porque modelos LOCAIS
# grandes (ex.: qwen2.5-coder:32b com offload de CPU em GPU de 8 GB, ~3 tok/s)
# levam minutos para gerar o arquivo inteiro — 120 s estourava. Override via env.
DEFAULT_LLM_TIMEOUT = int(os.environ.get("SMART_JBMC_LLM_TIMEOUT", "600"))

# Provedores OpenAI-compatíveis conhecidos (a UI já manda a base_url resolvida;
# este mapa é só conveniência/fallback no servidor).
PROVIDER_BASE_URL = {
    "deepseek": "https://api.deepseek.com",
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "local": LOCAL_BASE_URL,  # Ollama (OpenAI-compatible) na máquina servidora
}


def _is_local_base(base: str | None) -> bool:
    if not base:
        return False
    b = base.lower()
    return "://localhost" in b or "://127.0.0.1" in b or "://0.0.0.0" in b


class LLMUnavailable(Exception):
    """Sem chave / sem `requests` para chamar a API."""


class LLMRateLimited(LLMUnavailable):
    """Provedor respondeu 429 (cota/limite) mesmo após os retries com backoff.
    É um erro TRANSITÓRIO de infraestrutura/cota — NÃO uma falha de reparo; o laço
    deve marcá-lo como PROVIDER_ERROR para não poluir as métricas de reparo."""


# Quantas vezes retentar em erro transitório (429/502/503), com backoff exponencial
# respeitando o header Retry-After. Override por env.
DEFAULT_LLM_MAX_RETRIES = int(os.environ.get("SMART_JBMC_LLM_MAX_RETRIES", "4"))
_RETRYABLE_STATUS = {429, 502, 503}


def env_api_key():
    """Chave do .env (fallback quando a UI não fornece uma)."""
    load_env()
    key = os.environ.get("DEEPSEEK_API_KEY") or None
    # O .env.example traz "sk-xxxxxxxx..." como placeholder. Tratá-lo como AUSENTE
    # evita anunciar uma chave que existe mas dá 401 — sintoma confuso (a chamada
    # nem acontece e parece "a LLM não conseguiu").
    if key and set(key.removeprefix("sk-")) <= {"x"}:
        return None
    return key


def default_model():
    load_env()
    return os.environ.get("DEEPSEEK_MODEL") or DEFAULT_MODEL


def available() -> bool:
    return bool(env_api_key()) and requests is not None


SYSTEM_PROMPT = (
    "Você é um engenheiro de correção de bugs validados por model checking "
    "(JBMC para Java/Kotlin, ESBMC para C/C++). Recebe um programa, a categoria da "
    "vulnerabilidade (CWE/CERT-C) e o CONTRAEXEMPLO concreto que um verificador "
    "formal usou para violar a propriedade. Produza uma versão corrigida que "
    "(a) elimine a violação, (b) preserve o comportamento legítimo e (c) compile.\n"
    "PRINCÍPIOS (siga à risca — valem ainda mais para modelos menores):\n"
    "1. Faça a MENOR mudança possível que elimine a violação. NÃO reescreva nem "
    "reestruture o programa; mude só o necessário e mantenha estrutura, nomes e fluxo.\n"
    "2. PRESERVE a forma original: NÃO troque arrays de tamanho fixo/VLA por malloc, "
    "NÃO mude tipos de dados sem necessidade, NÃO adicione alocação dinâmica nem "
    "novos recursos. Prefira uma checagem/guard pontual — validar limites ANTES da "
    "operação que estoura (ex.: overflow), usar assume_abort_if_not quando fizer sentido.\n"
    "3. NÃO introduza uma violação NOVA (o verificador rejeita o patch se você criar "
    "outra). Se — e só se — for inevitável alocar memória, libere-a em TODOS os "
    "caminhos de saída, inclusive nos de erro/abort.\n"
    "4. INCLUA todos os cabeçalhos/imports necessários no topo: INT_MAX/INT_MIN/"
    "LONG_MAX → <limits.h>; malloc/free → <stdlib.h>; bool/true/false → <stdbool.h>; "
    "printf → <stdio.h>. Não use um símbolo sem declarar seu cabeçalho.\n"
    "5. MARQUE CADA LINHA ALTERADA OU INSERIDA com um comentário inline no formato "
    "EXATO: dois slashes + espaço + setinha de três traços + espaço, "
    "assim → `// <--- corrigido aqui: <razão curta>`. "
    "É OBRIGATÓRIO usar EXATAMENTE três traços (`<---`); não use `<--` (dois) nem "
    "`<----` (quatro), e não troque por outros símbolos. Na razão, CITE o CWE/CERT-C "
    "que veio no contexto (ex.: 'guard de OOB (CWE-787 / ARR30-C)') — NÃO invente um "
    "CWE diferente. Use sempre `//` (C/Java/Kotlin todos suportam). Se a mudança "
    "ocupa várias linhas contíguas (ex.: um bloco if), basta a marca na PRIMEIRA. "
    "Em #include/import novo, marque na própria linha. NÃO adicione outros "
    "comentários explicativos no código — APENAS as marcas `<--- corrigido aqui: ...`.\n"
    "6. O programa pode ter VÁRIOS arquivos. Você corrige UM só — o indicado como "
    "'ARQUIVO A CORRIGIR'. Os demais vêm como CONTEXTO SOMENTE-LEITURA: use-os para "
    "entender chamadas e assinaturas, mas NÃO os reescreva, NÃO copie o conteúdo "
    "deles para dentro do arquivo corrigido e NÃO redeclare classes/funções que já "
    "existem neles (isso quebra o projeto com 'duplicate class'). Se o arquivo a "
    "corrigir chama algo que você não vê, ele existe no contexto ou em biblioteca — "
    "NÃO invente uma reimplementação.\n"
    "7. NUNCA faça a violação sumir removendo, enfraquecendo ou comentando "
    "asserções, testes ou verificações. Corrija a CAUSA.\n"
    "RESPONDA APENAS com o código-fonte completo corrigido — sem texto fora dele, "
    "sem cercas de markdown. Mantenha o mesmo nome de classe/arquivo e a linguagem."
)


def _context_block(context_files) -> str:
    """Arquivos vizinhos da unidade de compilação, como contexto somente-leitura."""
    if not context_files:
        return ""
    partes = ["\n--- CONTEXTO SOMENTE-LEITURA (NÃO corrija, NÃO copie, NÃO redeclare) ---"]
    for nome, conteudo in context_files.items():
        partes.append(f"### {nome}\n{conteudo}")
    return "\n".join(partes) + "\n"


def _messages(bug, cwe_info, cert_rule, code, counterexample, lang,
              prev_patch, prev_cex, prev_verdict,
              file_name=None, context_files=None):
    ctx = (
        f"Linguagem: {lang}\n"
        f"Categoria do bug: {bug}\n"
        f"CWE: {(cwe_info or {}).get('cwe_id', '?')} {(cwe_info or {}).get('cwe_name', '')}\n"
        f"Regra CERT-C: {cert_rule}\n"
    )
    if file_name:
        ctx += f"Arquivo a corrigir: {file_name}\n"
    feedback = ""
    if prev_patch and prev_verdict:
        feedback = (
            "\n--- TENTATIVA ANTERIOR (NÃO funcionou) ---\n"
            f"Veredicto do verificador: {prev_verdict}\n"
            f"Código da tentativa anterior:\n{prev_patch}\n"
            f"Novo contraexemplo/erro:\n{prev_cex}\n"
            "Corrija de forma diferente, considerando esse feedback.\n"
        )
    rotulo = f"ARQUIVO A CORRIGIR ({file_name})" if file_name else "PROGRAMA A CORRIGIR"
    user = (
        f"{ctx}\n--- CONTRAEXEMPLO DO VERIFICADOR ---\n{counterexample}\n"
        f"{_context_block(context_files)}"
        f"{feedback}\n--- {rotulo} ---\n{code}\n"
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


_FENCE_RE = re.compile(r"^\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n```\s*$", re.DOTALL)

# Normaliza variações que modelos menores às vezes geram:
#   `// <-- corrigido aqui:`  ou  `// <----- corrigido aqui:`  →  `// <--- corrigido aqui:`
# Aceita 1 a 6 traços e qualquer espaçamento; preserva o restante da linha.
_FIX_MARKER_RE = re.compile(r"(//\s*)<-{1,6}(\s*corrigido aqui)", re.IGNORECASE)


def _strip_fences(text):
    if not text:
        return text
    m = _FENCE_RE.match(text.strip())
    if m:
        text = m.group(1)
    else:
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith("```")]
        if len(lines) != len(text.splitlines()):
            text = "\n".join(lines).strip()
    return _FIX_MARKER_RE.sub(r"\1<---\2", text)


def generate_patch(*, bug, cwe_info, cert_rule, code, counterexample, lang,
                   model=None, base_url=None, api_key=None,
                   prev_patch=None, prev_cex=None, prev_verdict=None,
                   timeout=None, max_tokens=8000, temperature=0.2, dry_run=False,
                   file_name=None, context_files=None) -> dict:
    """Pede um patch a um provedor OpenAI-compatível.

    `base_url`/`api_key`/`model` vêm da UI por requisição; caem para o .env
    quando ausentes. dry_run (ou env SMART_JBMC_LLM_DRYRUN=1) devolve o código
    inalterado, sem chamar a API (testar a fiação sem saldo/chave).
    """
    if dry_run or os.environ.get("SMART_JBMC_LLM_DRYRUN") == "1":
        return {"patch": code, "usage": None, "model": "dry-run", "ms": 0}

    if requests is None:
        raise LLMUnavailable("'requests' não instalado.")
    base = (base_url or DEEPSEEK_BASE_URL).rstrip("/")
    is_local = _is_local_base(base)
    if is_local and LOCAL_BASE_URL != _DEFAULT_LOCAL_BASE_URL:
        # a SPA manda http://localhost:11434/v1; no container isso não chega ao Ollama
        base = LOCAL_BASE_URL
    key = api_key or (None if is_local else env_api_key())
    if not key and not is_local:
        raise LLMUnavailable(
            "Sem API key. Configure provedor/chave/modelo no botão de configuração "
            "(ou preencha o .env), ou use o modo dry-run. "
            "Para usar a IA local desta máquina, escolha o provedor 'Local (Ollama)'."
        )
    model = model or (LOCAL_DEFAULT_MODEL if is_local else default_model())
    timeout = timeout or DEFAULT_LLM_TIMEOUT
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    payload = {
        "model": model,
        "messages": _messages(bug, cwe_info, cert_rule, code, counterexample,
                              lang, prev_patch, prev_cex, prev_verdict,
                              file_name=file_name, context_files=context_files),
        "temperature": temperature, "max_tokens": max_tokens, "stream": False,
    }
    import time

    def _retry_after(resp, fallback):
        """Segundos a esperar: respeita o header Retry-After do provedor; senão usa
        o backoff exponencial. Teto de 60 s para não travar a run."""
        ra = (resp.headers.get("Retry-After") or "").strip()
        if ra.replace(".", "", 1).isdigit():
            return min(float(ra), 60.0)
        return min(fallback, 60.0)

    resp = None
    t0 = time.perf_counter()
    for attempt in range(DEFAULT_LLM_MAX_RETRIES + 1):
        t0 = time.perf_counter()
        resp = requests.post(f"{base}/chat/completions", headers=headers,
                             json=payload, timeout=timeout)
        if resp.status_code == 200:
            break
        if resp.status_code in _RETRYABLE_STATUS and attempt < DEFAULT_LLM_MAX_RETRIES:
            time.sleep(_retry_after(resp, 2.0 * (2 ** attempt)))   # backoff exponencial
            continue
        break  # não-retryável, ou esgotou as tentativas
    ms = int((time.perf_counter() - t0) * 1000)
    if resp.status_code != 200:
        if resp.status_code == 429:
            raise LLMRateLimited(
                f"HTTP 429 (cota/limite) após {DEFAULT_LLM_MAX_RETRIES + 1} tentativas: "
                f"{resp.text[:200]}")
        raise LLMUnavailable(f"HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    content = data["choices"][0]["message"].get("content") or ""
    return {"patch": _strip_fences(content), "usage": data.get("usage"),
            "model": data.get("model", model), "ms": ms}
