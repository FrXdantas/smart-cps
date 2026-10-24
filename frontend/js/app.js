// SMART ESBMC/JBMC — SPA: lançar verificação, barra de progresso e resultados.

// Selos de status em tom sóbrio: contorno fino e texto escuro, sem fundo cheio.
// A cor só separa bom / ruim / atenção / neutro (ver .selo no CSS).
const STATUS_BADGE = {
  BUG: "selo selo-ruim", SAFE: "selo selo-bom",
  UNKNOWN: "selo selo-aviso", TIMEOUT: "selo selo-aviso",
  ERROR: "selo selo-neutro", COMPILE_FAIL: "selo selo-neutro",
  // classe de biblioteca (sem `main`): alvo inaplicável, não erro
  NO_ENTRY_POINT: "selo selo-neutro",
};
const LANG_BY_EXT = { java: "java", kt: "kotlin", c: "c" };
function langOf(t) {
  const e = (/\.(\w+)$/.exec(t.source || "") || [, ""])[1].toLowerCase();
  return LANG_BY_EXT[e] || t.kind || "—";
}
const VERDICT_BADGE = {
  FIX_OK: "selo selo-bom", STILL_VULNERABLE: "selo selo-aviso",
  DIFFERENT_BUG: "selo selo-aviso", TIMEOUT: "selo selo-neutro", ERROR: "selo selo-neutro",
  PROVIDER_ERROR: "selo selo-neutro",
  // patch recusado pelas guardas ANTES de chegar ao verificador: reimplementou
  // classe que já existe em outro arquivo, ou apagou asserção p/ a violação sumir
  INVALID_PATCH: "selo selo-ruim",
};

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

function downloadText(filename, text, mime) {
  const blob = new Blob([text], { type: (mime || "text/plain") + ";charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

// ---------------- paginação (client-side; renderiza só a página atual) ----------------
let curTargets = [], tgtPage = 1;
const tgtSize = 50;
let curRepair = [], repPage = 1;
const repSize = 50;

// Só aparece quando há mais de uma página: com uma página, contador e seletor
// de tamanho eram ruído. O tamanho fica fixo em 50 por página.
function buildPager(containerId, total, page, size, onGoto) {
  const c = document.getElementById(containerId);
  if (!c) return;
  const pages = Math.max(1, Math.ceil(total / size));
  c.classList.toggle("d-none", pages <= 1);
  if (pages <= 1) { c.innerHTML = ""; return; }
  c.innerHTML = `
    <div class="d-flex justify-content-end small">
      <div class="btn-group btn-group-sm">
        <button type="button" class="btn btn-outline-secondary pager-prev"${page <= 1 ? " disabled" : ""}>Anterior</button>
        <button type="button" class="btn btn-outline-secondary" disabled>${page}/${pages}</button>
        <button type="button" class="btn btn-outline-secondary pager-next"${page >= pages ? " disabled" : ""}>Próximo</button>
      </div>
    </div>`;
  c.querySelector(".pager-prev").addEventListener("click", () => onGoto(page - 1));
  c.querySelector(".pager-next").addEventListener("click", () => onGoto(page + 1));
}
const PHASE_LABEL = {
  queued: "Na fila…", scanning: "Escaneando arquivos…",
  compiling: "Compilando bytecode…", verifying: "Verificando alvos…",
  done: "Concluído", error: "Erro", cancelled: "Cancelado",
};

let pollTimer = null;
let animTimer = null;
let displayedPct = 0;
let targetPct = 0;
let startTime = 0;
let currentRunId = null;       // run exibida no painel de resultados

// ---------------- progresso ----------------
function setTarget(rec) {
  if (rec.status === "done") { targetPct = 100; return; }
  const pr = rec.progress || {};
  if (pr.phase === "verifying" && pr.total > 0) {
    targetPct = 10 + (pr.done / pr.total) * 85;     // 10..95
  } else if (pr.phase === "compiling") {
    targetPct = Math.max(targetPct, 8);
  } else if (pr.phase === "scanning") {
    targetPct = Math.max(targetPct, 4);
  } else {
    targetPct = Math.max(targetPct, 2);
  }
}

function animate() {
  displayedPct += (targetPct - displayedPct) * 0.15;
  if (targetPct >= 100 && displayedPct > 99.5) displayedPct = 100;
  const bar = document.getElementById("progress-bar");
  const pct = Math.round(displayedPct);
  bar.style.width = pct + "%";
  bar.textContent = pct + "%";
}

function updateProgressText(rec) {
  const pr = rec.progress || {};
  document.getElementById("progress-phase").textContent = PHASE_LABEL[pr.phase] || "Processando…";
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
  let meta = `${elapsed}s`;
  if (pr.phase === "verifying" && pr.total > 0) meta = `${pr.done}/${pr.total} alvos · ${elapsed}s`;
  document.getElementById("progress-meta").textContent = meta;
}

// Pasta enviada por upload: o campo EXIBE o rótulo ("ana/QuixBugs") e guarda o
// caminho real do servidor em dataset.real — é esse que vai para a API. Pasta
// digitada à mão não tem rótulo: vale o que está no campo.
function folderValue() {
  const el = document.getElementById("f-folder");
  return (el.dataset.real || el.value).trim();
}

function setFolder(path, label) {
  const el = document.getElementById("f-folder");
  if (label) { el.dataset.real = path; el.value = label; }
  else { delete el.dataset.real; el.value = path; }
}

// ---------------- ciclo de run ----------------
async function launchRun(ev) {
  ev.preventDefault();
  document.getElementById("form-error").textContent = "";
  const btn = document.getElementById("btn-run");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Lançando…';
  const cfg = {
    folder: folderValue(),
    unwind: +document.getElementById("f-unwind").value,
    timeout: +document.getElementById("f-timeout").value,
    jobs: +document.getElementById("f-jobs").value,
    solver: document.getElementById("f-solver").value,
    strategy: document.getElementById("f-strategy")?.value || "bounded",
    unsigned_overflow: !!document.getElementById("f-unsigned-overflow")?.checked,
    concurrency: !!document.getElementById("f-concurrency")?.checked,
    nan_check: !!document.getElementById("f-nan-check")?.checked,
  };
  // Opções de projeto (avançado): só incluídas quando preenchidas. As listas
  // vêm como texto (uma entrada por linha) e viram array; o backend ignora vazios.
  const lines = (id) => (document.getElementById(id)?.value || "")
    .split("\n").map((s) => s.trim()).filter(Boolean);
  const includeDirs = lines("f-include-dirs");
  const linkUnit = lines("f-link-unit");
  const fn = (document.getElementById("f-function")?.value || "").trim();
  if (includeDirs.length) cfg.include_dirs = includeDirs;
  if (linkUnit.length) cfg.link_unit = linkUnit;
  if (fn) cfg.function = fn;
  try {
    const { id } = await api.createRun(cfg);
    startRun(id);
  } catch (e) {
    document.getElementById("form-error").textContent = e.message;
    resetButton();
  }
}

function resetButton() {
  const btn = document.getElementById("btn-run");
  btn.disabled = false;
  btn.innerHTML = 'Verificar';
}

function startRun(id) {
  currentRunId = id;
  document.getElementById("results").classList.add("d-none");
  document.getElementById("detail-card").classList.add("d-none");
  document.getElementById("progress-card").classList.remove("d-none");
  const cb = document.getElementById("btn-cancel-run");
  cb.disabled = false;
  cb.innerHTML = 'Parar';
  displayedPct = 0; targetPct = 2; startTime = Date.now();
  clearInterval(animTimer); animTimer = setInterval(animate, 100);
  poll(id);
}

async function cancelCurrentRun() {
  if (!currentRunId) return;
  const btn = document.getElementById("btn-cancel-run");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Parando…';
  document.getElementById("progress-phase").textContent = "Parando… (aguardando alvos em execução)";
  try { await api.cancelRun(currentRunId); } catch (e) { /* o poll refletirá o estado */ }
}

async function poll(id) {
  let rec;
  try {
    rec = await api.getRun(id);
  } catch (e) {
    document.getElementById("progress-phase").textContent = "Erro ao consultar: " + e.message;
    return;
  }
  setTarget(rec);
  updateProgressText(rec);
  if (rec.status === "running") {
    pollTimer = setTimeout(() => poll(id), 800);
  } else if (rec.status === "done" || rec.status === "cancelled") {
    finishRun(rec);
  } else {
    clearInterval(animTimer);
    document.getElementById("progress-phase").textContent = "Erro: " + (rec.error || "desconhecido");
    document.getElementById("progress-bar").classList.replace("bg-primary", "bg-danger");
    resetButton();
  }
}

function finishRun(rec) {
  targetPct = 100;
  setTimeout(() => {
    clearInterval(animTimer);
    document.getElementById("progress-card").classList.add("d-none");
    renderResults(rec);
    loadHistory();
    resetButton();
  }, 600);
}

// ---------------- renderização ----------------
// Resumo da run: uma faixa só, números em cor neutra. O status de cada alvo já
// aparece colorido na tabela; repetir a cor aqui só competia com ela.
function summaryCard(label, value) {
  return `<div class="resumo-item"><span class="valor">${value}</span><span class="rotulo">${label}</span></div>`;
}

// "20/10/2026 - 12:13"
function fmtDataHora(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} - ${p(d.getHours())}:${p(d.getMinutes())}`;
}

const ICONE_LIXEIRA = `<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor"
  stroke-width="1.3" aria-hidden="true"><path d="M2.5 4h11M6 4V2.5h4V4M4 4l.7 9.5h6.6L12 4M6.6 6.5v5M9.4 6.5v5"/></svg>`;

function fmtWhen(iso) {
  if (!iso) return "";
  try { return new Date(iso).toLocaleString("pt-BR"); } catch { return iso; }
}

function renderResults(rec) {
  const result = rec.result || {};
  currentRunId = rec.id || currentRunId;

  // A identificação da run fica no Histórico (linha marcada); aqui só o aviso
  // de run cancelada, porque os números abaixo são parciais.
  document.getElementById("results-header").classList.toggle("d-none", rec.status !== "cancelled");

  const s = result.summary || {};
  const m = result.metrics || {};
  document.getElementById("summary-cards").innerHTML =
    summaryCard("Total", s.total || 0) +
    summaryCard("BUG", s.BUG || 0) +
    summaryCard("SAFE", s.SAFE || 0) +
    (s.UNKNOWN ? summaryCard("UNKNOWN", s.UNKNOWN) : "") +
    summaryCard("TIMEOUT", s.TIMEOUT || 0) +
    summaryCard("ERROR", s.ERROR || 0) +
    (s.COMPILE_FAIL ? summaryCard("COMPILE_FAIL", s.COMPILE_FAIL) : "") +
    (s.NO_ENTRY_POINT ? summaryCard("SEM MAIN", s.NO_ENTRY_POINT) : "") +
    summaryCard("CASTLE", m.castle_score ?? "—");

  // avisos de compilação (unidades que não compilaram) — não somem mais em silêncio
  const warns = result.warnings || [];
  const wEl = document.getElementById("results-warnings");
  if (warns.length) {
    wEl.classList.remove("d-none");
    wEl.innerHTML =
      `<strong>${warns.length} unidade(s) não compilaram</strong> ` +
      `e aparecem como <span class="badge selo selo-neutro">COMPILE_FAIL</span> na tabela (clique p/ ver o erro). ` +
      `<details class="mt-1"><summary>ver lista</summary>` +
      `<div class="mt-1" style="max-height:160px;overflow:auto;font-family:monospace">${warns.map(escapeHtml).join("<br>")}</div></details>`;
  } else {
    wEl.classList.add("d-none");
  }

  const dist = result.cwe_dist || {};
  const max = Math.max(1, ...Object.values(dist));
  const entries = Object.entries(dist).sort((a, b) => b[1] - a[1]);
  document.getElementById("cwe-dist").innerHTML = entries.length
    ? entries.map(([cwe, n]) => `
        <div class="mb-2">
          <div class="d-flex justify-content-between small"><span>${cwe}</span><span>${n}</span></div>
          <div class="progress" style="height:.5rem;">
            <div class="progress-bar bg-primary" style="width:${(n / max) * 100}%"></div>
          </div>
        </div>`).join("")
    : '<p class="text-muted small mb-0">Nenhum bug detectado.</p>';

  curTargets = result.targets || [];
  tgtPage = 1;
  renderTargetsTable();

  document.getElementById("detail-card").classList.add("d-none");
  document.getElementById("results").classList.remove("d-none");
  markActiveHistory(currentRunId);
  showRepairCard((s.BUG || 0) > 0);
}

// Clicar de novo na mesma linha fecha o detalhe e volta a tela para a linha.
// `chave` identifica o alvo aberto; a linha aberta fica marcada.
function alternarDetalhe(cardId, chave, tr, mostrar) {
  const card = document.getElementById(cardId);
  const tabela = tr.closest("tbody");
  const aberto = !card.classList.contains("d-none") && card.dataset.alvo === chave;
  tabela.querySelectorAll("tr.linha-aberta").forEach((l) => l.classList.remove("linha-aberta"));
  if (aberto) {
    card.classList.add("d-none");
    delete card.dataset.alvo;
    tr.scrollIntoView({ behavior: "smooth", block: "center" });
    return;
  }
  mostrar();
  card.dataset.alvo = chave;
  tr.classList.add("linha-aberta");
}

function targetRow(t) {
  const badge = STATUS_BADGE[t.status] || "selo selo-neutro";
  const tr = document.createElement("tr");
  tr.className = "target-row";
  tr.innerHTML = `
    <td class="text-truncate" style="max-width:220px" title="${t.target}">${t.target}</td>
    <td><span class="badge bg-body-tertiary text-body border" title="verificado por ${t.kind}">${langOf(t)}</span></td>
    <td><span class="badge ${badge}">${t.status}</span></td>
    <td class="small">${t.bug || "—"}</td>
    <td class="small">${t.cwe_id || "—"}</td>
    <td class="small">${t.cert_priority ? "P" + t.cert_priority + " " + (t.cert_level || "") : "—"}</td>`;
  tr.addEventListener("click", () =>
    alternarDetalhe("detail-card", t.source || t.target, tr, () => showDetail(t)));
  return tr;
}

function renderTargetsTable() {
  const total = curTargets.length;
  const pages = Math.max(1, Math.ceil(total / tgtSize));
  tgtPage = Math.min(Math.max(1, tgtPage), pages);
  const start = (tgtPage - 1) * tgtSize;
  const tb = document.getElementById("targets-body");
  tb.innerHTML = "";
  curTargets.slice(start, start + tgtSize).forEach(t => tb.appendChild(targetRow(t)));
  buildPager("targets-pager", total, tgtPage, tgtSize,
    p => { tgtPage = p; renderTargetsTable(); });
}

// ---------------- reparo guiado por LLM ----------------
let repairPoll = null;
let repairCancelling = false;    // true após clicar Parar — o poll mostra "Parando…" sem sobrescrever
let lastRepairResult = null;     // p/ detalhe na tela + export do relatório
let lastRepairRunId = null;


function showRepairCard(hasBugs) {
  const card = document.getElementById("repair-card");
  card.classList.toggle("d-none", !hasBugs);
  if (!hasBugs) return;
  document.getElementById("repair-progress").classList.add("d-none");
  document.getElementById("repair-results").classList.add("d-none");
  // a dica só aparece quando há o que avisar (ex.: falta configurar a LLM)
  document.getElementById("repair-hint").classList.add("d-none");
  const bar = document.getElementById("repair-bar");
  bar.classList.replace("bg-danger", "bg-primary");
  document.getElementById("btn-repair").disabled = false;
  updateRepairBadge();
}

function setRepairBar(pct, phase, meta) {
  const bar = document.getElementById("repair-bar");
  const p = Math.round(pct);
  bar.style.width = p + "%";
  bar.textContent = p + "%";
  document.getElementById("repair-phase").textContent = phase;
  document.getElementById("repair-meta").textContent = meta || "";
}

async function launchRepair() {
  if (!currentRunId) return;
  const dryRun = document.getElementById("repair-dryrun").checked;
  const cfg = loadLLMConfig();
  // 'local' (Ollama no servidor) NÃO usa api_key. Para os demais providers, exige.
  const isLocal = cfg.provider === "local";
  // A chave é de cada usuário: o servidor não tem chave própria para emprestar.
  const needsKey = !dryRun && !isLocal && !cfg.api_key;
  if (needsKey) {
    const hint = document.getElementById("repair-hint");
    hint.classList.remove("d-none");
    hint.innerHTML = '<span class="text-danger">' +
      'Configure o provedor e a API key no botão <strong>Configurar LLM</strong> ' +
      '(ou escolha <strong>Local (Ollama)</strong>, ou ative o <strong>dry-run</strong>).</span>';
    openSettings();
    return;
  }
  document.getElementById("btn-repair").disabled = true;
  document.getElementById("repair-hint").classList.add("d-none");
  document.getElementById("repair-results").classList.add("d-none");
  document.getElementById("repair-progress").classList.remove("d-none");
  document.getElementById("repair-bar").classList.replace("bg-danger", "bg-primary");
  repairCancelling = false;
  const rcb = document.getElementById("btn-cancel-repair");
  rcb.disabled = false;
  rcb.innerHTML = 'Parar';
  setRepairBar(4, "Iniciando…", "");
  try {
    await api.createRepair({
      run_id: currentRunId,
      dry_run: dryRun,
      only_unrepaired: document.getElementById("repair-incremental").checked,
      max_iters: 5,
      // unwind/timeout/solver não vão daqui: o servidor usa os da run, para o
      // oráculo re-verificar no mesmo regime em que o bug foi achado.
      provider: cfg.provider || null,
      base_url: cfg.base_url || null,
      api_key: cfg.api_key || null,
      model: cfg.model || null,
    });
    pollRepair();
  } catch (e) {
    setRepairBar(100, "Erro: " + e.message, "");
    document.getElementById("btn-repair").disabled = false;
  }
}

async function cancelCurrentRepair() {
  if (!currentRunId) return;
  repairCancelling = true;
  const btn = document.getElementById("btn-cancel-repair");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Parando…';
  document.getElementById("repair-phase").textContent = "Parando… (aguardando a iteração em curso)";
  try { await api.cancelRepair(currentRunId); } catch (e) { /* o poll refletirá o estado */ }
}

async function pollRepair() {
  let rec;
  try { rec = await api.getRepair(currentRunId); } catch { return; }
  const p = rec.progress || {};
  if (rec.status === "running") {
    const total = p.total || 0, done = p.done || 0;
    const frac = p.max ? (p.iter || 0) / p.max : 0;
    const pct = total ? Math.min(98, ((done + frac) / total) * 100) : 6;
    const spd = p.tok_s ? ` · ~${p.tok_s} tok/s` : "";
    const phase = repairCancelling
      ? "Parando… (aguardando a iteração em curso)"
      : `Reparando ${Math.min(done + 1, total || 1)}/${total || "?"}…`;
    setRepairBar(Math.max(6, pct), phase, `iteração ${p.iter || 0}/${p.max || 0}${spd}`);
    repairPoll = setTimeout(pollRepair, 800);
  } else if (rec.status === "done" || rec.status === "cancelled") {
    const stopped = rec.status === "cancelled";
    setRepairBar(100, stopped ? "Parado (parcial)" : "Concluído", "");
    loadHistory();   // o histórico passa a mostrar o modelo usado no reparo
    setTimeout(() => {
      document.getElementById("repair-progress").classList.add("d-none");
      renderRepair(rec.result);
    }, 400);
    document.getElementById("btn-repair").disabled = false;
  } else {
    document.getElementById("repair-bar").classList.replace("bg-primary", "bg-danger");
    setRepairBar(100, "Erro: " + (rec.error || "desconhecido"), "");
    document.getElementById("btn-repair").disabled = false;
  }
}

function renderRepair(result) {
  lastRepairResult = result;
  lastRepairRunId = currentRunId;
  const s = result.summary || {};
  document.getElementById("repair-summary").innerHTML =
    summaryCard("Bugs", s.total || 0) +
    summaryCard("Reparados", s.repaired || 0) +
    summaryCard("Não reparados", s.not_repaired || 0) +
    (s.provider_errors ? summaryCard("Erros provedor (429)", s.provider_errors) : "") +
    summaryCard("Iter. médias", s.avg_iterations_when_repaired || 0) +
    summaryCard("Tok/s médio", s.avg_tok_s || 0);
  curRepair = result.targets || [];
  repPage = 1;
  renderRepairTable();
  document.getElementById("repair-detail").classList.add("d-none");
  document.getElementById("repair-results").classList.remove("d-none");
}

const REPAIR_STATUS_BADGE = {
  REPAIRED: "selo selo-bom", NOT_REPAIRED: "selo selo-aviso",
  ERROR: "selo selo-neutro", PROVIDER_ERROR: "selo selo-neutro",
};

function repairRow(t) {
  const badge = REPAIR_STATUS_BADGE[t.status] || "selo selo-aviso";
  // rótulo amigável: deixa claro que rate-limit não é falha de reparo
  const label = t.status === "PROVIDER_ERROR" ? "PROVIDER_ERROR (cota/429)" : t.status;
  const tr = document.createElement("tr");
  tr.className = "target-row";
  tr.innerHTML = `
    <td class="small text-truncate" style="max-width:220px" title="${t.target}">${t.target}</td>
    <td class="small">${t.original_bug}</td>
    <td><span class="badge ${badge}">${label}</span></td>
    <td class="small">${t.iterations}</td>`;
  tr.addEventListener("click", () =>
    alternarDetalhe("repair-detail", t.source || t.target, tr, () => showRepairDetail(t)));
  return tr;
}

function renderRepairTable() {
  const total = curRepair.length;
  const pages = Math.max(1, Math.ceil(total / repSize));
  repPage = Math.min(Math.max(1, repPage), pages);
  const start = (repPage - 1) * repSize;
  const tb = document.getElementById("repair-body");
  tb.innerHTML = "";
  curRepair.slice(start, start + repSize).forEach(t => tb.appendChild(repairRow(t)));
  buildPager("repair-pager", total, repPage, repSize,
    p => { repPage = p; renderRepairTable(); });
}

// detalhe de UM alvo reparado: trilha de iterações + diff lado a lado
function showRepairDetail(t) {
  document.getElementById("repair-detail-title").textContent = t.target;
  const trail = (t.attempts || []).map(a => {
    const spd = a.tok_s ? ` · ${a.tok_s} tok/s` : "";
    const tip = `modelo: ${a.model}` + (a.tokens ? ` · ${a.tokens} tokens em ${(a.ms / 1000).toFixed(1)}s` : "");
    return `<span class="badge ${VERDICT_BADGE[a.verdict] || "selo selo-neutro"} me-1" title="${tip}">it${a.iteration}: ${a.verdict}${spd}</span>`;
  }).join("");
  document.getElementById("repair-detail-trail").innerHTML =
    `<div class="small text-body-secondary mb-1">Tentativas</div>${trail || "—"}`;
  // num projeto multi-arquivo o defeito costuma estar em outro arquivo que não o
  // do ponto de entrada onde o bug foi reportado — deixar isso explícito
  const alvoFonte = (t.source || "").split("/").pop();
  const reparado = (t.repaired_file || "").split("/").pop();
  const ondeHtml = (reparado && reparado !== alvoFonte)
    ? `<div class="small text-info">Defeito localizado em <code>${escapeHtml(reparado)}</code>` +
      ` (o bug foi reportado a partir de <code>${escapeHtml(alvoFonte)}</code>, que tem o <code>main</code>).</div>`
    : "";
  document.getElementById("repair-detail-path").innerHTML = ondeHtml + (t.fixed_path
    ? `Arquivo corrigido: <code>${escapeHtml(t.fixed_path)}</code>`
    : "Não reparado.");

  const orig = t.original_code, fixed = t.final_code;
  const codeEl = document.getElementById("repair-detail-code");
  if (!orig && !fixed) {
    codeEl.innerHTML = '<div class="col-12 text-muted small">Código não embutido nesta run (rode um novo reparo para ver o diff lado a lado).</div>';
  } else {
    const fixedLabel = t.status === "REPAIRED" ? "Corrigido" : "Última tentativa";
    codeEl.innerHTML =
      `<div class="col-md-6"><div class="small text-body-secondary mb-1">Original</div><pre class="code-pane">${escapeHtml(orig || "")}</pre></div>` +
      `<div class="col-md-6"><div class="small text-body-secondary mb-1">${fixedLabel}</div><pre class="code-pane ${t.status === "REPAIRED" ? "code-fixed" : ""}">${escapeHtml(fixed || "")}</pre></div>`;
  }
  const card = document.getElementById("repair-detail");
  card.classList.remove("d-none");
  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// relatório de reparo em Markdown (humano)
function exportRepairReport() {
  if (!lastRepairResult) return;
  const r = lastRepairResult, s = r.summary || {};
  const L = [];
  L.push(`# Relatório de reparo, run ${lastRepairRunId || ""}`, "");
  L.push(`Gerado em ${new Date().toLocaleString("pt-BR")}`, "");
  L.push("## Resumo");
  L.push(`- Bugs: ${s.total || 0}`);
  L.push(`- Reparados: ${s.repaired || 0}`);
  L.push(`- Não reparados: ${s.not_repaired || 0}`);
  if (s.provider_errors) {
    L.push(`- Erros de provedor (429/cota, EXCLUÍDOS do denominador): ${s.provider_errors}`);
    L.push(`- Alvos efetivamente tentados (com resposta do LLM): ${s.attempted}`);
  }
  L.push(`- Iterações médias (quando reparado): ${s.avg_iterations_when_repaired || 0}`);
  L.push(`- Velocidade média de geração: ${s.avg_tok_s || 0} tok/s`, "");
  (r.targets || []).forEach((t) => {
    const ext = (/\.(\w+)$/.exec(t.target) || [, ""])[1];
    L.push(`## ${t.target}: ${t.status}`);
    L.push(`- Bug original: ${t.original_bug}`);
    L.push(`- Iterações: ${t.iterations}`);
    const trail = (t.attempts || []).map(a =>
      `it${a.iteration}:${a.verdict}${a.tok_s ? ` (${a.tok_s} tok/s)` : ""}`).join(" → ");
    L.push(`- Trilha (oráculo = verificador): ${trail || "—"}`);
    if (t.fixed_path) L.push(`- Arquivo corrigido: \`${t.fixed_path}\``);
    if (t.original_code) L.push("", "### Código original", "```" + ext, t.original_code, "```");
    if (t.final_code) L.push("", `### Código ${t.status === "REPAIRED" ? "corrigido (FIX_OK)" : "da última tentativa"}`, "```" + ext, t.final_code, "```");
    L.push("");
  });
  downloadText(`relatorio_reparo_${lastRepairRunId || "run"}.md`, L.join("\n"), "text/markdown");
}

// SARIF dos achados da verificação (máquina) — download via endpoint
function exportSarif() {
  if (!currentRunId) return;
  window.location.href = "/api/runs/" + currentRunId + "/sarif";
}

// Pasta da run em .zip. Com fix, vêm junto os <nome>_FIXED.<ext> gravados pelo
// reparo ao lado dos originais; sem fix, só o que foi enviado.
function downloadFolder(fixed) {
  if (!currentRunId) return;
  window.location.href = `/api/runs/${currentRunId}/download?fixed=${fixed ? "true" : "false"}`;
}

function showDetail(t) {
  document.getElementById("detail-title").textContent = t.target;
  const info = t.cwe_id ? `${t.cwe_id}${t.cwe_name ? " (" + t.cwe_name + ")" : ""}` : "—";
  document.getElementById("detail-meta").innerHTML = `
    <span class="badge ${STATUS_BADGE[t.status] || "selo selo-neutro"}">${t.status}</span>
    <span class="ms-2">Bug: <strong>${t.bug || "—"}</strong></span>
    <span class="ms-2">CWE: ${info}</span>
    <span class="ms-2">CERT: ${t.cert_priority ? "P" + t.cert_priority + " (" + (t.cert_level || "") + ")" : "—"}</span>
    <span class="ms-2 text-muted">${t.elapsed_s}s</span>
    <div class="text-muted mt-1">${t.source || ""}</div>`;
  document.getElementById("detail-explanation").textContent =
    t.explanation || "Sem contraexemplo (alvo não vulnerável até o bound).";
  const card = document.getElementById("detail-card");
  card.classList.remove("d-none");
  card.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ---------------- histórico ----------------
function markActiveHistory(id) {
  document.querySelectorAll("#history .history-item").forEach(li =>
    li.classList.toggle("active", li.dataset.id === id));
}

async function loadHistory() {
  const el = document.getElementById("history");
  try {
    const runs = await api.listRuns();
    if (!runs.length) { el.innerHTML = '<li class="list-group-item text-muted small">Nenhuma run ainda.</li>'; return; }
    el.innerHTML = runs.map(r => {
      const rm = r.repair_model;
      const tipo = rm ? "reparo" : "verificação";
      const llm = rm
        ? `${escapeHtml(rm.model)} <span class="text-body-tertiary">(${rm.local ? "local" : "nuvem"})</span>`
        : '<span class="text-body-tertiary">sem LLM</span>';
      // a pasta fica no título da linha: o histórico mostra só o que foi pedido
      return `<li class="list-group-item history-item hist-linha" data-id="${r.id}"
                  title="${escapeHtml(r.folder_label || "")}">
        <code class="hist-run">${r.id}</code>
        <span class="hist-data">${fmtDataHora(r.created_at)}${rm && rm.at
          ? `<br><span class="hist-reparo">reparo ${fmtDataHora(rm.at)}</span>` : ""}</span>
        <span class="hist-tipo">${tipo}</span>
        <span class="hist-llm text-truncate">${llm}</span>
        <button type="button" class="btn btn-sm btn-link p-0 history-del"
                data-id="${r.id}" data-label="${escapeHtml(r.folder_label || r.id)}"
                title="Apagar esta run e a pasta dela no servidor" aria-label="Apagar">${ICONE_LIXEIRA}</button>
      </li>`;
    }).join("");
    el.querySelectorAll(".history-item").forEach(li =>
      li.addEventListener("click", () => loadRun(li.dataset.id)));
    el.querySelectorAll(".history-del").forEach(b =>
      b.addEventListener("click", (e) => { e.stopPropagation(); deleteRun(b.dataset.id, b.dataset.label); }));
    markActiveHistory(currentRunId);
  } catch (e) {
    el.innerHTML = `<li class="list-group-item text-danger small">${e.message}</li>`;
  }
}

async function loadRun(id) {
  const rec = await api.getRun(id);
  if (rec.status === "done" || rec.status === "cancelled") {
    renderResults(rec);
    // reparo já feito nesta run: reexibe o resultado (e com ele os botões de
    // relatório e de baixar a pasta), senão abrir do histórico mostraria só a
    // verificação e o reparo pareceria perdido
    try {
      const rep = await api.getRepair(id);
      if (rep && rep.result) renderRepair(rep.result);   // renderRepair usa currentRunId, já setado por renderResults
    } catch { /* 404 = esta run nunca foi reparada */ }
    document.getElementById("results").scrollIntoView({ behavior: "smooth" });
  } else if (rec.status === "running") {
    startRun(id);
  }
}

// Apaga UMA run do histórico — e a pasta dela no servidor, quando nenhuma outra
// run ainda a usa. Substitui o antigo botão "Limpar", que levava tudo junto.
async function deleteRun(id, label) {
  if (!confirm(`Apagar a run ${id}${label ? ` (${label})` : ""}?\n\n` +
               "Some o relatório, o reparo e a pasta enviada no servidor. Não dá para desfazer.")) return;
  try {
    await api.deleteRun(id);
  } catch (e) {
    alert("Falha ao apagar: " + e.message);
    return;
  }
  if (currentRunId === id) {
    currentRunId = null;
    document.getElementById("results").classList.add("d-none");
    document.getElementById("repair-card").classList.add("d-none");
    document.getElementById("progress-card").classList.add("d-none");
  }
  loadHistory();
}

// Resiliência a reload: ao abrir a página, retoma o acompanhamento ao vivo de uma
// verificação OU de um reparo que ainda esteja rodando no servidor (o estado vive
// no backend; só a SPA havia perdido o vínculo após o refresh).
async function reconnectActive() {
  let runs;
  try { runs = await api.listRuns(); } catch { return; }
  if (!runs.length) return;
  const latest = runs[0];   // listRuns vem ordenado por created_at desc

  // 1) verificação em andamento -> reanexa a barra de progresso da verificação
  if (latest.status === "running") { startRun(latest.id); return; }

  // 2) run concluída mas com REPARO em andamento -> reanexa a barra do reparo
  let rep;
  try { rep = await api.getRepair(latest.id); } catch { return; }  // 404 = sem reparo
  if (rep && rep.status === "running") {
    currentRunId = latest.id;
    try { renderResults(await api.getRun(latest.id)); } catch { /* ignora */ }
    document.getElementById("repair-results").classList.add("d-none");
    document.getElementById("repair-progress").classList.remove("d-none");
    document.getElementById("repair-bar").classList.replace("bg-danger", "bg-primary");
    repairCancelling = false;
    const rcb = document.getElementById("btn-cancel-repair");
    rcb.disabled = false;
    rcb.innerHTML = 'Parar';
    document.getElementById("btn-repair").disabled = true;
    pollRepair();
  }
}

// ---------------- ambiente (health) ----------------
// Barra superior: servidor no ar, cada ferramenta em verde (pronta) ou vermelho
// (ausente; a ausência silenciosa foi o que mascarou o MathSAT) e a RAM da
// máquina, que sobe rápido quando o ESBMC prova código com threads.
function renderRam(m) {
  const el = document.getElementById("ram");
  if (!m) { el.innerHTML = ""; return; }
  const gb = (mb) => (mb / 1024).toFixed(1).replace(".", ",");
  const cls = { ok: "tom-bom", atencao: "tom-aviso", alerta: "tom-ruim" }[m.nivel] || "";
  const aviso = m.nivel === "alerta" ? " · memória alta" : "";
  el.className = cls;
  el.title = `${m.pct}% da RAM em uso na máquina`;
  el.textContent = `RAM ${gb(m.usado_mb)} / ${gb(m.total_mb)} GB${aviso}`;
}

// Caixa da barra durante a verificação: o que está rodando agora (verificador e
// compilador), com memória e tempo de cada um, junto da RAM da máquina.
function renderEmUso(lista) {
  const el = document.getElementById("em-uso");
  const caixa = document.getElementById("caixa-uso");
  const ativos = lista || [];
  caixa.classList.toggle("ativa", ativos.length > 0);
  if (!ativos.length) { el.innerHTML = ""; return; }
  const gb = (mb) => mb >= 1024 ? (mb / 1024).toFixed(1).replace(".", ",") + " GB" : mb + " MB";
  const dur = (s) => s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`;
  el.innerHTML = ativos.map((a) =>
    `<span title="${a.papel}"><span class="uso-nome">${escapeHtml(a.nome)}</span> ${gb(a.rss_mb)} · ${dur(a.tempo_s)}</span>`
  ).join('<span class="text-body-tertiary"> | </span>') + '<span class="uso-sep"></span>';
}

let healthTimer = null;

async function loadHealth() {
  const st = document.getElementById("api-status");
  const tools = document.getElementById("tools");
  try {
    const d = await api.health();
    // Sem `tools` = respondeu ao anônimo (sessão expirada): o servidor está de
    // pé, mas nós é que não estamos mais logados.
    if (!d.tools) {
      st.className = "amb-status tom-aviso";
      st.textContent = "sessão expirada";
      tools.innerHTML = '<a href="/login.html">entrar de novo</a>';
      renderRam(null);
      return;
    }
    updateRepairBadge();
    st.className = "amb-status tom-bom";
    st.textContent = "online";
    tools.innerHTML = Object.entries(d.tools).map(([name, info]) => {
      const cls = info.available ? "tom-bom" : "tom-ruim text-decoration-line-through";
      const tip = info.available ? (info.path || "") : "indisponível";
      return `<span class="${cls}" title="${escapeHtml(tip)}">${escapeHtml(name)}</span>`;
    }).join(' <span class="text-body-tertiary">·</span> ');
    renderRam(d.memoria);
    renderEmUso(d.em_uso);
  } catch {
    st.className = "amb-status tom-ruim";
    st.textContent = "offline";
    tools.innerHTML = "";
    renderRam(null);
    renderEmUso(null);
  }
  // com algo rodando a barra atualiza a cada 3 s; parada, a cada 10 s
  clearTimeout(healthTimer);
  const ativo = document.getElementById("caixa-uso").classList.contains("ativa");
  healthTimer = setTimeout(loadHealth, ativo ? 3000 : 10000);
}

// ---------------- configuração do LLM (pop-up) ----------------
// ---------------- Upload de pasta (cliente -> servidor) ----------------
// Mantém em sincronia com scanner.scan()/constants.C_FAMILY_EXTS: família C + JVM.
const SOURCE_EXT_RE = /\.(c|cpp|cc|cxx|c\+\+|java|kt)$/i;

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + " MB";
  return (n / 1024 / 1024 / 1024).toFixed(2) + " GB";
}

async function uploadPickedFolder(ev) {
  const input = ev.target;
  const files = Array.from(input.files || []);
  if (!files.length) return;

  // só envia o que o scanner reconhece (família C/.java/.kt) — evita arrastar lixo.
  const picked = files.filter(f => SOURCE_EXT_RE.test(f.name));
  if (!picked.length) {
    alert("Nenhum arquivo .c/.cpp/.java/.kt na pasta selecionada.");
    input.value = "";
    return;
  }
  // nome lógico da pasta = primeiro segmento do webkitRelativePath
  const rootName = (picked[0].webkitRelativePath || picked[0].name).split("/")[0] || "upload";

  const fd = new FormData();
  let total = 0;
  picked.forEach(f => {
    const rel = f.webkitRelativePath || f.name;
    fd.append("files", f, f.name);
    fd.append("paths", rel);
    total += f.size;
  });

  const wrap = document.getElementById("upload-progress");
  const bar  = document.getElementById("upload-bar");
  const pct  = document.getElementById("upload-pct");
  const meta = document.getElementById("upload-meta");
  wrap.classList.remove("d-none");
  bar.style.width = "0%"; pct.textContent = "0";
  meta.textContent = `${picked.length} arquivos · ${fmtBytes(total)} · pasta "${rootName}"`;

  try {
    const data = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/uploads");
      xhr.withCredentials = true;
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const p = Math.round(e.loaded * 100 / e.total);
          bar.style.width = p + "%"; pct.textContent = String(p);
        }
      };
      xhr.onload = () => {
        if (xhr.status === 401) { location.href = "/login.html"; return; }
        const j = (() => { try { return JSON.parse(xhr.responseText); } catch { return {}; } })();
        if (xhr.status >= 200 && xhr.status < 300) resolve(j);
        else reject(new Error(j.detail || ("HTTP " + xhr.status)));
      };
      xhr.onerror = () => reject(new Error("falha de rede"));
      xhr.send(fd);
    });
    setFolder(data.folder, data.label || rootName);
    meta.innerHTML =
      `<span class="text-success">${data.count} arquivos · ${fmtBytes(data.total_bytes)}</span> · <code>${data.label || rootName}</code>`;
  } catch (e) {
    wrap.classList.add("d-none");
    alert("Falha no upload: " + e.message);
  } finally {
    input.value = ""; // permite re-selecionar a mesma pasta depois
  }
}

// Provedores OpenAI-compatíveis + modelos sugeridos (editáveis: nomes mudam,
// confira a lista do provedor). A config fica no localStorage do navegador.
const LLM_PROVIDERS = {
  deepseek: {
    base: "https://api.deepseek.com",
    models: ["deepseek-v4-flash", "deepseek-v4-pro"],
  },
  groq: {
    base: "https://api.groq.com/openai/v1",
    models: ["llama-3.3-70b-versatile", "deepseek-r1-distill-llama-70b",
             "moonshotai/kimi-k2-instruct", "openai/gpt-oss-120b"],
  },
  openrouter: {
    base: "https://openrouter.ai/api/v1",
    models: ["deepseek/deepseek-chat", "deepseek/deepseek-r1",
             "anthropic/claude-sonnet-4.5", "qwen/qwen-2.5-coder-32b-instruct",
             "google/gemini-2.5-pro"],
  },
  local: {
    base: "http://localhost:11434/v1",
    models: ["deepseek-coder-v2:16b", "qwen2.5:14b", "qwen3-coder:30b"],
    keyless: true,  // Ollama não exige API key
  },
  custom: { base: "", models: [] },
};
const LLM_CFG_KEY = "smart_llm_cfg";

function loadLLMConfig() {
  try { return JSON.parse(localStorage.getItem(LLM_CFG_KEY)) || {}; } catch { return {}; }
}

function updateRepairBadge() {
  const badge = document.getElementById("repair-model-badge");
  if (!badge) return;
  const dry = document.getElementById("repair-dryrun");
  if (dry && dry.checked) { badge.textContent = "dry-run"; return; }
  const cfg = loadLLMConfig();
  if (cfg.model) { badge.textContent = `${cfg.provider || "custom"} · ${cfg.model}`; return; }
  badge.textContent = "configurar LLM";
}

function fillModelSuggestions(provider) {
  const models = (LLM_PROVIDERS[provider] || {}).models || [];
  document.getElementById("cfg-model-list").innerHTML =
    models.map(m => `<option value="${m}">`).join("");
  // as sugestões aparecem na própria lista do campo; sem texto embaixo
  document.getElementById("cfg-model-hint").textContent = "";
}

function openSettings() {
  const cfg = loadLLMConfig();
  const provider = cfg.provider || "deepseek";
  document.getElementById("cfg-provider").value = provider;
  document.getElementById("cfg-baseurl").value =
    cfg.base_url || (LLM_PROVIDERS[provider] || {}).base || "";
  document.getElementById("cfg-key").value = cfg.api_key || "";
  document.getElementById("cfg-model").value =
    cfg.model || ((LLM_PROVIDERS[provider] || {}).models || [])[0] || "";
  fillModelSuggestions(provider);
  applyProviderUI(provider);
  document.getElementById("cfg-saved").classList.add("d-none");
  document.getElementById("settings-overlay").classList.remove("d-none");
}

function closeAdv() {
  document.getElementById("adv-overlay").classList.add("d-none");
  updateAdvSummary();
}

// Mostra ao lado do botão o que está definido, para a opção não ficar
// escondida no pop-up e valer numa run sem a pessoa perceber.
function updateAdvSummary() {
  const n = (id) => (document.getElementById(id).value || "").split("\n").filter((l) => l.trim()).length;
  const partes = [];
  if (n("f-include-dirs")) partes.push(`${n("f-include-dirs")} pasta(s) de headers`);
  if (n("f-link-unit")) partes.push(`${n("f-link-unit")} arquivo(s) juntos`);
  const fn = document.getElementById("f-function").value.trim();
  if (fn) partes.push(`entrada ${fn}()`);
  document.getElementById("adv-resumo").textContent = partes.join(", ");
  // sem nada definido, a linha nem aparece
  document.getElementById("adv-linha").classList.toggle("d-none", !partes.length);
}

function closeSettings() {
  document.getElementById("settings-overlay").classList.add("d-none");
}

function onProviderChange() {
  const provider = document.getElementById("cfg-provider").value;
  if (provider !== "custom") {
    document.getElementById("cfg-baseurl").value = (LLM_PROVIDERS[provider] || {}).base || "";
  }
  fillModelSuggestions(provider);
  const models = (LLM_PROVIDERS[provider] || {}).models || [];
  const cur = document.getElementById("cfg-model").value;
  if (models.length && !models.includes(cur)) document.getElementById("cfg-model").value = models[0];
  applyProviderUI(provider);
}

function applyProviderUI(provider) {
  // Quando o provedor é local (Ollama), a API key é desnecessária e a base URL
  // sempre aponta para o Ollama do SERVIDOR (não do PC do cliente).
  const isLocal  = provider === "local";
  const keyless  = !!(LLM_PROVIDERS[provider] || {}).keyless;
  const keyInput = document.getElementById("cfg-key");
  const baseInput = document.getElementById("cfg-baseurl");

  // ---- Endereço e chave: no local o servidor usa o próprio Ollama, então somem ----
  document.getElementById("cfg-key-wrap").classList.toggle("d-none", keyless);
  document.getElementById("cfg-base-wrap").classList.toggle("d-none", isLocal);
  if (keyless) keyInput.value = "";
  keyInput.disabled = keyless;
  if (isLocal) baseInput.value = LLM_PROVIDERS.local.base;
  baseInput.readOnly = isLocal;

  // ---- Modelo: input livre (remotos) OU select dropdown (Ollama do servidor) ----
  const hint    = document.getElementById("cfg-model-hint");
  const mInput  = document.getElementById("cfg-model");
  const mSelect = document.getElementById("cfg-model-select");
  if (isLocal) {
    mInput.classList.add("d-none");
    mSelect.classList.remove("d-none");
    mSelect.innerHTML = '<option>verificando…</option>';
    mSelect.disabled = true;
    hint.textContent = "consultando o Ollama do servidor…";
    api.localLlmStatus().then(s => {
      const realModels = s.available ? (s.models || []) : [];
      if (!s.available) {
        mSelect.innerHTML = '<option value="">(Ollama indisponível)</option>';
        mSelect.disabled = true;
        // a dica do servidor diz como resolver; o erro técnico fica no título
        hint.innerHTML = '<span class="tom-ruim">Ollama indisponível no servidor.</span> ' +
          escapeHtml(s.hint || "Peça ao administrador para iniciar o Ollama.");
        hint.title = s.error || "";
        return;
      }
      // popula o select com TODOS os modelos baixados no Ollama do servidor
      const cur = mInput.value;
      const preferred = cur && realModels.includes(cur)
        ? cur
        : (realModels.find(m => /deepseek|coder/i.test(m)) || realModels[0] || "");
      mSelect.innerHTML = realModels
        .map(m => `<option value="${m}"${m === preferred ? " selected" : ""}>${m}</option>`)
        .join("");
      mSelect.disabled = false;
      mInput.value = preferred; // mantém o input sincronizado (saveSettings lê dele)
      hint.textContent = `${realModels.length} ${realModels.length === 1 ? "modelo instalado" : "modelos instalados"} no servidor`;
    }).catch(e => {
      mSelect.innerHTML = '<option value="">(erro)</option>';
      hint.innerHTML = '<span class="tom-ruim">Não foi possível consultar o Ollama do servidor.</span>';
      hint.title = e.message || String(e);
    });
  } else {
    mInput.classList.remove("d-none");
    mSelect.classList.add("d-none");
  }
  // (para não-local, fillModelSuggestions já cuidou do hint)

}

function saveSettings() {
  const provider = document.getElementById("cfg-provider").value;
  // força a base do Ollama do servidor para 'local' (ignora valor antigo no localStorage)
  const base_url = provider === "local"
    ? LLM_PROVIDERS.local.base
    : document.getElementById("cfg-baseurl").value.trim();
  // para provedor local, o modelo vem do select (dropdown); para os outros, do input livre
  const model = provider === "local"
    ? document.getElementById("cfg-model-select").value
    : document.getElementById("cfg-model").value.trim();
  const cfg = {
    provider,
    base_url,
    api_key: document.getElementById("cfg-key").value.trim(),
    model,
  };
  localStorage.setItem(LLM_CFG_KEY, JSON.stringify(cfg));
  document.getElementById("cfg-saved").classList.remove("d-none");
  updateRepairBadge();
  setTimeout(closeSettings, 700);
}

function clearSettings() {
  localStorage.removeItem(LLM_CFG_KEY);
  document.getElementById("cfg-key").value = "";
  document.getElementById("cfg-model").value = "";
  document.getElementById("cfg-saved").classList.add("d-none");
  onProviderChange();
  updateRepairBadge();
}

function toggleKeyVisibility() {
  const el = document.getElementById("cfg-key");
  el.type = el.type === "password" ? "text" : "password";
}

// ---------------- limpar histórico ----------------
// ---------------- init ----------------
function init() {
  // máximo de jobs = núcleos da máquina (dica do navegador)
  const cores = navigator.hardwareConcurrency || 8;
  const jobsEl = document.getElementById("f-jobs");
  jobsEl.max = cores;
  document.getElementById("jobs-hint").textContent = `mín 1 · máx ${cores} (núcleos)`;

  document.getElementById("run-form").addEventListener("submit", launchRun);
  document.getElementById("btn-refresh-hist").addEventListener("click", loadHistory);
  document.getElementById("btn-cancel-run").addEventListener("click", cancelCurrentRun);
  document.getElementById("btn-upload").addEventListener("click", () =>
    document.getElementById("folder-picker").click());
  document.getElementById("folder-picker").addEventListener("change", uploadPickedFolder);
  document.getElementById("btn-repair").addEventListener("click", launchRepair);
  document.getElementById("btn-cancel-repair").addEventListener("click", cancelCurrentRepair);
  document.getElementById("repair-dryrun").addEventListener("change", updateRepairBadge);
  document.getElementById("btn-export-repair").addEventListener("click", exportRepairReport);
  document.getElementById("btn-export-sarif").addEventListener("click", exportSarif);
  document.getElementById("btn-dl-fixed").addEventListener("click", () => downloadFolder(true));
  document.getElementById("btn-dl-original").addEventListener("click", () => downloadFolder(false));
  // digitou/colou um caminho à mão: o rótulo do upload não vale mais
  document.getElementById("f-folder").addEventListener("input", (e) => {
    delete e.currentTarget.dataset.real;
  });

  // Histórico recolhível; a escolha fica neste navegador
  const histCorpo = document.getElementById("hist-corpo");
  const histBtn = document.getElementById("btn-toggle-hist");
  const aplicaHist = (recolhido) => {
    histCorpo.classList.toggle("d-none", recolhido);
    document.getElementById("hist-dica").classList.toggle("d-none", recolhido);
    histBtn.textContent = recolhido ? "Mostrar" : "Recolher";
    histBtn.setAttribute("aria-expanded", String(!recolhido));
  };
  let histRecolhido = false;
  try { histRecolhido = localStorage.getItem("smart-hist-recolhido") === "1"; } catch { /* ignora */ }
  aplicaHist(histRecolhido);
  histBtn.addEventListener("click", () => {
    histRecolhido = !histRecolhido;
    aplicaHist(histRecolhido);
    try { localStorage.setItem("smart-hist-recolhido", histRecolhido ? "1" : "0"); } catch { /* ignora */ }
  });

  // Pop-up das opções de projeto (-I, arquivos juntos, função de entrada)
  document.getElementById("adv-resumo").addEventListener("click", (e) => {
    e.preventDefault();
    document.getElementById("adv-overlay").classList.remove("d-none");
  });
  document.getElementById("btn-adv").addEventListener("click", () =>
    document.getElementById("adv-overlay").classList.remove("d-none"));
  document.getElementById("adv-close").addEventListener("click", closeAdv);
  document.getElementById("adv-ok").addEventListener("click", closeAdv);
  document.getElementById("adv-clear").addEventListener("click", () => {
    ["f-include-dirs", "f-link-unit", "f-function"].forEach((id) => {
      document.getElementById(id).value = "";
    });
    updateAdvSummary();
  });
  document.getElementById("adv-overlay").addEventListener("click", (e) => {
    if (e.target.id === "adv-overlay") closeAdv();
  });

  // Pop-up de configuração do LLM (navbar + no card de reparo, na hora do contraexemplo)
  document.getElementById("btn-settings").addEventListener("click", openSettings);
  document.getElementById("btn-settings-repair").addEventListener("click", openSettings);
  document.getElementById("settings-close").addEventListener("click", closeSettings);
  document.getElementById("cfg-provider").addEventListener("change", onProviderChange);
  document.getElementById("cfg-save").addEventListener("click", saveSettings);
  document.getElementById("cfg-clear").addEventListener("click", clearSettings);
  document.getElementById("cfg-key-toggle").addEventListener("click", toggleKeyVisibility);
  document.getElementById("settings-overlay").addEventListener("click", (e) => {
    if (e.target.id === "settings-overlay") closeSettings();   // clicar fora fecha
  });

  loadHealth();                      // reagenda a si mesma (3 s rodando, 10 s parada)
  loadHistory();
  loadSolvers();       // só oferece solvers compilados neste build do ESBMC
  updateRepairBadge();
  reconnectActive();   // resiliência a reload acidental: retoma run/reparo em andamento
}

// Desabilita no dropdown os solvers que NÃO estão compilados neste ESBMC
// (ex.: mathsat ausente vira ERROR em todos os alvos). Falha silenciosa: se a
// consulta der erro, mantém todas as opções (o backend ainda cai p/ boolector).
async function loadSolvers() {
  try {
    const { available } = await api.solvers();
    const sel = document.getElementById("f-solver");
    const hint = document.getElementById("solver-hint");
    const avail = new Set(available || []);
    let changed = false;
    for (const opt of sel.options) {
      if (avail.size && !avail.has(opt.value)) {
        opt.disabled = true;
        opt.textContent += " (indisponível neste build)";
        if (opt.selected) changed = true;
      }
    }
    if (changed && avail.size) sel.value = available[0];
    if (hint) hint.textContent = avail.size ? `compilados: ${available.join(", ")}` : "";
  } catch { /* mantém opções; backend valida e cai p/ boolector */ }
}

document.addEventListener("DOMContentLoaded", init);
