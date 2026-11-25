'use strict';

const state = {
  contracts: [],
  selectedId: null,
  running: false,
};

const el = {
  list: document.getElementById('contract-list'),
  run: document.getElementById('run'),
  runHint: document.getElementById('run-hint'),
  log: document.getElementById('log'),
  report: document.getElementById('report'),
  severity: document.getElementById('severity-badge'),
  verdict: document.getElementById('verdict-badge'),
  title: document.getElementById('finding-title'),
  impact: document.getElementById('impact'),
  exploitPath: document.getElementById('exploit-path'),
  pocPath: document.getElementById('poc-path'),
  pocCode: document.getElementById('poc-code'),
  forgeOutput: document.getElementById('forge-output'),
  fix: document.getElementById('fix'),
  key: document.getElementById('llm-key'),
  baseUrl: document.getElementById('llm-base'),
  modeNote: document.getElementById('mode-note'),
  repoInput: document.getElementById('repo-url'),
  repoRun: document.getElementById('repo-run'),
  repoHint: document.getElementById('repo-hint'),
  repoResults: document.getElementById('repo-results'),
  repoName: document.getElementById('repo-name'),
  repoStats: document.getElementById('repo-stats'),
  repoTruncated: document.getElementById('repo-truncated'),
  repoContractNames: document.getElementById('repo-contract-names'),
  repoGates: document.getElementById('repo-gates'),
  repoSurface: document.getElementById('repo-surface'),
  repoNote: document.getElementById('repo-note'),
};

function setRunning(running) {
  state.running = running;
  el.run.disabled = running || !state.selectedId;
  el.run.textContent = running ? 'Running…' : 'Run Audit';
  el.key.disabled = running;
  el.baseUrl.disabled = running;
  el.repoRun.disabled = running;
  el.repoInput.disabled = running;
  el.runHint.textContent = running
    ? 'Pipeline running — steps stream in below.'
    : state.selectedId
      ? 'Ready. Empty key runs the recorded PoC trace.'
      : 'Pick a contract to enable the audit.';
}

function selectContract(id) {
  if (state.running) return;
  state.selectedId = id;
  for (const node of el.list.querySelectorAll('[data-contract-id]')) {
    const active = node.dataset.contractId === id;
    node.classList.toggle('selected', active);
    node.setAttribute('aria-checked', String(active));
  }
  setRunning(false);
}

function renderContracts(contracts) {
  state.contracts = contracts;
  el.list.replaceChildren();

  for (const contract of contracts) {
    const available = contract.status === 'available';
    const node = document.createElement('button');
    node.type = 'button';
    node.className = `contract ${available ? '' : 'disabled'}`.trim();
    node.dataset.contractId = contract.id;
    node.setAttribute('role', 'radio');
    node.setAttribute('aria-checked', 'false');
    node.disabled = !available;

    const title = document.createElement('span');
    title.className = 'contract-title';
    title.textContent = contract.name;

    const meta = document.createElement('span');
    meta.className = 'contract-meta';
    meta.textContent = contract.contract;

    const desc = document.createElement('span');
    desc.className = 'contract-desc';
    desc.textContent = contract.description;

    const tag = document.createElement('span');
    tag.className = `tag ${available ? 'available' : 'later'}`;
    tag.textContent = available ? 'available' : 'Day 2';

    node.append(title, meta, desc, tag);
    if (available) node.addEventListener('click', () => selectContract(contract.id));
    el.list.append(node);
  }

  const first = contracts.find((c) => c.status === 'available');
  if (first) selectContract(first.id);
}

function clearLog() {
  el.log.replaceChildren();
}

function appendLog(message, kind) {
  const item = document.createElement('li');
  item.className = `log-item ${kind || ''}`.trim();
  const time = document.createElement('span');
  time.className = 'log-time';
  time.textContent = new Date().toLocaleTimeString([], { hour12: false });
  const text = document.createElement('span');
  text.textContent = message;
  item.append(time, text);
  el.log.append(item);
  el.log.scrollTop = el.log.scrollHeight;
}

function showReport(report) {
  const confirmed = report.verdict === 'VULNERABILITY CONFIRMED';
  el.report.hidden = false;

  el.severity.textContent = `${report.severity || 'Unknown'} severity`;
  el.severity.className = `badge severity ${confirmed ? 'high' : 'low'}`;

  el.verdict.textContent = report.verdict || 'UNKNOWN';
  el.verdict.className = `badge verdict ${confirmed ? 'confirmed' : 'unconfirmed'}`;

  el.title.textContent = report.title || '';
  el.impact.textContent = report.impact || '';
  el.exploitPath.textContent = report.exploitPath || '';
  el.pocCode.textContent = report.pocCode || '';
  el.forgeOutput.textContent = report.forgeOutput || '';
  el.fix.textContent = report.fixSuggestion || '';
  el.pocPath.textContent = report.pocPath || (report.meta && report.meta.pocPath) || '';

  if (report.meta && report.meta.pocGenerator) {
    el.modeNote.textContent =
      report.meta.pocGenerator === 'llm'
        ? 'PoC generated by LLM'
        : report.meta.pocGenerator === 'demo-fallback'
          ? 'LLM failed — recorded trace used'
          : 'Demo mode — recorded trace';
  }

  el.report.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function parseSseFrame(frame) {
  let event = 'message';
  const dataLines = [];
  for (const line of frame.split('\n')) {
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) dataLines.push(line.slice(5).trimStart());
  }
  if (!dataLines.length) return null;
  const raw = dataLines.join('\n');
  try {
    return { event, data: JSON.parse(raw) };
  } catch {
    return { event, data: raw };
  }
}

async function runAudit() {
  if (!state.selectedId || state.running) return;

  setRunning(true);
  clearLog();
  el.report.hidden = true;

  const payload = { contractId: state.selectedId };
  const key = el.key.value.trim();
  if (key) payload.llmApiKey = key;
  const baseUrl = el.baseUrl.value.trim();
  if (baseUrl) payload.llmBaseUrl = baseUrl;

  let streamed = false;
  let failed = false;

  try {
    const response = await fetch('/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify(payload),
    });

    if (!response.ok || !response.body) {
      let detail = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body && body.error) detail = body.error;
      } catch (_) { /* keep status text */ }
      appendLog(`Error: ${detail}`, 'error');
      failed = true;
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const parsed = parseSseFrame(frame);
        if (!parsed) continue;

        if (parsed.event === 'step' && parsed.data && parsed.data.message) {
          streamed = true;
          appendLog(parsed.data.message);
        } else if (parsed.event === 'report') {
          streamed = true;
          appendLog('Report ready.', 'ok');
          showReport(parsed.data);
        } else if (parsed.event === 'error') {
          failed = true;
          appendLog(`Error: ${parsed.data.error || 'pipeline error'}`, 'error');
        }
      }
    }
  } catch (err) {
    failed = true;
    appendLog(`Error: ${err.message}`, 'error');
  } finally {
    el.key.value = '';
    setRunning(false);
    if (!streamed && !failed) appendLog('Stream closed without a report.', 'error');
  }
}

el.run.addEventListener('click', runAudit);

function setRepoHint(text) {
  el.repoHint.textContent = text;
}

function renderTriage(triage) {
  el.repoResults.hidden = false;

  el.repoName.textContent = triage.repo || 'unknown repo';
  el.repoStats.textContent =
    `${triage.totalFiles} file${triage.totalFiles === 1 ? '' : 's'} · ` +
    `${triage.totalLoc} LOC · ` +
    `${(triage.contractNames || []).length} contract name${(triage.contractNames || []).length === 1 ? '' : 's'}` +
    (triage.truncated ? ' · truncated at 200 files' : '');

  el.repoTruncated.hidden = !triage.truncated;
  el.repoTruncated.textContent = triage.truncated
    ? 'File list truncated at 200 .sol files; gates reflect the partial map.'
    : '';

  el.repoContractNames.replaceChildren();
  const names = triage.contractNames || [];
  if (!names.length) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = 'No contract/interface/library names found.';
    el.repoContractNames.append(li);
  } else {
    for (const name of names) {
      const li = document.createElement('li');
      li.textContent = name;
      el.repoContractNames.append(li);
    }
  }

  el.repoGates.replaceChildren();
  for (const gate of triage.gates || []) {
    const tr = document.createElement('tr');
    const nameCell = document.createElement('td');
    nameCell.textContent = gate.name || gate.id;

    const statusCell = document.createElement('td');
    const badge = document.createElement('span');
    badge.className = `badge gate-status ${gate.status}`;
    badge.textContent = gate.status;
    statusCell.append(badge);

    const evidenceCell = document.createElement('td');
    evidenceCell.textContent = gate.evidence || '';

    tr.append(nameCell, statusCell, evidenceCell);
    el.repoGates.append(tr);
  }

  el.repoSurface.replaceChildren();
  const surface = triage.topSurface || {};
  const surfaceTitle = document.createElement('strong');
  surfaceTitle.textContent = surface.surface || 'No surface selected';
  const surfaceReason = document.createElement('span');
  surfaceReason.className = 'surface-reason';
  surfaceReason.textContent = surface.reason || '';
  const surfaceFile = document.createElement('code');
  surfaceFile.className = 'surface-file';
  surfaceFile.textContent = surface.file || '(no file)';
  el.repoSurface.append(surfaceTitle, surfaceReason, surfaceFile);

  el.repoNote.textContent = triage.note || '';

  el.repoResults.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function runRepoTriage() {
  if (state.running) return;
  const repoUrl = el.repoInput.value.trim();
  if (!repoUrl) {
    setRepoHint('Enter a public GitHub repository URL first.');
    return;
  }

  setRunning(true);
  el.repoRun.textContent = 'Triaging…';
  el.repoResults.hidden = true;
  setRepoHint('Starting triage…');

  let gotTriage = false;
  let failed = false;

  try {
    const response = await fetch('/api/repo-audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
      body: JSON.stringify({ repoUrl }),
    });

    if (!response.ok || !response.body) {
      let detail = `HTTP ${response.status}`;
      try {
        const body = await response.json();
        if (body && body.error) detail = body.error;
      } catch (_) { /* keep status text */ }
      setRepoHint(`Error: ${detail}`);
      failed = true;
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let latest = '';

    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const parsed = parseSseFrame(frame);
        if (!parsed) continue;

        if (parsed.event === 'step' && parsed.data && parsed.data.message) {
          latest = parsed.data.message;
          setRepoHint(latest);
        } else if (parsed.event === 'triage') {
          gotTriage = true;
          renderTriage(parsed.data);
          setRepoHint(`Triage complete — ${parsed.data.repo || repoUrl}`);
        } else if (parsed.event === 'error') {
          failed = true;
          setRepoHint(`Error: ${parsed.data.error || 'repo audit error'}`);
        }
      }
    }
  } catch (err) {
    failed = true;
    setRepoHint(`Error: ${err.message}`);
  } finally {
    setRunning(false);
    el.repoRun.textContent = 'Triage repo';
    if (!gotTriage && !failed) setRepoHint('Stream closed without a triage report.');
  }
}

el.repoRun.addEventListener('click', runRepoTriage);
el.repoInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') runRepoTriage();
});


(async function init() {
  setRunning(false);
  try {
    const response = await fetch('/api/demo-contracts');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await response.json();
    renderContracts(body.contracts || []);
  } catch (err) {
    el.list.replaceChildren();
    const problem = document.createElement('p');
    problem.className = 'muted error';
    problem.textContent = `Could not load demo contracts: ${err.message}`;
    el.list.append(problem);
  }
})();
