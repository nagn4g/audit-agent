'use strict';

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');

const { DEMO_CONTRACTS, PipelineError, runAudit } = require('./lib/pipeline');
const { parseGitHubUrl, cloneRepo, removeDir, mapContracts, screenRepo, topSurface } = require('./lib/repo');

const HOST = '127.0.0.1';
const PORT = 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_BODY_BYTES = 16 * 1024;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new PipelineError('Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function serveStatic(res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const target = path.join(PUBLIC_DIR, rel);
  if (!target.startsWith(PUBLIC_DIR + path.sep)) {
    return sendJson(res, 403, { error: 'Forbidden' });
  }
  try {
    const body = await fs.readFile(target);
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(target)] || 'application/octet-stream',
      'Content-Length': body.length,
      'Cache-Control': 'no-store',
    });
    res.end(body);
  } catch {
    sendJson(res, 404, { error: 'Not found' });
  }
}

function sseWrite(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

async function handleAudit(req, res) {
  let payload;
  try {
    const raw = await readBody(req);
    payload = raw ? JSON.parse(raw) : {};
  } catch (err) {
    return sendJson(res, 400, { error: `Invalid JSON body: ${err.message}` });
  }

  const contractId = typeof payload.contractId === 'string' ? payload.contractId : '';
  const llmApiKey = typeof payload.llmApiKey === 'string' ? payload.llmApiKey.trim() : '';
  const llmBaseUrl = typeof payload.llmBaseUrl === 'string' ? payload.llmBaseUrl.trim() : '';

  if (!contractId) return sendJson(res, 400, { error: 'contractId is required' });
  const known = DEMO_CONTRACTS.find((c) => c.id === contractId && c.status === 'available');
  if (!known) return sendJson(res, 400, { error: `Contract "${contractId}" is not available` });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': stream open\n\n');

  const controller = new AbortController();
  res.on('close', () => controller.abort());

  const emitStep = (message) => {
    if (!res.writableEnded) sseWrite(res, 'step', { message });
  };

  const keepAlive = setInterval(() => {
    if (!res.writableEnded) res.write(': keep-alive\n\n');
  }, 15_000);

  try {
    const report = await runAudit({ contractId, llmApiKey, llmBaseUrl, emitStep, signal: controller.signal });
    if (!res.writableEnded) sseWrite(res, 'report', report);
  } catch (err) {
    const message = err instanceof PipelineError ? err.message : `Pipeline error: ${err.message}`;
    emitStep(`Error: ${message}`);
    if (!res.writableEnded) sseWrite(res, 'error', { error: message });
  } finally {
    clearInterval(keepAlive);
    if (!res.writableEnded) res.end();
  }
}

async function handleRepoAudit(req, res) {
  let payload;
  try {
    const raw = await readBody(req);
    payload = raw ? JSON.parse(raw) : {};
  } catch (err) {
    return sendJson(res, 400, { error: `Invalid JSON body: ${err.message}` });
  }

  const repoUrl = typeof payload.repoUrl === 'string' ? payload.repoUrl.trim() : '';
  // llmApiKey / llmBaseUrl are accepted for forward-compatibility but unused:
  // repo triage is a deterministic heuristic screen and never calls the LLM.
  if (!repoUrl) return sendJson(res, 400, { error: 'repoUrl is required' });

  let parsed;
  try {
    parsed = parseGitHubUrl(repoUrl);
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }
  const repoSlug = `${parsed.owner}/${parsed.repo}`;

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write(': stream open\n\n');

  const controller = new AbortController();
  res.on('close', () => controller.abort());

  const emitStep = (message) => {
    if (!res.writableEnded) sseWrite(res, 'step', { message });
  };

  const keepAlive = setInterval(() => {
    if (!res.writableEnded) res.write(': keep-alive\n\n');
  }, 15_000);

  let cloneDir = null;
  try {
    emitStep(`Validating URL — ${repoSlug}`);
    emitStep(`Cloning ${repoSlug} (shallow, depth 1)`);

    cloneDir = await cloneRepo(parsed.owner, parsed.repo, { signal: controller.signal });

    emitStep('Mapping contracts');
    const map = await mapContracts(cloneDir);
    emitStep(`Mapping contracts — ${map.totalFiles} file(s), ${map.totalLoc} LOC`);

    emitStep('Running 10-gate screen');
    const { gates, note } = screenRepo(map);
    const surface = topSurface(map, gates);

    const triage = {
      repo: repoSlug,
      files: map.files,
      totalFiles: map.totalFiles,
      totalLoc: map.totalLoc,
      contractNames: map.contractNames,
      truncated: map.truncated,
      gates,
      topSurface: surface,
      note,
    };
    emitStep('Screen complete');
    if (!res.writableEnded) sseWrite(res, 'triage', triage);
  } catch (err) {
    const message = err instanceof PipelineError ? err.message : `Repo audit error: ${err.message}`;
    emitStep(`Error: ${message}`);
    if (!res.writableEnded) sseWrite(res, 'error', { error: message });
  } finally {
    clearInterval(keepAlive);
    await removeDir(cloneDir);
    if (!res.writableEnded) res.end();
  }
}

function handleRequest(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);

  if (req.method === 'GET' && url.pathname === '/api/demo-contracts') {
    return sendJson(res, 200, { contracts: DEMO_CONTRACTS });
  }
  if (req.method === 'POST' && url.pathname === '/api/audit') {
    return handleAudit(req, res);
  }
  if (req.method === 'POST' && url.pathname === '/api/repo-audit') {
    return handleRepoAudit(req, res);
  }
  if (req.method === 'GET' && (url.pathname === '/' || /^\/[\w.-]+\.(html|js|css|svg|ico)$/.test(url.pathname))) {
    return serveStatic(res, url.pathname);
  }
  return sendJson(res, 404, { error: 'Not found' });
}

function createServer() {
  const server = http.createServer(handleRequest);
  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  return server;
}

function start() {
  const server = createServer();
  server.listen(PORT, HOST, () => {
    console.log(`AuditAgent listening on http://${HOST}:${PORT}`);
  });
  server.on('error', (err) => {
    console.error(`AuditAgent failed to listen on ${HOST}:${PORT}: ${err.message}`);
    process.exitCode = 1;
  });
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 2000).unref();
    });
  }
  return server;
}

if (require.main === module) start();

module.exports = { createServer, handleRequest, HOST, PORT };
