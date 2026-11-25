'use strict';

const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { execFile } = require('node:child_process');

const { PipelineError } = require('./pipeline');

const MAX_FILES = 200;
const CLONE_TIMEOUT_MS = 60_000;
const SKIP_DIRS = new Set(['.git', 'node_modules', 'lib', 'out', 'cache']);
const NAME_RE = /^[A-Za-z0-9_.-]+$/;

const NOTE =
  'Heuristic screen only — not a vulnerability finding. ' +
  'Run a demo contract to see the full triage → PoC → proof loop.';

/**
 * Parse a public GitHub repository URL into { owner, repo }.
 *
 * Accepts only https://github.com/<owner>/<repo> with an optional `.git`
 * suffix, trailing slash, or `/tree/<branch>/...` suffix (stripped to the
 * repository root). Everything else is rejected.
 *
 * @param {string} input
 * @returns {{ owner: string, repo: string }}
 */
function parseGitHubUrl(input) {
  const raw = typeof input === 'string' ? input.trim() : '';
  if (!raw) throw new PipelineError('Repository URL is required');

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new PipelineError('Repository URL must be a full https://github.com/<owner>/<repo> URL');
  }

  if (url.protocol !== 'https:') {
    throw new PipelineError('Only https:// GitHub URLs are supported (ssh and http are rejected)');
  }
  if (url.username || url.password) {
    throw new PipelineError('Repository URL must not include credentials');
  }
  if (url.hostname !== 'github.com') {
    throw new PipelineError(`Only github.com is supported (got ${url.hostname || 'no host'})`);
  }
  if (url.port) {
    throw new PipelineError('Repository URL must not include a port');
  }
  if (url.search || url.hash) {
    throw new PipelineError('Repository URL must not include a query string or fragment');
  }

  const segments = url.pathname.split('/').filter(Boolean);
  if (segments.length < 2) {
    throw new PipelineError('Repository URL must look like https://github.com/<owner>/<repo>');
  }

  const [owner, rawRepo, extra] = segments;
  if (extra !== undefined && extra !== 'tree') {
    throw new PipelineError('Only the repository root or /tree/<branch>/... paths are supported');
  }
  if (extra === 'tree' && segments.length < 4) {
    throw new PipelineError('/tree/ paths must include a branch name');
  }

  let repo = rawRepo;
  if (repo.endsWith('.git')) repo = repo.slice(0, -4);
  if (!repo || repo.endsWith('.git')) {
    throw new PipelineError('Repository name is not valid');
  }
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo)) {
    throw new PipelineError('Owner and repository names may only contain letters, digits, dot, dash and underscore');
  }

  return { owner, repo };
}

function cloneErrorMessage(owner, repo, err, stderr) {
  const detail = String(stderr || '').toLowerCase();
  if (err && err.killed) {
    return `Cloning ${owner}/${repo} timed out after ${CLONE_TIMEOUT_MS / 1000}s`;
  }
  if (
    detail.includes('repository not found') ||
    detail.includes('not found') ||
    detail.includes('authentication failed') ||
    detail.includes('could not read username') ||
    detail.includes('terminal prompts disabled')
  ) {
    return `Repository ${owner}/${repo} was not found or is private (only public repos are supported)`;
  }
  if (
    detail.includes('could not resolve host') ||
    detail.includes('unable to access') ||
    detail.includes('network') ||
    detail.includes('connection')
  ) {
    return `Could not reach GitHub to clone ${owner}/${repo} (network error)`;
  }
  const line = String(stderr || '').trim().split('\n').filter(Boolean).pop();
  return `Failed to clone ${owner}/${repo}${line ? `: ${line.slice(0, 200)}` : ''}`;
}

/**
 * Shallow-clone a public GitHub repository into a fresh OS temp directory.
 *
 * The URL is passed as an argv element to execFile — never through a shell.
 *
 * @param {string} owner
 * @param {string} repo
 * @param {object} [options]
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<string>} absolute path of the clone (temp dir)
 */
async function cloneRepo(owner, repo, { signal } = {}) {
  if (!NAME_RE.test(owner) || !NAME_RE.test(repo)) {
    throw new PipelineError('Refusing to clone: invalid owner or repository name');
  }
  // Defence in depth for direct callers: the destination is always a fresh
  // directory under the OS temp dir, never inside the app tree.
  let dir;
  try {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), 'audit-agent-'));
  } catch (err) {
    throw new PipelineError(`Cannot create temp directory for clone: ${err.message}`);
  }

  const url = `https://github.com/${owner}/${repo}.git`;

  return new Promise((resolve, reject) => {
    execFile(
      'git',
      ['clone', '--depth', '1', url, dir],
      {
        timeout: CLONE_TIMEOUT_MS,
        killSignal: 'SIGKILL',
        maxBuffer: 8 * 1024 * 1024,
        signal,
        env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
      },
      async (err, stdout, stderr) => {
        if (err) {
          await removeDir(dir);
          if (signal && signal.aborted) {
            reject(new PipelineError('Clone cancelled'));
          } else {
            reject(new PipelineError(cloneErrorMessage(owner, repo, err, stderr)));
          }
          return;
        }
        resolve(dir);
      },
    );
  });
}

/** Best-effort recursive delete. Never throws. */
async function removeDir(dir) {
  if (!dir) return;
  try {
    await fs.rm(dir, { recursive: true, force: true });
  } catch {
    /* best-effort cleanup */
  }
}

function countLines(text) {
  if (!text) return 0;
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines.length;
}

function extractContracts(text) {
  const names = [];
  const re = /^[ \t]*(?:abstract[ \t]+)?(contract|interface|library)[ \t]+([A-Za-z_$][\w$]*)/gm;
  let match;
  while ((match = re.exec(text)) !== null) names.push(match[2]);
  return names;
}

async function walk(dir, relBase, collected, state) {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  for (const entry of entries) {
    if (collected.length >= MAX_FILES) {
      state.truncated = true;
      return;
    }
    const abs = path.join(dir, entry.name);
    const rel = relBase ? `${relBase}/${entry.name}` : entry.name;

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      await walk(abs, rel, collected, state);
      if (collected.length >= MAX_FILES) {
        state.truncated = true;
        return;
      }
      continue;
    }
    if (!entry.isFile() || !entry.name.endsWith('.sol')) continue;

    let text;
    try {
      text = await fs.readFile(abs, 'utf8');
    } catch {
      continue;
    }

    const loc = countLines(text);
    const contracts = extractContracts(text);
    const callMatch = text.match(/\.call\s*[{(]/g) || [];

    collected.push({
      path: rel,
      loc,
      contracts,
      pragmaPinned: /pragma\s+solidity\s+=?\s*\d+\.\d+\.\d+\s*;/.test(text),
      importsKnownLib: /(?:@openzeppelin\/|forge-std\/)/.test(text),
      externalCallCount: callMatch.length,
      hasValueCall: /\.call\s*\{\s*value\s*:/.test(text),
      hasLowLevelCall: /\.(?:call|delegatecall|staticcall)\b/.test(text),
      hasDelegatecall: /\bdelegatecall\b/.test(text),
      hasProxy: /\bProxy\b|\bupgradeTo\b|\bUUPS\b|\bTransparentUpgradeableProxy\b/.test(text),
      hasAssemblyOrSelfdestruct: /\bassembly\b|\bselfdestruct\b/.test(text),
    });
  }
}

/**
 * Recursively map `*.sol` files under a directory.
 *
 * @param {string} dir
 * @returns {Promise<object>} { files, totalFiles, totalLoc, contractNames, truncated, details }
 *   `files` is report-safe ({ path, loc, contracts }); `details` carries the
 *   per-file flags the screen uses and is not sent to the client.
 */
async function mapContracts(dir) {
  const collected = [];
  const state = { truncated: false };
  await walk(dir, '', collected, state);

  const files = collected.map((f) => ({ path: f.path, loc: f.loc, contracts: f.contracts }));
  const totalLoc = collected.reduce((sum, f) => sum + f.loc, 0);
  const seen = new Set();
  const contractNames = [];
  for (const f of collected) {
    for (const name of f.contracts) {
      if (!seen.has(name)) {
        seen.add(name);
        contractNames.push(name);
      }
    }
  }

  return {
    files,
    totalFiles: files.length,
    totalLoc,
    contractNames,
    truncated: state.truncated,
    details: collected,
  };
}

function gate(id, name, status, evidence) {
  return { id, name, status, evidence };
}

/**
 * Deterministic 10-gate heuristic screen over a mapped repository.
 *
 * @param {object} map output of mapContracts()
 * @returns {{ gates: object[], note: string }}
 */
function screenRepo(map) {
  const details = map.details || [];
  const gates = [];

  // 1. has-sol-files
  gates.push(
    map.totalFiles === 0
      ? gate('has-sol-files', 'Has Solidity files', 'fail', 'No .sol files found in the repository')
      : gate('has-sol-files', 'Has Solidity files', 'pass', `${map.totalFiles} .sol file(s) found`),
  );

  // 2. solc-version-pinned
  const pinned = details.find((f) => f.pragmaPinned);
  gates.push(
    pinned
      ? gate('solc-version-pinned', 'Solidity version pinned', 'pass', `Pinned pragma in ${pinned.path}`)
      : gate(
          'solc-version-pinned',
          'Solidity version pinned',
          'warn',
          map.totalFiles === 0 ? 'No files to inspect' : 'No exact pinned pragma (range or caret only)',
        ),
  );

  // 3. has-tests
  const testFile = details.find((f) => f.path.endsWith('.t.sol') || f.path.split('/').includes('test'));
  gates.push(
    testFile
      ? gate('has-tests', 'Tests present', 'pass', `Found ${testFile.path}`)
      : gate('has-tests', 'Tests present', 'warn', 'No test/ directory or *.t.sol file found'),
  );

  // 4. known-libraries (informational)
  const libFile = details.find((f) => f.importsKnownLib);
  gates.push(
    libFile
      ? gate('known-libraries', 'Known libraries imported', 'pass', `Found in ${libFile.path}`)
      : gate('known-libraries', 'Known libraries imported', 'warn', 'No @openzeppelin/ or forge-std/ imports (informational)'),
  );

  // 5. external-calls
  const externalFiles = details.filter((f) => f.externalCallCount > 0);
  const externalTotal = externalFiles.reduce((sum, f) => sum + f.externalCallCount, 0);
  gates.push(
    externalTotal > 0
      ? gate(
          'external-calls',
          'External calls',
          'warn',
          `${externalTotal} external call(s); first in ${externalFiles[0].path}`,
        )
      : gate('external-calls', 'External calls', 'pass', 'No .call{ / .call( occurrences found'),
  );

  // 6. low-level-calls
  const lowLevelFile = details.find((f) => f.hasLowLevelCall);
  gates.push(
    lowLevelFile
      ? gate('low-level-calls', 'Low-level calls', 'warn', `Low-level call surface in ${lowLevelFile.path}`)
      : gate('low-level-calls', 'Low-level calls', 'pass', 'No .call / .delegatecall / .staticcall found'),
  );

  // 7. delegatecall-present (highest-risk surface)
  const delegateFile = details.find((f) => f.hasDelegatecall);
  gates.push(
    delegateFile
      ? gate('delegatecall-present', 'Delegatecall present', 'fail', `delegatecall in ${delegateFile.path}`)
      : gate('delegatecall-present', 'Delegatecall present', 'pass', 'No delegatecall found'),
  );

  // 8. upgradeable-proxy
  const proxyFile = details.find((f) => f.hasProxy);
  gates.push(
    proxyFile
      ? gate('upgradeable-proxy', 'Upgradeable proxy', 'warn', `Proxy/upgrade pattern in ${proxyFile.path}`)
      : gate('upgradeable-proxy', 'Upgradeable proxy', 'pass', 'No proxy/upgrade pattern found'),
  );

  // 9. assembly-or-selfdestruct
  const asmFile = details.find((f) => f.hasAssemblyOrSelfdestruct);
  gates.push(
    asmFile
      ? gate('assembly-or-selfdestruct', 'Assembly or selfdestruct', 'warn', `assembly/selfdestruct in ${asmFile.path}`)
      : gate('assembly-or-selfdestruct', 'Assembly or selfdestruct', 'pass', 'No assembly or selfdestruct found'),
  );

  // 10. size-complexity
  gates.push(
    map.totalLoc > 5000
      ? gate(
          'size-complexity',
          'Size / complexity',
          'warn',
          `${map.totalLoc} LOC — triage only — too big for a full single-pass review`,
        )
      : gate('size-complexity', 'Size / complexity', 'pass', `${map.totalLoc} LOC across ${map.totalFiles} file(s)`),
  );

  return { gates, note: NOTE };
}

/**
 * Pick the most promising review surface. Priority:
 * delegatecall > .call{value > any low-level call > largest contract file.
 *
 * @param {object} map output of mapContracts()
 * @param {object[]} gates output of screenRepo().gates
 * @returns {{ surface: string, reason: string, file: string }}
 */
function topSurface(map, gates) {
  const details = map.details || [];
  const delegate = details.find((f) => f.hasDelegatecall);
  if (delegate) {
    return {
      surface: 'delegatecall (highest-risk surface)',
      reason: 'delegatecall executes foreign code in this contract\'s storage context',
      file: delegate.path,
    };
  }

  const valueCall = details.find((f) => f.hasValueCall);
  if (valueCall) {
    return {
      surface: 'external call moving value',
      reason: '.call{value: ...} transfers ETH to an external address',
      file: valueCall.path,
    };
  }

  const lowLevel = details.find((f) => f.hasLowLevelCall);
  if (lowLevel) {
    return {
      surface: 'low-level call handling',
      reason: 'low-level call whose return value and state ordering need review',
      file: lowLevel.path,
    };
  }

  const largest = [...details].sort((a, b) => b.loc - a.loc)[0];
  if (largest) {
    return {
      surface: 'largest contract, start here',
      reason: `largest file at ${largest.loc} LOC`,
      file: largest.path,
    };
  }

  const gateFail = (gates || []).find((g) => g.status === 'fail');
  return {
    surface: 'no Solidity surface found',
    reason: gateFail ? `${gateFail.name}: ${gateFail.evidence}` : 'repository has no mapable files',
    file: '',
  };
}

module.exports = {
  NOTE,
  parseGitHubUrl,
  cloneRepo,
  removeDir,
  mapContracts,
  screenRepo,
  topSurface,
};
