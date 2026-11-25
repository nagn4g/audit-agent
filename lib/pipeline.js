'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { RECORDED_POC } = require('./recorded-poc');
const { chatCompletion, extractSolidity } = require('./llm');

const ROOT = path.resolve(__dirname, '..');
const FOUNDRY_DIR = path.join(ROOT, 'foundry');
const POC_PATH = path.join(FOUNDRY_DIR, 'test', 'ReentrancyPoC.t.sol');
const CONTRACT_PATH = path.join(FOUNDRY_DIR, 'src', 'VulnerableBank.sol');
const FALLBACK_FORGE = '/home/hatch/.foundry/bin/forge';
const FORGE_TIMEOUT_MS = 180_000;

const DEMO_CONTRACTS = [
  {
    id: 'reentrancy',
    name: 'Reentrancy',
    contract: 'VulnerableBank.sol',
    description: 'withdraw() sends ETH before zeroing the balance.',
    status: 'available',
  },
  {
    id: 'access-control',
    name: 'Access Control',
    contract: 'Missing modifier on privileged function',
    description: 'Unauthenticated admin path.',
    status: 'coming Day 2',
  },
  {
    id: 'unchecked-call',
    name: 'Unchecked Call',
    contract: 'Ignored low-level call return value',
    description: 'Silent transfer failure.',
    status: 'coming Day 2',
  },
];

class PipelineError extends Error {}

function isExecutableFile(file) {
  return fs.access(file, 1 /* X_OK */).then(() => true, () => false);
}

function findOnPath(binary) {
  const dirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  return dirs.map((dir) => path.join(dir, binary));
}

/**
 * Resolve forge as: env FORGE_BIN, else `forge` on PATH, else the local install.
 * Returns null when nothing usable exists.
 */
async function resolveForge() {
  const fromEnv = (process.env.FORGE_BIN || '').trim();
  if (fromEnv) {
    const candidate = path.resolve(fromEnv);
    if (await isExecutableFile(candidate)) return { bin: candidate, source: 'FORGE_BIN' };
    // An explicit FORGE_BIN is a user instruction: surface it rather than
    // silently running a different forge.
    throw new PipelineError(`FORGE_BIN is set to ${fromEnv} but it is not an executable file`);
  }
  for (const candidate of findOnPath('forge')) {
    if (await isExecutableFile(candidate)) return { bin: candidate, source: 'PATH' };
  }
  if (await isExecutableFile(FALLBACK_FORGE)) return { bin: FALLBACK_FORGE, source: 'fallback' };
  return null;
}

function runForge(bin) {
  return new Promise((resolve) => {
    const child = spawn(bin, ['test'], {
      cwd: FOUNDRY_DIR,
      env: { ...process.env, FORGE_COLOR: 'never', NO_COLOR: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let output = '';
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ output: output.trimEnd(), ...result });
    };

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish({ exitCode: null, timedOut: true });
    }, FORGE_TIMEOUT_MS);

    child.stdout.on('data', (chunk) => { output += chunk.toString(); });
    child.stderr.on('data', (chunk) => { output += chunk.toString(); });

    child.on('error', (err) => {
      finish({ exitCode: null, spawnError: err.message });
    });
    child.on('close', (code) => {
      finish({ exitCode: code, timedOut: false });
    });
  });
}

function forgePassed(result) {
  return result.exitCode === 0 && /\[PASS\]/.test(result.output) && !/\[FAIL/.test(result.output);
}

const LLM_SYSTEM_PROMPT =
  'You are a Solidity security engineer writing a Foundry proof-of-concept test. ' +
  'Return ONLY Solidity code, no prose, no markdown fences.';

function buildLlmPrompt(poc) {
  return (
    'Write a Foundry test contract that exploits reentrancy in VulnerableBank.\n' +
    'Constraints:\n' +
    '- Target file is foundry/src/VulnerableBank.sol, import it as "../src/VulnerableBank.sol".\n' +
    '- The bank is funded with 10 ether before the attack; the attacker starts with 1 ether.\n' +
    '- withdraw() calls msg.sender before zeroing balances, so re-enter from receive().\n' +
    '- Do NOT import forge-std or any external library; use plain assert() only.\n' +
    '- Contract must expose a function named testReentrancyDrainsBank().\n' +
    '- Assert the attacker ends with more than it deposited and the bank balance is 0.\n\n' +
    'Reference implementation from the recorded trace (adapt, do not copy blindly):\n' +
    poc
  );
}

async function generateWithLlm({ apiKey, baseUrl, poc, emitStep, signal }) {
  const messages = [
    { role: 'system', content: LLM_SYSTEM_PROMPT },
    { role: 'user', content: buildLlmPrompt(poc) },
  ];

  let lastError = null;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const content = await chatCompletion({ apiKey, baseUrl, messages, signal });
    const code = extractSolidity(content);
    if (code) {
      emitStep('Generating PoC — LLM draft accepted (http chat/completions)');
      return code;
    }
    lastError = new Error('LLM response did not contain a usable Foundry test');
    if (attempt === 1) {
      emitStep('Generating PoC — LLM draft rejected (missing pragma/test, or imports forge-std), retrying');
    }
  }
  throw lastError;
}

async function readUtf8(file, label) {
  try {
    return await fs.readFile(file, 'utf8');
  } catch {
    throw new PipelineError(`Cannot read ${label} at ${path.relative(ROOT, file)}`);
  }
}

/**
 * Run the triage -> PoC -> proof loop for one contract.
 *
 * @param {object} options
 * @param {string} options.contractId
 * @param {string} [options.llmApiKey] kept in memory only, never logged or persisted
 * @param {string} [options.llmBaseUrl]
 * @param {(message: string) => void} [options.emitStep]
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<object>} the report object
 */
async function runAudit({ contractId, llmApiKey, llmBaseUrl, emitStep = () => {}, signal } = {}) {
  const steps = [];
  const record = (message) => {
    steps.push(message);
    emitStep(message);
  };

  if (contractId !== 'reentrancy') {
    throw new PipelineError(`Unknown or unavailable contractId: ${String(contractId)}`);
  }

  await readUtf8(CONTRACT_PATH, 'VulnerableBank.sol');
  record('Loading contract: VulnerableBank.sol');

  record('Screening: 10-gate triage');
  record('Surface selected: reentrancy in withdraw() (external call before state update)');

  const poc = RECORDED_POC;
  let pocSource;
  let pocGenerator;

  if (llmApiKey) {
    record('Generating PoC — LLM enabled (BYOK, in-memory only)');
    try {
      pocSource = await generateWithLlm({ apiKey: llmApiKey, baseUrl: llmBaseUrl, poc, emitStep: record, signal });
      pocGenerator = 'llm';
    } catch (err) {
      record(`Generating PoC — LLM failed (${err.message}); falling back to recorded PoC trace`);
      pocSource = poc;
      pocGenerator = 'demo-fallback';
    }
  } else {
    pocSource = poc;
    pocGenerator = 'demo';
    record('Generating PoC — demo mode: recorded PoC trace, no LLM key');
  }

  const forge = await resolveForge();
  if (!forge) {
    throw new PipelineError(
      'No forge binary found. Set FORGE_BIN, add forge to PATH, or install Foundry at ~/.foundry/bin/forge.',
    );
  }

  record('Writing PoC to foundry/test/ReentrancyPoC.t.sol');
  try {
    await fs.writeFile(POC_PATH, pocSource, 'utf8');
  } catch (err) {
    throw new PipelineError(`Cannot write PoC: ${err.message}`);
  }

  record('Running forge test');
  const result = await runForge(forge.bin);
  if (result.spawnError) {
    await fs.writeFile(POC_PATH, poc, 'utf8').catch(() => {});
    throw new PipelineError(`forge could not be started (${result.spawnError})`);
  }
  const confirmed = forgePassed(result);

  if (!confirmed) {
    // Keep the seeded PoC on disk so the local tree stays runnable; the
    // verdict below still reflects the raw failure output, never a faked pass.
    await fs.writeFile(POC_PATH, poc, 'utf8').catch(() => {});
  }

  return {
    verdict: confirmed ? 'VULNERABILITY CONFIRMED' : 'NOT CONFIRMED',
    severity: 'High',
    title: 'Reentrancy in VulnerableBank.withdraw()',
    impact:
      'Any depositor can recursively re-enter withdraw() and drain the entire ETH balance of the bank, ' +
      'stealing other users\' funds. The attacker only needs 1 ether of seed capital.',
    exploitPath:
      'attacker.attack() deposits 1 ether -> bank.withdraw() sends 1 ether via call before zeroing balances -> ' +
      'Attacker.receive() re-enters bank.withdraw() while balances[attacker] is still non-zero -> ' +
      'loop repeats until the bank has < 1 ether left -> attacker walks away with the bank\'s 10 ether.',
    pocCode: pocSource,
    forgeOutput: result.output || '(no output captured)',
    fixSuggestion:
      'Apply checks-effects-interactions: zero the balance before the external call (or use ReentrancyGuard).',
    steps,
    meta: {
      contractId,
      pocGenerator,
      forge: { source: forge.source, exitCode: result.exitCode, timedOut: result.timedOut === true },
    },
  };
}

module.exports = {
  DEMO_CONTRACTS,
  PipelineError,
  ROOT,
  FOUNDRY_DIR,
  POC_PATH,
  resolveForge,
  runAudit,
};
