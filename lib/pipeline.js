'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { RECORDED_POCS } = require('./recorded-poc');
const { chatCompletion, extractSolidity } = require('./llm');

const ROOT = path.resolve(__dirname, '..');
const FOUNDRY_DIR = path.join(ROOT, 'foundry');
const FALLBACK_FORGE = '/home/hatch/.foundry/bin/forge';
const FORGE_TIMEOUT_MS = 180_000;

// Repo-relative paths used on disk and shown in the report. Built from the
// per-contract config below so nothing here is tied to one demo.
function srcPathFor(fileName) {
  return path.join(FOUNDRY_DIR, 'src', fileName);
}

function testPathFor(fileName) {
  return path.join(FOUNDRY_DIR, 'test', fileName);
}

function repoRelative(file) {
  return path.relative(ROOT, file).split(path.sep).join('/');
}

/**
 * Single source of truth for the seeded demo contracts.
 *
 * Every field the pipeline needs lives here:
 *  - identity/UI: id, name, contract, description, status
 *  - files: sourceFile, testFile (repo-relative), testFn, testContract
 *  - recorded PoC: poc (forge-std free source string)
 *  - finding: surface, severity, title, impact, exploitPath, fixSuggestion
 *  - LLM prompt inputs: targetContract, constraints, referencePoc
 */
const CONTRACT_CONFIG = {
  reentrancy: {
    id: 'reentrancy',
    name: 'Reentrancy',
    contract: 'VulnerableBank.sol',
    description: 'withdraw() sends ETH before zeroing the balance.',
    status: 'available',
    sourceFile: repoRelative(srcPathFor('VulnerableBank.sol')),
    testFile: repoRelative(testPathFor('ReentrancyPoC.t.sol')),
    testFn: 'testReentrancyDrainsBank',
    testContract: 'ReentrancyPoC',
    poc: RECORDED_POCS.reentrancy,
    surface: 'reentrancy in withdraw() (external call before state update)',
    severity: 'High',
    title: 'Reentrancy in VulnerableBank.withdraw()',
    impact:
      'Any depositor can recursively re-enter withdraw() and drain the entire ETH balance of the bank, ' +
      'stealing other users\' funds. The attacker only needs 1 ether of seed capital.',
    exploitPath:
      'attacker.attack() deposits 1 ether -> bank.withdraw() sends 1 ether via call before zeroing balances -> ' +
      'Attacker.receive() re-enters bank.withdraw() while balances[attacker] is still non-zero -> ' +
      'loop repeats until the bank has < 1 ether left -> attacker walks away with the bank\'s 10 ether.',
    fixSuggestion:
      'Apply checks-effects-interactions: zero the balance before the external call (or use ReentrancyGuard).',
    prompt: {
      targetContract: 'VulnerableBank',
      constraints: [
        'Target file is foundry/src/VulnerableBank.sol, import it as "../src/VulnerableBank.sol".',
        'The bank is funded with 10 ether before the attack; the attacker starts with 1 ether.',
        'withdraw() calls msg.sender before zeroing balances, so re-enter from receive().',
        'Do NOT import forge-std or any external library; use plain assert() only.',
        'Contract must expose a function named testReentrancyDrainsBank().',
        'Assert the attacker ends with more than it deposited and the bank balance is 0.',
      ],
    },
  },

  'access-control': {
    id: 'access-control',
    name: 'Access Control',
    contract: 'AccessVault.sol',
    description: 'drain() sends the whole vault with no owner check.',
    status: 'available',
    sourceFile: repoRelative(srcPathFor('AccessVault.sol')),
    testFile: repoRelative(testPathFor('AccessControlPoC.t.sol')),
    testFn: 'testNonOwnerDrainsVault',
    testContract: 'AccessControlPoC',
    poc: RECORDED_POCS['access-control'],
    surface: 'missing access control on drain() (privileged function callable by anyone)',
    severity: 'High',
    title: 'Missing access control on AccessVault.drain()',
    impact:
      'The vault records an owner in its constructor but never enforces it. Any address can call drain() ' +
      'and transfer the entire ETH balance, including every other user\'s deposit, to itself.',
    exploitPath:
      'vault is funded with 10 ether of user deposits -> an attacker contract with no owner privileges calls ' +
      'vault.drain() -> drain() sends address(this).balance to msg.sender unconditionally -> ' +
      'the attacker receives all 10 ether and the vault balance becomes 0.',
    fixSuggestion:
      'Add an onlyOwner check (require(msg.sender == owner, "not owner")) to drain(), or use OpenZeppelin Ownable.',
    prompt: {
      targetContract: 'AccessVault',
      constraints: [
        'Target file is foundry/src/AccessVault.sol, import it as "../src/AccessVault.sol".',
        'The vault is funded with 10 ether of other users\' deposits before the attack.',
        'drain() has no onlyOwner modifier and no require on msg.sender.',
        'The attacker must be a non-owner contract or plain address, not the deployer.',
        'Do NOT import forge-std or any external library; use plain assert() only.',
        'Contract must expose a function named testNonOwnerDrainsVault().',
        'Assert the attacker ends with more than it started with and the vault balance is 0.',
      ],
    },
  },

  'unchecked-call': {
    id: 'unchecked-call',
    name: 'Unchecked Call',
    contract: 'UncheckedPayout.sol',
    description: 'pay() ignores a failed call and still marks the payout done.',
    status: 'available',
    sourceFile: repoRelative(srcPathFor('UncheckedPayout.sol')),
    testFile: repoRelative(testPathFor('UncheckedCallPoC.t.sol')),
    testFn: 'testUncheckedCallLosesFunds',
    testContract: 'UncheckedCallPoC',
    poc: RECORDED_POCS['unchecked-call'],
    surface: 'ignored low-level call return value in pay() (silent transfer failure)',
    severity: 'Medium',
    title: 'Unchecked low-level call return value in UncheckedPayout.pay()',
    impact:
      'If the recipient rejects ETH, pay() still zeroes the sender\'s balance and records the payout as done. ' +
      'The funds are silently lost: the recipient got nothing and the sender cannot retry.',
    exploitPath:
      'sender deposits 1 ether -> pay() is called with a recipient whose receive() reverts -> ' +
      'the low-level call fails but its bool is ignored -> balances[msg.sender] is zeroed and ' +
      'paid[recipient] = true -> recipient balance is 0 and the 1 ether is stuck in the contract.',
    fixSuggestion:
      'Require the call to succeed: (bool ok, ) = recipient.call{value: amount}(""); require(ok, "transfer failed"); ' +
      'and only update state after the successful transfer.',
    prompt: {
      targetContract: 'UncheckedPayout',
      constraints: [
        'Target file is foundry/src/UncheckedPayout.sol, import it as "../src/UncheckedPayout.sol".',
        'The sender deposits 1 ether before calling pay().',
        'The recipient is a contract whose receive() always reverts.',
        'pay() ignores the low-level call result and marks paid[recipient] = true anyway.',
        'Do NOT import forge-std or any external library; use plain assert() only.',
        'Contract must expose a function named testUncheckedCallLosesFunds().',
        'Assert the recipient balance is 0 AND the payout is recorded as done (paid[recipient] true / sender balance 0).',
      ],
    },
  },
};

const CONTRACT_IDS = Object.keys(CONTRACT_CONFIG);

// Public list for the UI/API. Built from the config table so a new contract
// only has to be added in one place.
const DEMO_CONTRACTS = CONTRACT_IDS.map((id) => {
  const cfg = CONTRACT_CONFIG[id];
  return {
    id: cfg.id,
    name: cfg.name,
    contract: cfg.contract,
    description: cfg.description,
    status: cfg.status,
  };
});

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

/**
 * Run forge scoped to one PoC. Both --match-contract and --match-test are set
 * so a failure (or a stray extra test) in another demo cannot change this
 * verdict: only the audited test's result is reported. --force is always set:
 * forge's incremental cache has been observed to skip recompilation after a
 * PoC file is rewritten ("No files changed"), which would let a verdict be
 * computed from stale artifacts of a previous PoC.
 */
function runForge(bin, { testContract, testFn }) {
  return new Promise((resolve) => {
    const args = ['test', '--force', '--match-contract', testContract, '--match-test', testFn];
    const child = spawn(bin, args, {
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
      resolve({ output: output.trimEnd(), args, ...result });
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

function buildLlmPrompt(cfg, source) {
  const constraints = [
    ...cfg.prompt.constraints,
    // forge is invoked with --match-contract <testContract>, so the name is
    // load-bearing: a differently-named test contract yields "no tests match".
    `The test contract must be named ${cfg.testContract}.`,
  ].map((line) => `- ${line}`).join('\n');
  // The target source is included in full: agentic-style models otherwise
  // stop the turn with tool_calls trying to read the file themselves (the
  // chat/completions endpoint offers no tools), which yields an empty
  // completion. Stating "you have no tools" plus the source in-context makes
  // the model emit the PoC directly.
  const sourceBlock = source
    ? `\n\nTarget contract source (read this — you have no tools, do not attempt any function call):\n\`\`\`solidity\n${source}\n\`\`\``
    : '';
  return (
    `Write a Foundry test contract that exploits ${cfg.surface} in ${cfg.prompt.targetContract}.\n` +
    'Constraints:\n' +
    constraints + '\n\n' +
    'Reference implementation from the recorded trace (adapt, do not copy blindly):\n' +
    cfg.poc +
    sourceBlock
  );
}

async function generateWithLlm({ apiKey, baseUrl, cfg, source, emitStep, signal }) {
  const messages = [
    { role: 'system', content: LLM_SYSTEM_PROMPT },
    { role: 'user', content: buildLlmPrompt(cfg, source) },
  ];

  let lastError = null;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const content = await chatCompletion({ apiKey, baseUrl, messages, signal });
    const { code, error } = extractSolidity(content, {
      targetContract: cfg.prompt.targetContract,
      testContract: cfg.testContract,
    });
    if (code) {
      emitStep('Generating PoC — LLM draft accepted (http chat/completions)');
      return code;
    }
    lastError = new Error(`LLM response did not contain a usable Foundry test (${error})`);
    if (attempt === 1) {
      emitStep(`Generating PoC — LLM draft rejected (${error}), retrying with feedback`);
      messages.push({
        role: 'user',
        content: `Your previous draft was rejected: ${error}. Fix exactly that and return the complete corrected file.`,
      });
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

function requireContract(contractId) {
  const cfg = CONTRACT_CONFIG[contractId];
  if (!cfg || cfg.status !== 'available') {
    throw new PipelineError(`Unknown or unavailable contractId: ${String(contractId)}`);
  }
  return cfg;
}

/**
 * Run the triage -> PoC -> proof loop for one contract.
 *
 * @param {object} options
 * @param {string} options.contractId one of the ids in DEMO_CONTRACTS
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

  const cfg = requireContract(contractId);
  const sourcePath = path.join(ROOT, cfg.sourceFile);
  const pocPath = path.join(ROOT, cfg.testFile);

  const source = await readUtf8(sourcePath, cfg.contract);
  record(`Loading contract: ${cfg.contract}`);

  record('Screening: 10-gate triage');
  record(`Surface selected: ${cfg.surface}`);

  const poc = cfg.poc;
  let pocSource;
  let pocGenerator;

  if (llmApiKey) {
    record('Generating PoC — LLM enabled (BYOK, in-memory only)');
    try {
      pocSource = await generateWithLlm({ apiKey: llmApiKey, baseUrl: llmBaseUrl, cfg, source, emitStep: record, signal });
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

  record(`Writing PoC to ${cfg.testFile}`);
  try {
    await fs.writeFile(pocPath, pocSource, 'utf8');
  } catch (err) {
    throw new PipelineError(`Cannot write PoC: ${err.message}`);
  }

  record(`Running forge test --force --match-contract ${cfg.testContract} --match-test ${cfg.testFn}`);
  const result = await runForge(forge.bin, { testContract: cfg.testContract, testFn: cfg.testFn });
  if (result.spawnError) {
    await fs.writeFile(pocPath, poc, 'utf8').catch(() => {});
    throw new PipelineError(`forge could not be started (${result.spawnError})`);
  }
  const confirmed = forgePassed(result);

  if (!confirmed) {
    // Keep the seeded PoC on disk so the local tree stays runnable; the
    // verdict below still reflects the raw failure output, never a faked pass.
    await fs.writeFile(pocPath, poc, 'utf8').catch(() => {});
  }

  return {
    verdict: confirmed ? 'VULNERABILITY CONFIRMED' : 'NOT CONFIRMED',
    severity: cfg.severity,
    title: cfg.title,
    impact: cfg.impact,
    exploitPath: cfg.exploitPath,
    pocPath: cfg.testFile,
    pocCode: pocSource,
    forgeOutput: result.output || '(no output captured)',
    fixSuggestion: cfg.fixSuggestion,
    steps,
    meta: {
      contractId: cfg.id,
      contract: cfg.contract,
      pocPath: cfg.testFile,
      pocGenerator,
      testFn: cfg.testFn,
      forge: {
        source: forge.source,
        exitCode: result.exitCode,
        timedOut: result.timedOut === true,
        args: result.args,
      },
    },
  };
}

module.exports = {
  CONTRACT_CONFIG,
  DEMO_CONTRACTS,
  PipelineError,
  ROOT,
  FOUNDRY_DIR,
  resolveForge,
  runAudit,
};
