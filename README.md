# AuditAgent

Local demo app for SLAY HACKS 2026. Two ways in:

1. **Demo contracts** — pick one of three seeded Solidity contracts, watch the agent triage it,
   generate a Foundry proof-of-concept, and run that PoC live. The report is whatever
   `forge test` actually says — a failing PoC yields `NOT CONFIRMED`, never a faked pass.
2. **Repo intake** — paste a public GitHub URL; the agent shallow-clones it, maps every `.sol`
   file, and runs a deterministic 10-gate heuristic screen. No LLM is called for repo intake.

## Honest ceiling

AuditAgent proves the **triage → PoC → proof loop on known vulnerability classes**.
It does **not** find novel 0-days in audited production code. Each demo contract is intentionally
vulnerable and its recorded exploit trace is the ground truth for a clean, offline run.

Repo intake is a **heuristic screen, not a vulnerability finding**. Every triage report carries:

> Heuristic screen only — not a vulnerability finding. Run a demo contract to see the full
> triage → PoC → proof loop.

## Demo contracts

All three are `^0.8.20`, use plain `assert()` and import **no `forge-std`**, so `forge test` runs
offline with zero installs. Each PoC runs in isolation with `--force --match-contract
--match-test`, so one contract's result can never change another's verdict — and no verdict
can come from a stale compile (forge's incremental cache has been observed to skip
recompilation after a PoC file is rewritten).

### 1. Reentrancy — `reentrancy`

- `foundry/src/VulnerableBank.sol`: `deposit()` credits `balances[msg.sender]`; `withdraw()` sends
  the full balance with a low-level `call` **before** zeroing the balance — classic reentrancy.
- `foundry/test/ReentrancyPoC.t.sol`, test `testReentrancyDrainsBank()`: a 10-ether-funded bank, an
  `Attacker` deposits 1 ether and re-enters `withdraw()` from `receive()` until drained.
- Proves: recursive withdrawal lets the attacker walk away with more than it deposited.

### 2. Missing access control — `access-control`

- `foundry/src/AccessVault.sol`: constructor sets `owner`, `deposit()` is payable, and the privileged
  `drain()` sends the whole balance to `msg.sender` with **no `onlyOwner` and no `require`** — the
  missing check is commented in the source.
- `foundry/test/AccessControlPoC.t.sol`, test `testNonOwnerDrainsVault()`: a vault funded with
  10 ether of deposits is drained by a non-owner attacker contract.
- Proves: any address can take every depositor's funds from a privileged-but-unprotected function.

### 3. Unchecked low-level call — `unchecked-call`

- `foundry/src/UncheckedPayout.sol`: `pay(recipient)` zeroes the sender's balance, performs
  `recipient.call{value: amount}("")` while **ignoring the returned bool** (no `require`, no branch),
  then sets `paid[recipient] = true` regardless of the outcome.
- `foundry/test/UncheckedCallPoC.t.sol`, test `testUncheckedCallLosesFunds()`: the recipient's
  `receive()` always reverts; the test asserts the recipient received **0 ETH** *and* the payout is
  recorded as done (`paid[recipient] == true`, sender balance zeroed) — the proof of silent failure.
- Proves: a failed transfer is treated as success and the funds are lost.

## Repo intake

### How it works

`POST /api/repo-audit` streams over SSE:

1. **Validating URL** — accepts only `https://github.com/<owner>/<repo>`, with an optional
   trailing `.git`, trailing slash, or `/tree/<branch>/...` path (stripped to the repo root).
   Everything else (other hosts, `ssh://`, `http://`, credentials, query strings, weird paths)
   is rejected before any network activity.
2. **Cloning** — `git clone --depth 1 https://github.com/<owner>/<repo>.git` into a fresh
   directory created with `fs.mkdtemp(os.tmpdir(), 'audit-agent-')`. The URL is passed as an
   `execFile` argv element — never through a shell. 60s timeout, killed on expiry.
3. **Mapping contracts** — recursive walk for `*.sol`, skipping `.git`, `node_modules`, `lib/`,
   `out/`, `cache/`. Capped at 200 files (truncation is noted in the report). Reports relative
   path, line count, and `contract` / `interface` / `library` names per file.
4. **Running the 10-gate screen** — deterministic heuristics (below).
5. **Done** — a `triage` event carries the report:
   `{ repo, files, totalFiles, totalLoc, contractNames, gates, topSurface, note }`.

The temp clone directory is always removed in a `finally` (best-effort). The clone target is the
OS temp dir only — never inside `app-src` and never inside a git checkout.

### The 10 gates

| # | Gate | Pass | Warn | Fail |
|---|------|------|------|------|
| 1 | `has-sol-files` | any `.sol` files | — | 0 files |
| 2 | `solc-version-pinned` | any exact pinned pragma (`0.x.y` / `=0.x.y`) | only ranges | — |
| 3 | `has-tests` | `test/` dir or `*.t.sol` present | none found | — |
| 4 | `known-libraries` | `@openzeppelin/` or `forge-std/` imports | none (informational) | — |
| 5 | `external-calls` | no `.call{` / `.call(` | any found (count + first file) | — |
| 6 | `low-level-calls` | none | `.call` / `.delegatecall` / `.staticcall` present | — |
| 7 | `delegatecall-present` | no `delegatecall` | — | `delegatecall` present (highest-risk surface) |
| 8 | `upgradeable-proxy` | no proxy pattern | `Proxy` / `upgradeTo` / `UUPS` / `TransparentUpgradeableProxy` | — |
| 9 | `assembly-or-selfdestruct` | none | `assembly` or `selfdestruct` | — |
| 10 | `size-complexity` | `totalLoc <= 5000` | `> 5000` (triage only — too big for a full single-pass review) | — |

`topSurface` then picks, in priority order: `delegatecall` present → a file with `.call{value` →
any low-level call → largest contract file.

### Repo intake limits

- **Public GitHub repos only.** Private repos, authentication and non-GitHub hosts are rejected.
- **Shallow clone** (`--depth 1`): no history, only the default branch tip.
- **Temp dir cleaned up** after every run; nothing is persisted.
- **Heuristic, not a vuln scanner:** the gates flag surfaces worth reading, not confirmed bugs.
- **Repo intake does not call the LLM.** `llmApiKey` / `llmBaseUrl` are accepted in the request
  body for forward-compatibility but are unused.

## Setup

- Node 24+
- Foundry 1.9.0 (`forge` on `PATH`, or `FORGE_BIN`, or at `~/.foundry/bin/forge`) — only needed for
  the demo-contract PoC loop, not for repo intake
- `git` on `PATH` — only needed for repo intake
- Optional: an OpenAI-compatible API key for LLM-generated demo PoCs (BYOK)

No dependencies to install — the server uses Node's built-in `http` and `fetch`.

By default `foundry.toml` pins `solc_version = "0.8.20"` so the demo runs offline against the
local solc cache. If your machine lacks that compiler you can drop the pin and let forge pick one.

## Run

```bash
npm start
# open http://127.0.0.1:3000
```

Verify the Foundry side on its own:

```bash
npm run test:forge   # cd foundry && forge test
```

## API

- `GET /api/demo-contracts` — seeded contract list; all three are `available`:
  `reentrancy`, `access-control`, `unchecked-call`.
- `POST /api/audit` — SSE stream. Body:
  `{ "contractId": "reentrancy" | "access-control" | "unchecked-call", "llmApiKey": "...", "llmBaseUrl": "..." }`.
  Unknown ids are rejected with HTTP 400. Streams `step` events, then a final `report` event. The
  report includes `pocPath` (the audited test file, e.g. `foundry/test/AccessControlPoC.t.sol`).
- `POST /api/repo-audit` — SSE stream. Body:
  `{ "repoUrl": "https://github.com/<owner>/<repo>" }`. Invalid URLs are rejected with HTTP 400
  before cloning. Streams `step` events, then a final `triage` event; errors arrive as an `error`
  event. Repo triage never calls the LLM.

Both endpoints share the same 16KB request body limit. Keys are kept in memory for the duration of
one request only — never logged and never written to disk.

## BYOK live test (25 Nov 2026)

The LLM path was tested end-to-end with a real free-tier key — not just demo mode:

- Model: `deepseek-v4.1-flash-free` (100milionseek) via a local LiteLLM proxy at
  `http://localhost:4001/v1`, server started with `LLM_MODEL=seek-deepseek-v4.1-flash-free`.
- Result: the LLM generated a PoC for **all three** demo contracts and every one passed
  `forge test` (verdict `VULNERABILITY CONFIRMED`, `pocGenerator: "llm"`). The generated PoCs
  differ from the recorded traces — they are genuinely model-written, not the fallback.
- A bad key fails honestly: the pipeline falls back to the recorded trace and the report is
  labelled `demo-fallback` (the UI shows "LLM failed — recorded trace used"), never a fake
  LLM pass. A PoC that fails `forge test` yields `NOT CONFIRMED`.
- Two things the test forced: (1) the target contract's source is included in the LLM prompt —
  agentic-style models otherwise stop the turn with `tool_calls` trying to read the file
  themselves, which returns an empty completion; (2) forge always runs with `--force` (see above).

## Screenshots

Final screenshots (Day 3, 25 Nov 2026, taken from the real local run — see
`shots/` in the workspace; attach these to the Devpost submission):

- `shots/ui-day3-home-2026-11-25.png` — home: 3 demo contracts, BYOK panel, live log.
- `shots/ui-day3-report-2026-11-25.png` — full audit report for reentrancy:
  `VULNERABILITY CONFIRMED` (High), live log, PoC code, forge output `[PASS]`,
  fix suggestion. Footer reads "Demo mode — recorded trace".
- `shots/ui-day3-repo-2026-11-25.png` — repo intake triage of this repo:
  6 files · 219 LOC · 9 contract names, 10-gate table, top surface.

Note: the PNGs live in the workspace `shots/` directory, not in this repo —
`push-files` only carries UTF-8 text, so binaries are uploaded to the repo (or
attached to Devpost) via the browser.

## Limitations

- Repo intake performs a heuristic screen only, not automated vulnerability discovery, and does
  not generate or run PoCs against the cloned repo.
- Demo PoCs are scoped to the three seeded contracts; repo intake and the PoC loop are not yet
  joined end-to-end.
- Triage is deterministic for the seeded demo, not a general static analyzer.
