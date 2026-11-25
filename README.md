# AuditAgent

Local demo app for SLAY HACKS 2026: pick a seeded Solidity contract, watch the agent triage it,
generate a Foundry proof-of-concept, and run that PoC live. The report is whatever `forge test`
actually says — a failing PoC yields `NOT CONFIRMED`, never a faked pass.

## Honest ceiling

AuditAgent proves the **triage → PoC → proof loop on known vulnerability classes**.
It does **not** find novel 0-days in audited production code. The demo contract is intentionally
vulnerable and the recorded exploit trace is the ground truth for a clean, offline run.

## What it does

1. Loads the target contract.
2. Runs a 10-gate triage screen (deterministic for the seeded demo).
3. Selects the attack surface (here: reentrancy in `withdraw()`).
4. Generates the PoC — with your BYOK key it asks an OpenAI-compatible model; without one it uses
   the recorded exploit trace in demo mode.
5. Writes the PoC to `foundry/test/ReentrancyPoC.t.sol`.
6. Runs `forge test` and streams the result.
7. Emits a report with verdict, severity, impact, exploit path, PoC source, raw forge output and a fix.

## Demo contract

`foundry/src/VulnerableBank.sol` (Solidity `^0.8.20`):

- `deposit()` payable credits `balances[msg.sender]`.
- `withdraw()` sends the full balance with a low-level `call` **before** zeroing the balance —
  classic reentrancy.

`foundry/test/ReentrancyPoC.t.sol` deploys a 10-ether-funded bank, has an `Attacker` deposit 1 ether
and re-enter `withdraw()` from `receive()` until the bank is drained, then asserts the attacker walked
away with more than it put in and the bank balance is 0. It uses plain `assert()` with **no `forge-std`
import**, so `forge test` works offline with zero installs.

## Setup

- Node 24+
- Foundry 1.9.0 (`forge` on `PATH`, or `FORGE_BIN`, or at `~/.foundry/bin/forge`)
- Optional: an OpenAI-compatible API key for LLM-generated PoCs (BYOK)

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

- `GET /api/demo-contracts` — seeded contract list (`reentrancy` available, two Day 2 entries).
- `POST /api/audit` — SSE stream. Body: `{ "contractId": "reentrancy", "llmApiKey": "...", "llmBaseUrl": "..." }`.
  Streams `step` events, then a final `report` event.

Keys are kept in memory for the duration of one request only — never logged and never written to disk.

## Limitations

- One contract, one vulnerability class. Access control and unchecked-call demos are Day 2.
- Repo intake (pointing at a GitHub repo) is Day 2; the input is disabled.
- Triage is deterministic for the seeded demo, not a general static analyzer.
