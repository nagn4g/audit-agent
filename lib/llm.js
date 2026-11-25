'use strict';

const DEFAULT_BASE_URL = 'https://api.openai.com/v1';
const DEFAULT_MODEL = 'gpt-4o-mini';
const TIMEOUT_MS = 90_000;
// Reasoning models can spend the whole budget on hidden reasoning and return
// an empty completion when no cap is set (seen on deepseek-v4.1-flash-free:
// content null). 8000 leaves room for a full PoC file after reasoning.
const MAX_TOKENS = Number.parseInt(process.env.LLM_MAX_TOKENS || '8000', 10) || 8000;

function normalizeBaseUrl(input) {
  const raw = (input && String(input).trim()) || DEFAULT_BASE_URL;
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('LLM base URL is not a valid URL');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('LLM base URL must use http or https');
  }
  return url.toString().replace(/\/+$/, '');
}

function stripCodeFences(text) {
  let out = String(text || '').trim();
  const fenced = out.match(/```(?:solidity|sol)?\s*\n([\s\S]*?)```/i);
  if (fenced) out = fenced[1].trim();
  return out;
}

/**
 * Pull a complete Solidity test file out of an LLM response.
 * Returns { code } on success, or { code: null, error } with a short reason
 * when the response is not usable as a Foundry test. The reason feeds the
 * retry feedback in the pipeline so a second draft can fix the exact defect.
 *
 * @param {string} text raw model output
 * @param {object} [options]
 * @param {string} [options.targetContract] contract the PoC must reference
 *        (e.g. "VulnerableBank"). Defaults to VulnerableBank for callers that
 *        predate multi-contract support.
 * @param {string} [options.testContract] exact name the test contract must
 *        have (e.g. "UncheckedCallPoC") — forge is invoked with
 *        --match-contract, so a differently-named contract yields "no tests
 *        match" and a false NOT CONFIRMED.
 */
function extractSolidity(text, { targetContract = 'VulnerableBank', testContract = '' } = {}) {
  let code = stripCodeFences(text);
  const start = code.search(/\/\/\s*SPDX-License-Identifier:|pragma\s+solidity/i);
  if (start > 0) code = code.slice(start);
  const end = code.lastIndexOf('}');
  if (end !== -1) code = code.slice(0, end + 1);
  code = code.trim();
  if (!code) return { code: null, error: 'empty response' };

  const hasPragma = /pragma\s+solidity\s+[^;]+;/.test(code);
  const hasContract = /contract\s+[A-Za-z_]\w*/.test(code);
  const hasTestFn = /function\s+test[A-Za-z0-9_]*\s*\(/.test(code);
  // Every demo contract has a distinct, simple identifier, so a literal
  // substring check is enough and avoids building a RegExp from user input.
  const name = String(targetContract || '').trim();
  const referencesTarget = name ? code.includes(name) : false;
  const usesForgeStd = /forge-std|Test\.sol|Vm\.sol/.test(code);
  if (!hasPragma) return { code: null, error: 'missing pragma solidity' };
  if (!hasContract) return { code: null, error: 'no contract definition found' };
  if (!hasTestFn) return { code: null, error: 'no test function (test*) found' };
  if (!referencesTarget) return { code: null, error: `does not reference target contract ${name}` };
  if (usesForgeStd) return { code: null, error: 'imports forge-std, which the demo does not use' };
  const expected = String(testContract || '').trim();
  if (expected && !new RegExp(`contract\\s+${expected}\\b`).test(code)) {
    return { code: null, error: `test contract must be named ${expected}` };
  }
  return { code: code + '\n', error: null };
}

async function chatCompletion({ apiKey, baseUrl, model, messages, signal }) {
  const url = `${normalizeBaseUrl(baseUrl)}/chat/completions`;
  const timeout = AbortSignal.timeout(TIMEOUT_MS);
  const combined = signal && AbortSignal.any ? AbortSignal.any([signal, timeout]) : timeout;

  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: model || process.env.LLM_MODEL || DEFAULT_MODEL,
        temperature: 0,
        max_tokens: MAX_TOKENS,
        messages,
      }),
      signal: combined,
    });
  } catch (err) {
    if (err && err.name === 'TimeoutError') throw new Error('LLM request timed out');
    if (err && err.name === 'AbortError') throw new Error('LLM request aborted');
    throw new Error(`LLM request failed: ${err && err.message ? err.message : 'network error'}`);
  }

  const bodyText = await response.text();
  if (!response.ok) {
    const detail = bodyText.replace(/\s+/g, ' ').slice(0, 300);
    throw new Error(`LLM endpoint returned HTTP ${response.status}${detail ? `: ${detail}` : ''}`);
  }

  let data;
  try {
    data = JSON.parse(bodyText);
  } catch {
    throw new Error('LLM endpoint returned a non-JSON response');
  }

  const content = data && data.choices && data.choices[0] && data.choices[0].message
    ? data.choices[0].message.content
    : null;
  if (typeof content !== 'string' || !content.trim()) {
    throw new Error('LLM endpoint returned an empty completion');
  }
  return content;
}

module.exports = {
  DEFAULT_BASE_URL,
  DEFAULT_MODEL,
  normalizeBaseUrl,
  extractSolidity,
  chatCompletion,
};
