'use strict';

const DEFAULT_BASE_URL = 'https://api.openai.com/v1';
const DEFAULT_MODEL = 'gpt-4o-mini';
const TIMEOUT_MS = 90_000;

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
 * Returns null when the response is not usable as a Foundry test.
 *
 * @param {string} text raw model output
 * @param {object} [options]
 * @param {string} [options.targetContract] contract the PoC must reference
 *        (e.g. "VulnerableBank"). Defaults to VulnerableBank for callers that
 *        predate multi-contract support.
 */
function extractSolidity(text, { targetContract = 'VulnerableBank' } = {}) {
  let code = stripCodeFences(text);
  const start = code.search(/\/\/\s*SPDX-License-Identifier:|pragma\s+solidity/i);
  if (start > 0) code = code.slice(start);
  const end = code.lastIndexOf('}');
  if (end !== -1) code = code.slice(0, end + 1);
  code = code.trim();
  if (!code) return null;

  const hasPragma = /pragma\s+solidity\s+[^;]+;/.test(code);
  const hasContract = /contract\s+[A-Za-z_]\w*/.test(code);
  const hasTestFn = /function\s+test[A-Za-z0-9_]*\s*\(/.test(code);
  // Every demo contract has a distinct, simple identifier, so a literal
  // substring check is enough and avoids building a RegExp from user input.
  const name = String(targetContract || '').trim();
  const referencesTarget = name ? code.includes(name) : false;
  const usesForgeStd = /forge-std|Test\.sol|Vm\.sol/.test(code);
  if (!hasPragma || !hasContract || !hasTestFn || !referencesTarget || usesForgeStd) return null;
  return code + '\n';
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
