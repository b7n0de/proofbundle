#!/usr/bin/env node
// Offline verifier for a Certisyn containment public record. Node 20 or later, no dependencies.
//   node verify.mjs <record.json> <seal.json> [input.json]
// The public key is read from KEY.json beside this file. It is the pinned key agreed before the pilot.
// The key carried inside a seal is never used.
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA = 'certisyn/containment-public/v1';
const DOMAIN = 'certisyn/containment-seal/v1';

// Strict JSON reader. Member names are compared after unescaping. A repeated name is refused.
export function parseStrict(text) {
  let i = 0;
  const ws = () => { while (i < text.length && ' \t\n\r'.includes(text[i])) i++; };
  const fail = (m) => { throw new Error(`${m} at offset ${i}`); };
  function str() {
    if (text[i] !== '"') fail('expected string');
    const start = i; i++;
    while (i < text.length && text[i] !== '"') { if (text[i] === '\\') i++; i++; }
    if (text[i] !== '"') fail('unterminated string');
    i++;
    return JSON.parse(text.slice(start, i));
  }
  function val() {
    ws();
    const c = text[i];
    if (c === '{') {
      i++; const o = {}; const seen = new Set(); ws();
      if (text[i] === '}') { i++; return o; }
      for (;;) {
        ws(); const k = str();
        if (seen.has(k)) fail(`duplicate member name "${k}"`);
        seen.add(k); ws();
        if (text[i] !== ':') fail('expected colon'); i++;
        o[k] = val(); ws();
        if (text[i] === ',') { i++; continue; }
        if (text[i] === '}') { i++; return o; }
        fail('expected comma or close brace');
      }
    }
    if (c === '[') {
      i++; const a = []; ws();
      if (text[i] === ']') { i++; return a; }
      for (;;) { a.push(val()); ws(); if (text[i] === ',') { i++; continue; } if (text[i] === ']') { i++; return a; } fail('expected comma or close bracket'); }
    }
    if (c === '"') return str();
    const m = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?|^true|^false|^null/.exec(text.slice(i));
    if (!m) fail('unexpected token');
    i += m[0].length;
    return JSON.parse(m[0]);
  }
  const v = val(); ws();
  if (i !== text.length) fail('trailing content');
  return v;
}

// Canonical form: members sorted by UTF-16 code unit, no whitespace, numbers and strings as in ECMAScript JSON.
export function canonical(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
}
export const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

export function verifyPair(recordText, sealText, pinnedPubB64, inputText) {
  const reasons = [];
  let rec, seal;
  try { rec = parseStrict(recordText); } catch (e) { return { ok: false, reasons: [`record: ${e.message}`] }; }
  try { seal = parseStrict(sealText); } catch (e) { return { ok: false, reasons: [`seal: ${e.message}`] }; }
  if (rec.schema !== SCHEMA) reasons.push('record schema is not ' + SCHEMA);
  const { result_digest, ...body } = rec;
  if (sha256(canonical(body)) !== result_digest) reasons.push('result_digest does not recompute from the record body');
  if (inputText !== undefined) {
    let inp; try { inp = parseStrict(inputText); } catch (e) { reasons.push(`input: ${e.message}`); }
    if (inp && sha256(canonical(inp)) !== rec.input_digest) reasons.push('input_digest does not recompute from the input file');
  }
  if (seal.domain !== DOMAIN || seal.algorithm !== 'ed25519') reasons.push('seal domain or algorithm is not the containment seal');
  const msg = `${DOMAIN}\n${SCHEMA}\n${result_digest}`;
  if (seal.signed_message !== msg) reasons.push('signed message does not match the record digest');
  if (seal.signed_message_sha256 !== sha256(seal.signed_message ?? '')) reasons.push('signed_message_sha256 does not recompute');
  try {
    const raw = Buffer.from(pinnedPubB64, 'base64');
    const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), raw]), format: 'der', type: 'spki' });
    if (!verify(null, Buffer.from(seal.signed_message ?? ''), key, Buffer.from(seal.signature_b64 ?? '', 'base64'))) reasons.push('signature does not verify under the pinned key');
  } catch { reasons.push('signature or key could not be decoded'); }
  return { ok: reasons.length === 0, reasons };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const here = dirname(fileURLToPath(import.meta.url));
  const [rf, sf, inf] = process.argv.slice(2);
  if (!rf || !sf) { console.error('usage: node verify.mjs <record.json> <seal.json> [input.json]'); process.exit(2); }
  const pub = JSON.parse(readFileSync(join(here, 'KEY.json'), 'utf8')).ed25519_pub_b64;
  const r = verifyPair(readFileSync(rf, 'utf8'), readFileSync(sf, 'utf8'), pub, inf ? readFileSync(inf, 'utf8') : undefined);
  console.log(r.ok ? 'ACCEPT' : 'REFUSE');
  for (const x of r.reasons) console.log('  ' + x);
  process.exit(r.ok ? 0 : 1);
}
