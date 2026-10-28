// Runs every vector and compares with expected.json. Exit 0 only when every outcome matches.
import { readFileSync } from 'node:fs';
import { verifyPair } from './verify.mjs';
const pub = JSON.parse(readFileSync('KEY.json', 'utf8')).ed25519_pub_b64;
const exp = JSON.parse(readFileSync('expected.json', 'utf8'));
let bad = 0;
const run = (id, want, over = {}) => {
  const rec = over.record ?? id;
  const inId = over.input ?? id;
  const inp = ['P01', 'P02'].includes(inId) ? readFileSync(`inputs/${inId}.input.json`, 'utf8') : undefined;
  const r = verifyPair(readFileSync(`vectors/${rec}.record.json`, 'utf8'), readFileSync(`vectors/${rec}.seal.json`, 'utf8'), pub, inp);
  const got = r.ok ? 'ACCEPT' : 'REFUSE';
  if (got !== want) bad++;
  console.log(`${id} expected ${want} got ${got}${r.ok ? '' : '  (' + r.reasons[0] + ')'}`);
};
for (const id of exp.accept) run(id, 'ACCEPT');
for (const n of exp.refuse) run(n.id, 'REFUSE', n);
console.log(bad ? `${bad} MISMATCH` : 'all vectors behave as expected');
process.exit(bad ? 1 : 0);
