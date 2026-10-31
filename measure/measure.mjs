#!/usr/bin/env node
// Measures installable non-browser clients against the reflector; never fabricates.
import { execFile } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
const C = join(HERE, 'clients');
const URL = process.env.REFLECTOR_URL || process.env.REFLECTOR || 'https://tls.peet.ws/api/all';
const OUT = process.argv[2] || join(HERE, 'measured.json');
const DATE = new Date().toISOString().slice(0, 10);

const JA4_RE = /^[tq]\d{2}[di]\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/;

const CLIENTS = [
  { id: 'curl-h2',   label: 'curl (HTTP/2 ALPN)',  tool: 'curl', category: 'tool',    bin: 'curl',    argv: ['curl', '-s', '--http2', URL], ver: ['curl', '--version'] },
  { id: 'curl-h1',   label: 'curl (HTTP/1.1)',     tool: 'curl', category: 'tool',    bin: 'curl',    argv: ['curl', '-s', '--http1.1', URL], ver: ['curl', '--version'] },
  { id: 'wget',      label: 'GNU Wget',            tool: 'wget', category: 'tool',    bin: 'wget',    argv: ['wget', '-qO-', URL], ver: ['wget', '--version'] },
  { id: 'python-requests', label: 'python-requests', tool: 'python-requests', category: 'library', bin: 'python3', argv: ['python3', '-I', join(C, 'req_requests.py'), URL] },
  { id: 'python-httpx', label: 'python-httpx', tool: 'python-httpx', category: 'library', bin: 'python3', argv: ['python3', '-I', join(C, 'req_httpx.py'), URL, '--http2'] },
  { id: 'python-urllib', label: 'python urllib', tool: 'python-urllib', category: 'library', bin: 'python3', argv: ['python3', '-I', join(C, 'req_urllib.py'), URL] },
  { id: 'python-aiohttp', label: 'python-aiohttp', tool: 'python-aiohttp', category: 'library', bin: 'python3', argv: ['python3', '-I', join(C, 'req_aiohttp.py'), URL] },
  { id: 'go-nethttp', label: 'Go net/http', tool: 'go-net-http', category: 'library', bin: 'go', argv: ['go', 'run', join(C, 'gohttp', 'main.go'), URL] },
  { id: 'node-fetch', label: 'Node fetch (undici)', tool: 'node-undici', category: 'library', bin: 'node', argv: ['node', join(C, 'node_fetch.mjs'), URL] },
  { id: 'java-httpclient', label: 'Java HttpClient', tool: 'java-httpclient', category: 'library', bin: 'java', argv: ['java', join(C, 'Fetch.java'), URL] },
];

function sanitize(s) {
  return String(s == null ? '' : s).replace(/[\r\n]+/g, ' ').trim();
}

// Some reflectors omit the 2-char ALPN field when there is no ALPN; the FoxIO
// spec (and ja4-guard) encode that as "00". Pad it so both forms agree.
function canonJA4(ja4) {
  const p = ja4.split('_');
  if (p.length === 3 && p[0].length === 8) p[0] += '00';
  return p.join('_');
}

function extract(d) {
  const tls = d.tls || {};
  const h2 = d.http2 || {};
  return {
    ja4: canonJA4(sanitize(d.ja4 || tls.ja4)),
    ja4h: sanitize(d.ja4h || tls.ja4h || (d.http1 || {}).ja4h || h2.ja4h),
    akamai: sanitize(d.akamai_h2 || h2.akamai_fingerprint),
  };
}

async function has(bin) {
  try { await run('command', ['-v', bin], { shell: '/bin/bash' }); return true; }
  catch { return false; }
}

async function version(c, stderr) {
  if (c.ver) {
    try {
      const { stdout } = await run(c.ver[0], c.ver.slice(1));
      const first = stdout.split('\n')[0];
      const m = first.match(/\d+\.\d+(\.\d+)?/);
      return sanitize(m ? m[0] : first);
    } catch { return 'unknown'; }
  }
  const line = (stderr || '').trim().split('\n').pop() || '';
  return sanitize(line) || 'unknown';
}

const entries = [];
const skipped = [];

for (const c of CLIENTS) {
  if (!(await has(c.bin))) {
    skipped.push({ id: c.id, reason: `${c.bin} not installed` });
    console.error(`SKIP  ${c.id}: ${c.bin} not installed`);
    continue;
  }
  let stdout, stderr;
  try {
    ({ stdout, stderr } = await run(c.argv[0], c.argv.slice(1), { timeout: 60000, maxBuffer: 4 << 20 }));
  } catch (e) {
    skipped.push({ id: c.id, reason: `run failed: ${sanitize(e.message)}` });
    console.error(`SKIP  ${c.id}: run failed`);
    continue;
  }
  let fp;
  try { fp = JSON.parse(stdout); }
  catch {
    skipped.push({ id: c.id, reason: 'reflector response not JSON' });
    console.error(`SKIP  ${c.id}: non-JSON response`);
    continue;
  }
  const { ja4, ja4h, akamai } = extract(fp);
  if (!JA4_RE.test(ja4)) {
    skipped.push({ id: c.id, reason: `no valid JA4 (${ja4 || 'empty'})` });
    console.error(`SKIP  ${c.id}: no valid JA4`);
    continue;
  }
  const ver = await version(c, stderr);
  const e = {
    ja4,
    category: c.category,
    label: `${c.label} ${ver}`,
    verdict: 'non-browser',
    source: URL,
    provenance: { method: 'measured', tool: c.tool, version: ver, date: DATE },
  };
  if (ja4h && ja4h !== 'ge20nn000000_000000000000_000000000000_000000000000') e.ja4h = ja4h;
  if (akamai) e.akamai_h2 = akamai;
  entries.push(e);
  console.error(`OK    ${c.id}: ${ja4} (${ver})`);
}

if (entries.length === 0) {
  console.error('FATAL: measured 0 clients — refusing to write an empty feed.');
  process.exit(1);
}

entries.sort((a, b) => a.label.localeCompare(b.label));
writeFileSync(OUT, JSON.stringify({ measured: DATE, reflector: URL.replace(/^https?:\/\//, '').split('/')[0], entries, skipped }, null, 2) + '\n');
console.error(`\nwrote ${entries.length} measured entr${entries.length === 1 ? 'y' : 'ies'} to ${OUT} (${skipped.length} skipped)`);
