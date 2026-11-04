// 本地验证：csh-api 运行时模型推理必须与训练器的特征/向量/打分完全一致。
// 使用内存 KV 跑真实 onRequest，不接触生产。
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { onRequest } from '../functions/api/%5B%5Bdefault%5D%5D.js'
import { riskMlTokens, vectorize } from './train-risk-model.mjs'

const modelPath = process.argv[2] || 'risk-model.json'
const model = JSON.parse(readFileSync(modelPath, 'utf8'))

const store = new Map()
globalThis.CSH_STATE = {
  async get(key) { return store.has(key) ? store.get(key) : null },
  async put(key, value) { store.set(key, String(value)) },
  async delete(key) { store.delete(key) },
  async list(prefix) { return [...store.keys()].filter((k) => k.startsWith(prefix)) },
}

const env = {
  CSH_LICENSE_SECRET: 'test-license-secret',
  CSH_BUILD_SECRET: 'test-build-secret',
  CSH_ADMIN_USER: 'admin',
  CSH_ADMIN_PASS: 'pw-123456',
  CSH_LIC_ENFORCE: 'false',
  CSH_ADMIN_API_TOKEN: 'svc-token-1234567890abcdef',
  PURGE_TOKEN: 'purge-test',
}
const token = env.CSH_ADMIN_API_TOKEN
let failed = 0
const pending = []

function log(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`)
  if (!ok) failed++
}

function call(path, { method = 'GET', body, headers = {} } = {}) {
  const req = new Request('https://api.test' + path, {
    method,
    headers: Object.assign({ origin: 'https://api.test', authorization: 'Bearer ' + token }, headers),
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return onRequest({ request: req, env, waitUntil(p) { pending.push(p) } })
}

async function jsonOf(res) {
  const text = await res.text()
  try { return { status: res.status, data: JSON.parse(text) } } catch { return { status: res.status, data: text } }
}

async function flush() {
  await Promise.allSettled(pending.splice(0))
}

function sigmoid(z) {
  return z >= 0 ? 1 / (1 + Math.exp(-z)) : Math.exp(z) / (1 + Math.exp(z))
}

function expectedScore(ev) {
  const x = vectorize(riskMlTokens(ev), model.dim)
  const w = new Map(model.weights)
  let z = model.bias
  for (let i = 0; i < x.length; i++) {
    const wi = w.get(i)
    if (x[i] && wi) z += wi * x[i]
  }
  return sigmoid(z)
}

const samples = [
  {
    name: '扫描器 UA 探测',
    event: {
      service: 'site', method: 'GET', path: '/api/echocave', query: '',
      headers: { 'user-agent': 'sqlmap/1.7.2#stable (https://sqlmap.org)', accept: '*/*' },
      host: 'api.classsoftwarehub.cn',
    },
  },
  {
    name: '正常浏览器提交',
    event: {
      service: 'site', method: 'POST', path: '/api/submit', query: '',
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
        'content-type': 'application/json', accept: 'application/json', referer: 'https://classsoftwarehub.cn/submit',
      },
      host: 'api.classsoftwarehub.cn',
    },
  },
  {
    name: '敏感路径探测',
    event: {
      service: 'site', method: 'GET', path: '/wp-admin/setup-config.php', query: '',
      headers: { 'user-agent': 'Mozilla/5.0' }, host: 'classsoftwarehub.cn',
    },
  },
  {
    name: '下载面 curl + 越权参数',
    event: {
      service: 'download', method: 'GET', path: '/api/dl-ticket', query: 'url=http://169.254.169.254/latest/meta-data/',
      headers: { 'user-agent': 'curl/8.4.0', accept: '*/*', range: 'bytes=0-' },
      host: 'api.classsoftwarehub.cn',
    },
  },
  {
    name: '正常下载请求',
    event: {
      service: 'download', method: 'GET', path: '/pang-zhengyang/ClassSoftwareHub/releases/download/v1.2.3/app-setup.exe',
      query: 's=deadbeef&e=1730000000&h=abcdef&f=app-setup.exe',
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        accept: '*/*', referer: 'https://classsoftwarehub.cn/download',
      },
      host: 'download.classsoftwarehub.cn',
    },
  },
  {
    name: 'OSS 列举探测',
    event: {
      service: 'oss', method: 'GET', path: '/api/files', query: 'source=bucket&all=1&prefix=../',
      headers: { 'user-agent': 'python-requests/2.31.0', accept: 'application/json' },
      host: 'api.classsoftwarehub.cn',
    },
  },
]

// ── 1. 通过管理接口上传模型 ─────────────────────────────────────────
const saved = await jsonOf(await call('/api/admin/risk/model', { method: 'POST', body: { model } }))
log('模型上传成功', saved.status === 200 && saved.data.ok === true && saved.data.model.weights === model.weights.length,
  `status=${saved.status}`)

const status = await jsonOf(await call('/api/admin/risk/model'))
log('模型状态可读且已加载', status.status === 200 && status.data.model.loaded === true &&
  status.data.model.dim === model.dim && status.data.model.high === model.high,
  `threshold=${status.data.model && status.data.model.threshold} high=${status.data.model && status.data.model.high}`)

// ── 2. 特征与打分与训练器逐条对齐 ────────────────────────────────────
for (const s of samples) {
  const out = await jsonOf(await call('/api/admin/risk/explain', { method: 'POST', body: { event: s.event } }))
  const okShape = out.status === 200 && out.data.ok === true && Array.isArray(out.data.tokens)
  if (!okShape) {
    log(`explain: ${s.name}`, false, `status=${out.status} ${JSON.stringify(out.data).slice(0, 120)}`)
    continue
  }
  const want = expectedScore(s.event)
  const got = out.data.score
  const tokenSame = JSON.stringify(out.data.tokens) === JSON.stringify(riskMlTokens(s.event))
  const scoreSame = Math.abs(want - got) < 2e-6
  const sigOk = (got >= model.high ? !!out.data.signals.ml_high : true) &&
    (got >= model.threshold ? !!out.data.signals.ml_anomaly : !out.data.signals.ml_anomaly)
  log(`explain 对齐: ${s.name}`, tokenSame && scoreSame && sigOk,
    `score=${got.toFixed(4)} want=${want.toFixed(4)} tokens=${out.data.tokens.length} tokenSame=${tokenSame}`)
}

// ── 3. 非法模型整份拒绝 ─────────────────────────────────────────────
const badFeature = { ...model, feature: 'risk-request-v0' }
const bad1 = await jsonOf(await call('/api/admin/risk/model', { method: 'POST', body: { model: badFeature } }))
log('拒绝旧版本特征模型', bad1.status === 400)

const bad2 = await jsonOf(await call('/api/admin/risk/model', { method: 'POST', body: { model: { ...model, weights: [[0, 'x']] } } }))
log('拒绝非法权重模型', bad2.status === 400)

const still = await jsonOf(await call('/api/admin/risk/model'))
log('非法上传不影响已加载模型', still.data.model.loaded === true && still.data.model.high === model.high)

// ── 4. 真实请求：模型信号写入 IP 风险记录 ────────────────────────────
const ip = '203.0.113.77'
const riskReq = new Request('https://api.test/api/files?source=bucket&all=1&prefix=../', {
  method: 'GET',
  headers: {
    'eo-connecting-ip': ip,
    'user-agent': 'python-requests/2.31.0',
    accept: 'application/json',
  },
})
const res = await onRequest({ request: riskReq, env, waitUntil(p) { pending.push(p) } })
await flush()
log('可疑请求返回响应', res.status > 0, `status=${res.status}`)

const key = 'lic:risk:i:' + createHash('sha256').update(ip).digest('hex').slice(0, 24)
const rec = store.has(key) ? JSON.parse(store.get(key)) : null
const reasons = rec && rec.r ? Object.keys(rec.r) : []
log('模型信号已并入风险记录', !!rec && (reasons.includes('ml_anomaly') || reasons.includes('ml_high')),
  `reasons=${reasons.join(',')} s=${rec && rec.s}`)

// 正常 200 的 API 调用不参与模型打分（API 路径与训练日志分布不同，避免误报）。
const ip2 = '203.0.113.78'
const okReq = new Request('https://api.test/api/dl-mode', {
  method: 'GET',
  headers: {
    'eo-connecting-ip': ip2,
    'x-purge-token': 'purge-test',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36',
    accept: 'application/json',
  },
})
const okRes = await onRequest({ request: okReq, env, waitUntil(p) { pending.push(p) } })
await flush()
const key2 = 'lic:risk:i:' + createHash('sha256').update(ip2).digest('hex').slice(0, 24)
const rec2 = store.has(key2) ? JSON.parse(store.get(key2)) : null
log('正常 200 请求不产生模型风险记录', okRes.status === 200 && !rec2, `status=${okRes.status} rec=${rec2 ? Object.keys(rec2.r).join(',') : 'none'}`)

// ── 5. 删除模型后优雅回退 ───────────────────────────────────────────
const del = await jsonOf(await call('/api/admin/risk/model', { method: 'POST', body: { delete: true } }))
const after = await jsonOf(await call('/api/admin/risk/model'))
log('删除模型后回退为纯规则', del.data.deleted === true && after.data.model.loaded === false)

const noModel = await jsonOf(await call('/api/admin/risk/explain', { method: 'POST', body: { event: samples[0].event } }))
log('无模型时 explain 明确返回 503', noModel.status === 503)

await flush()
console.log(failed ? `\n${failed} 项失败` : '\n全部通过')
process.exitCode = failed ? 1 : 0
