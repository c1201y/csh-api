// 验证风险模型的运行时设置（/api/admin/settings）：
//   1. 观测台用服务令牌即可读写参数，未登录被拒；
//   2. 白名单、自动封禁开关、模型开关、封禁时长、SSH 阈值全部生效；
//   3. 非法值被拒绝且不落库；reset 恢复出厂值；
//   4. 模型 ?full=1 能带回权重，供观测台同步本地副本。
// 只使用内存 KV，不接触生产。
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { onRequest } from '../functions/api/%5B%5Bdefault%5D%5D.js'

const model = JSON.parse(readFileSync(new URL('./risk-model.json', import.meta.url), 'utf8'))

const store = new Map()
globalThis.CSH_STATE = {
  async get(key) { return store.has(key) ? store.get(key) : null },
  async put(key, value) { store.set(key, String(value)) },
  async delete(key) { store.delete(key) },
  async list(prefix) { return [...store.keys()].filter((k) => k.startsWith(prefix)) },
}

const baseEnv = {
  CSH_LICENSE_SECRET: 'test-license-secret',
  CSH_BUILD_SECRET: 'test-build-secret',
  CSH_ADMIN_USER: 'admin',
  CSH_ADMIN_PASS: 'pw-123456',
  CSH_LIC_ENFORCE: 'false',
  CSH_ADMIN_API_TOKEN: 'svc-token-1234567890abcdef',
  PURGE_TOKEN: 'purge-test',
  CSH_RISK_ML_ACT: '0.5',
  CSH_RISK_AUTOBAN_MIN: '10',
  CSH_RISK_AUTOBAN_MAX_MIN: '60',
  CSH_RISK_SSH_BAN_HITS: '5',
  CSH_RISK_ALLOW_IPS: '',
}

const token = baseEnv.CSH_ADMIN_API_TOKEN
const pending = []
let failed = 0

function log(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`)
  if (!ok) failed++
}

// 每个请求用新的 env 对象：参数缓存在 env 上，避免读到上一个请求的旧值。
function freshEnv(extra) {
  return { ...baseEnv, ...(extra || {}) }
}

function req(path, { method = 'GET', ip = '198.18.0.70', headers = {}, body } = {}, env = freshEnv()) {
  const h = { origin: 'https://api.test', 'eo-connecting-ip': ip, ...headers }
  const init = { method, headers: h }
  if (body !== undefined) {
    h['content-type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  return onRequest({ request: new Request('https://api.test' + path, init), env, waitUntil(p) { pending.push(p) } })
}

function admin(path, { method = 'GET', body, headers = {}, env = freshEnv() } = {}) {
  const h = { authorization: 'Bearer ' + token, ...headers }
  const init = { method, headers: h }
  if (body !== undefined) {
    h['content-type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  return onRequest({ request: new Request('https://api.test' + path, init), env, waitUntil(p) { pending.push(p) } })
}

async function jsonOf(res) {
  const text = await res.text()
  try { return { status: res.status, data: JSON.parse(text) } } catch { return { status: res.status, data: text } }
}

async function flush() {
  await Promise.allSettled(pending.splice(0))
}

function ipKey(ip) {
  return 'lic:banip:' + createHash('sha256').update(ip).digest('hex').slice(0, 24)
}

function banRec(ip) {
  return store.has(ipKey(ip)) ? JSON.parse(store.get(ipKey(ip))) : null
}

const attack = {
  'user-agent': 'sqlmap/1.7.2#stable (https://sqlmap.org)',
  accept: '*/*',
}
const cleanUa = { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36' }

// ── 0. 鉴权 ────────────────────────────────────────────────────────
const anon = await jsonOf(await onRequest({
  request: new Request('https://api.test/api/admin/settings'),
  env: freshEnv(),
  waitUntil() {},
}))
log('未登录不能读参数', anon.status === 401, `status=${anon.status}`)

// ── 1. 默认值 ──────────────────────────────────────────────────────
const got0 = await jsonOf(await admin('/api/admin/settings'))
const riskGroup = got0.status === 200 ? (got0.data.groups || []).find((g) => g.id === 'risk') : null
const keys = riskGroup ? riskGroup.fields.map((f) => f.key) : []
log('服务令牌可读参数', got0.status === 200 && got0.data.ok === true, `status=${got0.status}`)
log('风险分组含全部字段', keys.length === 15 &&
  ['riskMlOn', 'riskAutoBan', 'riskMlAct', 'riskBanBaseMin', 'riskBanMaxMin', 'riskAllowIps',
    'riskSshBan', 'riskSshHits', 'riskSshBanMin', 'riskSshWindowMin',
    'riskBanMinHits', 'riskBanMinPaths', 'riskTrustHours', 'riskLearnOn', 'riskLearnMin'].every((k) => keys.includes(k)),
  keys.join(','))
const fieldOf = (bundle, key) => bundle.groups.find((g) => g.id === 'risk').fields.find((f) => f.key === key)
log('出厂值来自环境变量', got0.status === 200 &&
  fieldOf(got0.data, 'riskMlAct').def === 0.5 &&
  fieldOf(got0.data, 'riskBanBaseMin').def === 10 &&
  fieldOf(got0.data, 'riskSshHits').def === 5 &&
  fieldOf(got0.data, 'riskMlOn').value === true &&
  fieldOf(got0.data, 'riskAllowIps').value === '' &&
  got0.data.overrides === 0)

// ── 2. 模型上传与全量读取 ───────────────────────────────────────────
const up = await jsonOf(await admin('/api/admin/risk/model', { method: 'POST', body: { model } }))
log('模型上传成功', up.status === 200 && up.data.ok === true, `status=${up.status}`)
const full = await jsonOf(await admin('/api/admin/risk/model?full=1'))
log('?full=1 带回权重', full.status === 200 && full.data.ok === true &&
  full.data.raw && Array.isArray(full.data.raw.weights) &&
  full.data.raw.weights.length === model.weights.length,
  `status=${full.status} dim=${full.data.raw && full.data.raw.dim}`)

// ── 3. 写入参数 ────────────────────────────────────────────────────
const patch = {
  riskAllowIps: '10.0.0.0/8,198.18.0.99',
  riskMlAct: 0.6,
  riskBanBaseMin: 2,
  riskBanMaxMin: 5,
  riskSshHits: 3,
  riskSshBanMin: 7,
  riskSshWindowMin: 30,
}
const saved = await jsonOf(await admin('/api/admin/settings', { method: 'POST', body: { patch } }))
log('服务令牌可写参数', saved.status === 200 && saved.data.changed === 7, `status=${saved.status} changed=${saved.data.changed}`)
const storedCfg = store.has('cfg:settings') ? JSON.parse(store.get('cfg:settings')) : null
log('参数写入 KV', !!storedCfg && storedCfg.v.riskSshHits === 3 && storedCfg.v.riskAllowIps === '10.0.0.0/8,198.18.0.99')

const got1 = await jsonOf(await admin('/api/admin/settings'))
log('回读生效且标记已改', got1.status === 200 &&
  fieldOf(got1.data, 'riskBanBaseMin').value === 2 &&
  fieldOf(got1.data, 'riskBanBaseMin').overridden === true &&
  fieldOf(got1.data, 'riskSshWindowMin').value === 30 &&
  got1.data.overrides === 7)

// ── 4. 白名单生效（含 CIDR） ────────────────────────────────────────
const allowed = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '10.9.9.9', headers: attack }))
await flush()
log('白名单 CIDR 内不封禁', allowed.status !== 429 && !store.has(ipKey('10.9.9.9')), `status=${allowed.status}`)

// 手动封禁白名单 IP 被拒
const manualAllow = await jsonOf(await admin('/api/admin/ip-ban', { method: 'POST', body: { ip: '198.18.0.99', minutes: 5 } }))
log('白名单拒绝手动封禁', manualAllow.status === 400 && !store.has(ipKey('198.18.0.99')), `status=${manualAllow.status}`)

// ── 5. 封禁时长来自参数 ────────────────────────────────────────────
const t0 = Date.now()
const hit = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.0.71', headers: attack }))
await flush()
const rec71 = banRec('198.18.0.71')
const min71 = rec71 ? Math.round((rec71.until - t0) / 60000) : -1
log('自动封禁沿用参数时长', hit.status === 429 && !!rec71 && min71 >= 1 && min71 <= 2, `status=${hit.status} minutes=${min71}`)

// ── 6. SSH 阈值与联动时长 ──────────────────────────────────────────
const now = Date.now()
const evs = (ip, n) => Array.from({ length: n }, (_, i) => ({
  id: `${ip}-${i}`, ts: now - i * 1000, ip, user: 'root', op: 'password',
  kind: 'brute', result: 'failed', n: 1, server: 'ecs',
}))
const t1 = Date.now()
const rep = await jsonOf(await admin('/api/admin/risk/report', { method: 'POST', body: { source: 'ssh', events: evs('198.18.0.72', 4) } }))
await flush()
const rec72 = banRec('198.18.0.72')
const min72 = rec72 ? Math.round((rec72.until - t1) / 60000) : -1
log('SSH 阈值 3 触发封禁', rep.status === 200 && rep.data.actions.length === 1, `actions=${JSON.stringify(rep.data && rep.data.actions)}`)
log('SSH 封禁时长 7 分钟', min72 === 7, `minutes=${min72}`)
log('SSH 未达阈值不动作', (await jsonOf(await admin('/api/admin/risk/report', {
  method: 'POST', body: { source: 'ssh', events: evs('198.18.0.73', 2) },
}))).data.actions.length === 0)

// ── 7. 关闭模型推理只识别不封禁 ─────────────────────────────────────
const offMl = await jsonOf(await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskMlOn: false } } }))
const mlOffReq = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.0.74', headers: attack }))
await flush()
log('关闭模型后不自动封禁', offMl.data.changed === 1 && mlOffReq.status !== 429 && !store.has(ipKey('198.18.0.74')),
  `status=${mlOffReq.status}`)
await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskMlOn: true } } })

// ── 8. 关闭自动封禁 ────────────────────────────────────────────────
await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskAutoBan: false } } })
const offBanReq = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.0.75', headers: attack }))
await flush()
log('关闭自动封禁后放行', offBanReq.status !== 429 && !store.has(ipKey('198.18.0.75')), `status=${offBanReq.status}`)
await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskAutoBan: true } } })

// ── 9. 非法值不落库 ────────────────────────────────────────────────
const badIps = await jsonOf(await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskAllowIps: 'not-an-ip' } } }))
log('非法 IP 列表被拒', badIps.status === 400 && !!badIps.data.errors.riskAllowIps, JSON.stringify(badIps.data))
const badNum = await jsonOf(await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskMlAct: 1.5 } } }))
log('越界数值被拒', badNum.status === 400 && !!badNum.data.errors.riskMlAct, JSON.stringify(badNum.data))
const badKey = await jsonOf(await admin('/api/admin/settings', { method: 'POST', body: { patch: { nope: 1 } } }))
log('未知参数被拒', badKey.status === 400 && !!badKey.data.errors.nope)
const still = await jsonOf(await admin('/api/admin/settings'))
log('被拒后参数不变', fieldOf(still.data, 'riskAllowIps').value === '10.0.0.0/8,198.18.0.99' && fieldOf(still.data, 'riskMlAct').value === 0.6)

// ── 10. reset 恢复出厂值 ───────────────────────────────────────────
const reset = await jsonOf(await admin('/api/admin/settings', { method: 'POST', body: { reset: true } }))
const got2 = await jsonOf(await admin('/api/admin/settings'))
log('reset 清除全部覆盖', reset.status === 200 && reset.data.changed === 7 && got2.data.overrides === 0,
  `changed=${reset.data.changed} overrides=${got2.data.overrides}`)
log('reset 后回到环境默认', fieldOf(got2.data, 'riskBanBaseMin').value === 10 && fieldOf(got2.data, 'riskAllowIps').value === '')

// ── 11. 恢复默认后行为回到环境配置 ─────────────────────────────────
const t2 = Date.now()
const dfltHit = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.0.76', headers: attack }))
await flush()
const rec76 = banRec('198.18.0.76')
const min76 = rec76 ? Math.round((rec76.until - t2) / 60000) : -1
log('默认时长 10 分钟生效', dfltHit.status === 429 && min76 === 10, `status=${dfltHit.status} minutes=${min76}`)

// 正常请求不受影响
const normal = await jsonOf(await req('/api/status', { ip: '198.18.0.77', headers: { ...cleanUa, accept: 'application/json', referer: 'https://classsoftwarehub.cn/' } }))
await flush()
log('正常请求不被误封', normal.status !== 429, `status=${normal.status}`)

await flush()
console.log(failed ? `\n${failed} 项失败` : '\n全部通过')
process.exitCode = failed ? 1 : 0
