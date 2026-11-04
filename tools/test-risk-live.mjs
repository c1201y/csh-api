// 验证“同步识别 + 模型自动封禁 + SSH 实时上报”：
//   1. 高置信攻击在本次请求内被 429，并落地 IP 封禁；
//   2. 后续请求（含干净请求）由同步闸门直接拒绝；
//   3. 白名单、关闭开关、正常请求都不会被误封；
//   4. SSH 上报能把失败聚合成风险并触发封禁；
//   5. 管理接口可查看/解封。
// 只使用内存 KV，不接触生产。
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { onRequest } from '../functions/api/%5B%5Bdefault%5D%5D.js'

const modelPath = process.argv[2] || 'tools/risk-model.json'
const model = JSON.parse(readFileSync(modelPath, 'utf8'))

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
}

const token = baseEnv.CSH_ADMIN_API_TOKEN
const pending = []
let failed = 0

function log(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`)
  if (!ok) failed++
}

function req(path, { method = 'GET', ip = '198.18.0.10', headers = {}, body } = {}, env = baseEnv) {
  const h = { origin: 'https://api.test', 'eo-connecting-ip': ip, ...headers }
  const init = { method, headers: h }
  if (body !== undefined) {
    h['content-type'] = 'application/json'
    init.body = JSON.stringify(body)
  }
  return onRequest({ request: new Request('https://api.test' + path, init), env, waitUntil(p) { pending.push(p) } })
}

function admin(path, { method = 'GET', body, headers = {} } = {}, env = baseEnv) {
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

// ── 0. 模型上线 ────────────────────────────────────────────────────
const up = await jsonOf(await admin('/api/admin/risk/model', { method: 'POST', body: { model } }))
log('模型上传成功', up.status === 200 && up.data.ok === true, `status=${up.status}`)

// ── 1. 高置信攻击：本次即拒绝并封禁 ─────────────────────────────────
const attack = {
  'user-agent': 'sqlmap/1.7.2#stable (https://sqlmap.org)',
  accept: '*/*',
}
const first = await jsonOf(await req('/api/wp-admin/setup-config.php?x=union%20select%201', { ip: '198.18.0.10', headers: attack }))
await flush()
log('高置信攻击本次请求即 429', first.status === 429 && first.data.code === 'csh_ip_restricted',
  `status=${first.status} code=${first.data.code}`)
log('封禁记录已落地', store.has(ipKey('198.18.0.10')), `key=${ipKey('198.18.0.10')}`)
const banRec = store.has(ipKey('198.18.0.10')) ? JSON.parse(store.get(ipKey('198.18.0.10'))) : null
log('封禁带时长与原因', !!banRec && banRec.until > Date.now() && !!banRec.reason,
  banRec && `until=${banRec.until} reason=${banRec.reason} lv=${banRec.lv}`)

const follow = await jsonOf(await req('/api/status', {
  ip: '198.18.0.10',
  headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36' },
}))
await flush()
log('同一 IP 的后续干净请求也被挡住', follow.status === 429 && follow.data.code === 'csh_ip_restricted', `status=${follow.status}`)

const other = await jsonOf(await req('/api/status', {
  ip: '198.18.0.11',
  headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36' },
}))
await flush()
log('其它 IP 不受影响', other.status !== 429, `status=${other.status}`)

// ── 2. 白名单不封禁 ────────────────────────────────────────────────
const allowEnv = { ...baseEnv, CSH_RISK_ALLOW_IPS: '198.18.0.99,10.0.0.0/8' }
const allowed = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.0.99', headers: attack }, allowEnv))
await flush()
log('白名单 IP 不会被自动封禁', allowed.status !== 429 && !store.has(ipKey('198.18.0.99')), `status=${allowed.status}`)

// ── 3. 关闭自动封禁 ────────────────────────────────────────────────
const offEnv = { ...baseEnv, CSH_RISK_AUTOBAN: 'off' }
const off = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.0.30', headers: attack }, offEnv))
await flush()
log('关闭开关后只识别不封禁', off.status !== 429 && !store.has(ipKey('198.18.0.30')), `status=${off.status}`)

// ── 4. 正常请求不触发模型动作 ───────────────────────────────────────
const normal = await jsonOf(await req('/api/status', {
  ip: '198.18.0.40',
  headers: {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
    accept: 'application/json',
    referer: 'https://classsoftwarehub.cn/',
  },
}))
await flush()
log('正常浏览器请求不被误封', normal.status !== 429, `status=${normal.status}`)

// ── 5. SSH 实时上报：聚合失败 → 风险 + 封禁 ─────────────────────────
const now = Date.now()
const sshEvents = Array.from({ length: 6 }, (_, i) => ({
  id: `live-ssh-${i}`,
  ts: now - i * 1000,
  ip: '198.18.0.20',
  user: 'root',
  op: 'password',
  kind: 'brute',
  result: 'failed',
  n: 1,
  server: 'ecs',
}))
const rep = await jsonOf(await admin('/api/admin/risk/report', { method: 'POST', body: { source: 'ssh', events: sshEvents } }))
await flush()
log('SSH 上报入账成功', rep.status === 200 && rep.data.added === 6, `status=${rep.status} added=${rep.data && rep.data.added}`)
log('SSH 失败量触发封禁', rep.status === 200 && Array.isArray(rep.data.actions) && rep.data.actions.length === 1,
  JSON.stringify(rep.data && rep.data.actions))
log('SSH 封禁记录存在', store.has(ipKey('198.18.0.20')))

const sshFollow = await jsonOf(await req('/api/status', {
  ip: '198.18.0.20',
  headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36' },
}))
await flush()
log('SSH 攻击 IP 访问 API 被拒', sshFollow.status === 429 && sshFollow.data.code === 'csh_ip_restricted', `status=${sshFollow.status}`)

// 重复上报不能把同一批证据反复升级：动作只对新增证据生效。
const rep2 = await jsonOf(await admin('/api/admin/risk/report', { method: 'POST', body: { source: 'ssh', events: sshEvents } }))
await flush()
log('重复上报不重复动作', rep2.status === 200 && rep2.data.added === 0 && rep2.data.actions.length === 0,
  `added=${rep2.data && rep2.data.added} actions=${JSON.stringify(rep2.data && rep2.data.actions)}`)

// ── 6. 后台清单与解封 ──────────────────────────────────────────────
const list = await jsonOf(await admin('/api/admin/ip-bans'))
const row = list.status === 200 && Array.isArray(list.data.rows)
  ? list.data.rows.find((x) => x.ip === '198.18.0.10')
  : null
log('后台能看到自动封禁', !!row && row.active === true, row && JSON.stringify(row))

const unban = await jsonOf(await admin('/api/admin/ip-unban', { method: 'POST', body: { ip: '198.18.0.10' } }))
await flush()
log('解封成功', unban.status === 200 && unban.data.removed === true, JSON.stringify(unban.data))

const afterUnban = await jsonOf(await req('/api/status', {
  ip: '198.18.0.10',
  headers: { 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36' },
}))
await flush()
log('解封后恢复访问', afterUnban.status !== 429, `status=${afterUnban.status}`)

// 手动封禁
const manual = await jsonOf(await admin('/api/admin/ip-ban', { method: 'POST', body: { ip: '198.18.0.50', minutes: 5, reason: '测试' } }))
await flush()
const manualReq = await jsonOf(await req('/api/status', { ip: '198.18.0.50', headers: { 'user-agent': 'Mozilla/5.0 Chrome/130' } }))
await flush()
log('手动封禁立即生效', manual.status === 200 && manualReq.status === 429, `ban=${manual.status} req=${manualReq.status}`)

const badIp = await jsonOf(await admin('/api/admin/ip-ban', { method: 'POST', body: { ip: 'not-an-ip' } }))
log('非法 IP 被拒绝', badIp.status === 400)

await flush()
console.log(failed ? `\n${failed} 项失败` : '\n全部通过')
process.exitCode = failed ? 1 : 0
