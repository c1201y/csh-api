// 验证反馈标注、增量自学习、回滚与误报信任：
//   1. 反馈接口鉴权、去重、列表统计；
//   2. dry-run 不落盘，正式学习版本号 +1，可回滚；
//   3. 误报标注会自动解封并进入信任名单，信任期内不再被自动封禁；
//   4. 自动学习按 learnMin 触发，参数在 ip-bans 中可读。
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
  CSH_RISK_ALLOW_IPS: '',
}
const token = baseEnv.CSH_ADMIN_API_TOKEN
const pending = []
let failed = 0
function log(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`)
  if (!ok) failed++
}
const freshEnv = (extra) => ({ ...baseEnv, ...(extra || {}) })
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
const flush = () => Promise.allSettled(pending.splice(0))
const ipKey = (ip) => 'lic:banip:' + createHash('sha256').update(ip).digest('hex').slice(0, 24)
const banRec = (ip) => (store.has(ipKey(ip)) ? JSON.parse(store.get(ipKey(ip))) : null)

const attack = { 'user-agent': 'sqlmap/1.7.2#stable (https://sqlmap.org)', accept: '*/*' }
// 每条样本使用互不重叠的合成 token，验证学习机制本身；锚点保护单独用攻击特征验证。
const tokensFor = (n) => [`x:learn-${n}`, `x:grp-${n}`, `x:fb-${n}`]
const sample = (ip, label, n, path = `/probe-${n}`) => ({
  ip, path, method: 'GET', service: 'site', label, score: label ? 0.93 : 0.88, tokens: tokensFor(n),
})

// ── 0. 鉴权 ────────────────────────────────────────────────────────
const anon = await jsonOf(await req('/api/admin/risk/feedback'))
log('未登录不能读反馈', anon.status === 401, `status=${anon.status}`)

// ── 1. 上传模型 + 添加反馈 ─────────────────────────────────────────
const up = await jsonOf(await admin('/api/admin/risk/model', { method: 'POST', body: { model } }))
log('模型上传成功', up.status === 200 && up.data.ok === true, `status=${up.status}`)

const add1 = await jsonOf(await admin('/api/admin/risk/feedback', { method: 'POST', body: sample('198.18.3.10', 1, 1) }))
log('添加恶意样本', add1.status === 200 && add1.data.ok === true && add1.data.duplicate === false && !!add1.data.item.id,
  JSON.stringify(add1.data))
const dup = await jsonOf(await admin('/api/admin/risk/feedback', { method: 'POST', body: sample('198.18.3.10', 1, 1) }))
log('重复样本被去重', dup.status === 200 && dup.data.duplicate === true)

const missing = await jsonOf(await admin('/api/admin/risk/feedback', { method: 'POST', body: { ip: '198.18.3.11', path: '/x', label: 1 } }))
log('缺少 token 被拒', missing.status === 400)

const list1 = await jsonOf(await admin('/api/admin/risk/feedback?limit=20'))
log('反馈列表可读', list1.status === 200 && list1.data.total === 1 && list1.data.pos === 1 && list1.data.items.length === 1,
  `total=${list1.data.total} pos=${list1.data.pos}`)
log('反馈附带特征 token', Array.isArray(list1.data.items[0].t) && list1.data.items[0].t.length === 3)

// ── 2. 学习 dry-run / 正式 / 回滚 ──────────────────────────────────
const dry = await jsonOf(await admin('/api/admin/risk/model/learn', { method: 'POST', body: { force: true, dryRun: true } }))
log('dry-run 返回评估', dry.status === 200 && dry.data.ok === true && dry.data.dryRun === true &&
  dry.data.before && dry.data.after && dry.data.anchors && dry.data.anchors.ok === true,
  JSON.stringify(dry.data.anchors || dry.data))
const afterDry = await jsonOf(await admin('/api/admin/risk/model'))
log('dry-run 不写版本', afterDry.status === 200 && afterDry.data.model.mv === 1 && !afterDry.data.prev)

const learn1 = await jsonOf(await admin('/api/admin/risk/model/learn', { method: 'POST', body: { force: true } }))
log('正式学习成功', learn1.status === 200 && learn1.data.ok === true && learn1.data.samples >= 1 && learn1.data.mv === 2,
  `status=${learn1.status} ${JSON.stringify(learn1.data.error || '')}`)
const afterLearn = await jsonOf(await admin('/api/admin/risk/model'))
log('模型版本 +1 且保留上一版', afterLearn.status === 200 && afterLearn.data.model.mv === 2 &&
  afterLearn.data.prev && afterLearn.data.prev.mv === 1 &&
  afterLearn.data.train && afterLearn.data.train.mv === 2,
  JSON.stringify(afterLearn.data.prev))

const rollback = await jsonOf(await admin('/api/admin/risk/model/rollback', { method: 'POST' }))
log('回滚成功', rollback.status === 200 && rollback.data.ok === true && rollback.data.mv === 1, JSON.stringify(rollback.data))
const afterRollback = await jsonOf(await admin('/api/admin/risk/model'))
log('回滚后版本为 1', afterRollback.status === 200 && afterRollback.data.model.mv === 1)

// ── 3. 误报标注：解封 + 信任 ───────────────────────────────────────
const ban = await jsonOf(await admin('/api/admin/ip-ban', { method: 'POST', body: { ip: '198.18.3.20', minutes: 10, reason: 'test' } }))
log('先手动封禁', ban.status === 200 && !!banRec('198.18.3.20'))
const fp = await jsonOf(await admin('/api/admin/risk/feedback', {
  method: 'POST', body: sample('198.18.3.20', 0, 20, '/api/status'),
}))
log('误报标注解封', fp.status === 200 && fp.data.ok === true && fp.data.unbanned === true, JSON.stringify(fp.data))
log('误报标注写入信任', fp.status === 200 && fp.data.trustUntil > Date.now() && fp.data.trustHours === 24,
  `until=${fp.data.trustUntil} hours=${fp.data.trustHours}`)

const trustedHit = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.3.20', headers: attack }))
await flush()
log('信任期内不再自动封禁', trustedHit.status !== 429 && !banRec('198.18.3.20'), `status=${trustedHit.status}`)

const trustList = await jsonOf(await admin('/api/admin/ip-trust'))
log('信任名单可读', trustList.status === 200 && trustList.data.total === 1 &&
  trustList.data.items[0].ip === '198.18.3.20' && trustList.data.hours === 24,
  JSON.stringify(trustList.data))

const untrust = await jsonOf(await admin('/api/admin/ip-trust', { method: 'POST', body: { ip: '198.18.3.20', clear: true } }))
log('可手动移除信任', untrust.status === 200 && untrust.data.removed === true)
const attackHit = await jsonOf(await req('/api/wp-admin/setup-config.php?x=1', { ip: '198.18.3.20', headers: attack }))
await flush()
log('移除信任后恢复自动封禁', attackHit.status === 429 && !!banRec('198.18.3.20'), `status=${attackHit.status}`)

// ── 4. 自动学习触发与阈值参数 ─────────────────────────────────────
const cfgSet = await jsonOf(await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskLearnMin: 5, riskBanMinHits: 7, riskBanMinPaths: 3 } } }))
log('自学习/重复阈值可配置', cfgSet.status === 200 && cfgSet.data.changed === 3, `changed=${cfgSet.data.changed}`)
const bans = await jsonOf(await admin('/api/admin/ip-bans'))
log('ip-bans 回显新阈值', bans.status === 200 && bans.data.cfg.learnMin === 5 &&
  bans.data.cfg.minHits === 7 && bans.data.cfg.minPaths === 3, JSON.stringify(bans.data.cfg))

const autoFew = await jsonOf(await admin('/api/admin/risk/model/learn', { method: 'POST', body: { auto: true } }))
log('样本不足时自动学习跳过', autoFew.status === 200 && autoFew.data.skipped === 'few', JSON.stringify(autoFew.data))

for (let i = 0; i < 6; i++) {
  await admin('/api/admin/risk/feedback', { method: 'POST', body: sample(`198.18.3.3${i}`, i % 2, 30 + i) })
}
const autoLearn = await jsonOf(await admin('/api/admin/risk/model/learn', { method: 'POST', body: { auto: true } }))
log('达到阈值后自动学习', autoLearn.status === 200 && autoLearn.data.ok === true && autoLearn.data.samples >= 5 &&
  autoLearn.data.mv === 2, JSON.stringify(autoLearn.data.error ? { err: autoLearn.data.error, anchors: autoLearn.data.anchors, before: autoLearn.data.before, after: autoLearn.data.after } : { mv: autoLearn.data.mv, n: autoLearn.data.samples }))

// ── 5. 锚点守卫拒绝伤害检测的学习 ─────────────────────────────────
const clear0 = await jsonOf(await admin('/api/admin/risk/feedback', { method: 'POST', body: { clear: true } }))
log('清空反馈以便单测守卫', clear0.status === 200)
const ex = await jsonOf(await admin('/api/admin/risk/explain', {
  method: 'POST',
  body: {
    event: {
      service: 'site', method: 'GET', path: '/wp-login.php', query: '',
      headers: { 'user-agent': 'sqlmap/1.7.2#stable' }, host: 'classsoftwarehub.cn', http: '1.1',
    },
  },
}))
const badTokens = ex.status === 200 && Array.isArray(ex.data.tokens) ? ex.data.tokens : ['pk:wp-login']
log('攻击样本评分很高', ex.status === 200 && ex.data.score >= 0.9, `score=${ex.data && ex.data.score}`)
for (let i = 0; i < 3; i++) {
  await admin('/api/admin/risk/feedback', {
    method: 'POST',
    body: {
      ip: `198.18.4.${i + 1}`, path: `/guard-${i}`, method: 'GET', label: 0, score: 0.95,
      tokens: badTokens,
    },
  })
}
const guarded = await jsonOf(await admin('/api/admin/risk/model/learn', { method: 'POST', body: { force: true, lr: 2 } }))
log('锚点守卫拒绝压低攻击特征', guarded.status === 400 && guarded.data.ok === false &&
  /锚点守卫/.test(String(guarded.data.error)), JSON.stringify(guarded.data.anchors || guarded.data.error))

// ── 6. 清空反馈 ───────────────────────────────────────────────────
const clear = await jsonOf(await admin('/api/admin/risk/feedback', { method: 'POST', body: { clear: true } }))
log('清空反馈', clear.status === 200 && clear.data.removed > 0, JSON.stringify(clear.data))
const list2 = await jsonOf(await admin('/api/admin/risk/feedback'))
log('清空后列表为空', list2.status === 200 && list2.data.total === 0 && list2.data.stored === 0)

await flush()
console.log(failed ? `\n${failed} 项失败` : '\n全部通过')
process.exitCode = failed ? 1 : 0
