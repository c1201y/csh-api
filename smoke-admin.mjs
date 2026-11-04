// 本地烟测：用内存 KV 跑通「登录 → 签发 → 激活 → 封禁」全链路。
// 仅用于开发期验证，不参与部署。
import { createHash } from 'node:crypto'
import { onRequest } from './functions/api/%5B%5Bdefault%5D%5D.js'
import { onRequest as adminPage } from './functions/admin.js'

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
  CSH_LIC_ENFORCE_AT: '',
  CSH_LIC_LEGACY_UNTIL: '',
  CSH_ADMIN_API_TOKEN: 'svc-token-1234567890abcdef',
}

const sha256HexLocal = (text) => createHash('sha256').update(String(text)).digest('hex')

let cookie = ''
const pendingTasks = []

function call(path, { method = 'GET', body, headers = {} } = {}) {
  const req = new Request('https://api.test' + path, {
    method,
    headers: Object.assign({ origin: 'https://api.test', 'sec-fetch-site': 'same-origin' }, headers),
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return onRequest({ request: req, env, waitUntil(p) { pendingTasks.push(p) } })
}

/** 等待 waitUntil 收集的异步任务（设备触点等）落库完成。 */
async function flush() {
  await Promise.allSettled(pendingTasks.splice(0))
}

async function jsonOf(res) {
  const text = await res.text()
  try { return { status: res.status, data: JSON.parse(text) } } catch { return { status: res.status, data: text } }
}

function log(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`)
  if (!ok) process.exitCode = 1
}

const session0 = await jsonOf(await call('/api/admin/session'))
log('未登录时 session 返回 401', session0.status === 401 && session0.data.ready === true)

// ── 设备信誉 / 服务令牌 ──────────────────────────────────────────────
const noToken = await jsonOf(await call('/api/admin/devices'))
log('无会话且无令牌访问设备列表被拒', noToken.status === 401)

const svcToken = 'svc-token-1234567890abcdef'
const svcOnline = await jsonOf(await call('/api/admin/online', { headers: { authorization: 'Bearer ' + svcToken } }))
log('服务令牌可访问后台接口', svcOnline.status === 200 && svcOnline.data.ok === true)

const repDevice = 'feedfacecafebeef'
let repLast = null
for (let i = 0; i < 21; i++) {
  repLast = await jsonOf(await call('/api/echocave', {
    method: 'POST',
    headers: { 'x-csh-did': repDevice },
    body: {},
  }))
}
log('设备每分钟超限返回 429', repLast.status === 429 && repLast.data.code === 'csh_device_rate_limited', repLast && repLast.data.error)

const repEvents = await jsonOf(await call('/api/admin/device-events?device=' + repDevice, {
  headers: { authorization: 'Bearer ' + svcToken },
}))
log('设备事件日志可回溯', repEvents.status === 200 && Array.isArray(repEvents.data.events) &&
  repEvents.data.events.some((e) => e.kind === 'rate_limited'))

const badLogin = await jsonOf(await call('/api/admin/login', { method: 'POST', body: { user: 'admin', pass: 'nope' } }))
log('错误密码 401', badLogin.status === 401)

const goodLogin = await call('/api/admin/login', { method: 'POST', body: { user: 'admin', pass: 'pw-123456' } })
const setCookie = goodLogin.headers.get('set-cookie') || ''
cookie = setCookie.split(';')[0]
const loginBody = await jsonOf(goodLogin)
log('正确密码登录成功', goodLogin.status === 200 && loginBody.data.ok === true, setCookie.slice(0, 60))
log('Cookie 带 HttpOnly/Secure/SameSite', /HttpOnly/.test(setCookie) && /Secure/.test(setCookie) && /SameSite=Strict/.test(setCookie))

const sess = await jsonOf(await call('/api/admin/session', { headers: { cookie } }))
log('带 Cookie 取到会话', sess.status === 200 && sess.data.user === 'admin')

const crossSite = await jsonOf(await call('/api/admin/codes', {
  method: 'POST',
  headers: { cookie, origin: 'https://evil.test', 'sec-fetch-site': 'cross-site' },
  body: { count: 1 },
}))
log('跨站提交被拒', crossSite.status === 403)

const issued = await jsonOf(await call('/api/admin/codes', { method: 'POST', headers: { cookie }, body: { count: 2, note: '烟测' } }))
log('批量签发 2 个', issued.status === 200 && issued.data.codes?.length === 2, issued.data.codes?.[0]?.code)

const code = issued.data.codes?.[0]?.code
const serial = issued.data.codes?.[0]?.serial

const device = 'a1b2c3d4e5f60708'
const act = await jsonOf(await call('/api/license/activate', { method: 'POST', body: { code, device, version: '1.2.0', build: 'test' } }))
log('激活码可兑换令牌', act.status === 200 && !!act.data.token)

// 预置一台后台上线前激活的老设备（只有 lic:d: 记录，无索引），验证回填
const legacyDevice = '0legacy00000000a'
await store.set('lic:d:' + legacyDevice, JSON.stringify({
  at: Date.now() - 30 * 86400e3, tail: 'OLD9', serial: 77, build: 'dv1.1.0', ver: '1.1.0',
  _exp: Date.now() + 300 * 86400e3,
}))

const devices = await jsonOf(await call('/api/admin/devices', { headers: { cookie } }))
log('设备出现在后台列表', devices.status === 200 && devices.data.devices?.some((d) => d.d === device))
log('存量老设备被回填', devices.data.devices?.some((d) => d.d === legacyDevice && d.tail === 'OLD9'))

const devicesAgain = await jsonOf(await call('/api/admin/devices', { headers: { cookie } }))
log('回填只跑一次且不产生重复', devicesAgain.data.backfilled === true &&
  devicesAgain.data.devices.filter((d) => d.d === legacyDevice).length === 1)

// 设备触点：未激活的客户端只要带设备码请求就会被登记
const fresh = 'aa11bb22cc33dd44'
await call('/api/mirror-sign?url=https://github.com/x/y/releases/download/v1/tag', {
  headers: { 'x-csh-did': fresh, 'x-csh-build': 'dv1.2.0-insider1.6', 'x-csh-ver': '1.2.0' },
})
await flush()
const touched = JSON.parse(await store.get('lic:d:' + fresh))
log('未激活设备请求即被登记', !!touched && touched.tail === '' && touched.build === 'dv1.2.0-insider1.6' && touched.ver === '1.2.0')

// 节流：6 小时内重复请求不重写，也不覆盖已有构建号
await call('/api/mirror-sign?url=https://github.com/x/y/releases/download/v1/tag', {
  headers: { 'x-csh-did': fresh, 'x-csh-build': 'dv9.9.9' },
})
await flush()
const untouched = JSON.parse(await store.get('lic:d:' + fresh))
log('触点在节流窗口内不重复写', untouched.build === 'dv1.2.0-insider1.6')

// 窗口外刷新时间戳，但保留既有 tail/serial/构建号
touched.at = Date.now() - 7 * 3600e3
await store.set('lic:d:' + fresh, JSON.stringify(touched))
await call('/api/mirror-sign?url=https://github.com/x/y/releases/download/v1/tag', { headers: { 'x-csh-did': fresh } })
await flush()
const refreshed = JSON.parse(await store.get('lic:d:' + fresh))
log('节流窗口外仅刷新时间戳', Math.abs(refreshed.at - Date.now()) < 60e3 && refreshed.build === 'dv1.2.0-insider1.6')

// 触点登记的设备出现在后台列表（tail 为空表示从未激活）
const devicesTouched = await jsonOf(await call('/api/admin/devices', { headers: { cookie } }))
log('触点设备进入后台列表', devicesTouched.data.devices?.some((d) => d.d === fresh))

const codesAfter = await jsonOf(await call('/api/admin/codes', { headers: { cookie } }))
const rec = codesAfter.data.codes?.find((c) => c.s === serial)
log('签发记录标记为已使用', !!rec && rec.u === device && rec.n === 1)

const revokeUsed = await jsonOf(await call('/api/admin/code-revoke', { method: 'POST', headers: { cookie }, body: { serial } }))
log('已使用的码拒绝吊销', revokeUsed.status === 409)

const ban = await jsonOf(await call('/api/admin/ban', { method: 'POST', headers: { cookie }, body: { device, hours: 24, reason: '烟测封禁' } }))
log('封禁设备', ban.status === 200 && ban.data.until > Date.now())

const actBanned = await jsonOf(await call('/api/license/activate', { method: 'POST', body: { code: issued.data.codes[1].code, device } }))
log('被封禁设备无法激活', actBanned.status === 429 && actBanned.data.code === 'csh_device_banned', actBanned.data.error)

const gated = await jsonOf(await call('/api/echocave', { method: 'POST', headers: { 'x-csh-device': device }, body: {} }))
log('被封禁设备请求受保护接口被拒', gated.status === 429 && gated.data.code === 'csh_device_banned')

const unban = await jsonOf(await call('/api/admin/unban', { method: 'POST', headers: { cookie }, body: { device } }))
log('解封设备', unban.status === 200)
const actAfter = await jsonOf(await call('/api/license/activate', { method: 'POST', body: { code: issued.data.codes[1].code, device } }))
log('解封后可再次激活', actAfter.status === 200 && !!actAfter.data.token)

const revoking = await jsonOf(await call('/api/admin/codes', { method: 'POST', headers: { cookie }, body: { count: 1, note: '吊销测试' } }))
const freshCode = revoking.data.codes[0]
const revokedCode = await jsonOf(await call('/api/admin/code-revoke', { method: 'POST', headers: { cookie }, body: { serial: freshCode.serial } }))
const actRevoked = await jsonOf(await call('/api/license/activate', { method: 'POST', body: { code: freshCode.code, device: 'ffffffffffffffff' } }))
log('吊销后的码无法激活', revokedCode.status === 200 && actRevoked.status === 403, actRevoked.data.error)

// ── 在线喊话：客户端心跳 → 后台在线列表 → 投递 ─────────────────────────
const pairCode = '618204'
const onlineDev = 'cccc111122223333'
const otherDev = 'dddd444455556666'

const beat = await jsonOf(await call(
  `/api/announce/poll?deviceId=${onlineDev}&pairCode=${pairCode}&name=${encodeURIComponent('第三机房-01')}`,
))
log('客户端轮询注册成功', beat.status === 204 || beat.status === 200, 'status=' + beat.status)

const onlineList = await jsonOf(await call('/api/admin/online', { headers: { cookie } }))
const onlineHit = (onlineList.data.online || []).find((d) => d.d === onlineDev)
log('在线设备出现在后台', onlineList.status === 200 && !!onlineHit && onlineHit.pair === pairCode, onlineHit?.name)

// 同组第二台设备在线（用于验证 targets 只投给选中设备）
await call(`/api/announce/poll?deviceId=${otherDev}&pairCode=${pairCode}&name=other`)

const shout = await jsonOf(await call('/api/admin/shout', {
  method: 'POST',
  headers: { cookie },
  body: { text: '下课铃响前把作业交到讲台', duration: 30, targets: [onlineDev] },
}))
log('定向喊话送达 1 台', shout.status === 200 && shout.data.delivered === 1, JSON.stringify(shout.data.failed || []))

const got = await jsonOf(await call(`/api/announce/poll?deviceId=${onlineDev}&pairCode=${pairCode}`))
log('目标设备收到喊话', got.status === 200 && got.data.text === '下课铃响前把作业交到讲台', got.data.from)

const gotOther = await call(`/api/announce/poll?deviceId=${otherDev}&pairCode=${pairCode}`)
log('未选中设备不接收', gotOther.status === 204)

const shoutAll = await jsonOf(await call('/api/admin/shout', {
  method: 'POST',
  headers: { cookie },
  body: { text: '全体注意', duration: 10 },
}))
log('不限频连续喊话（全部在线）', shoutAll.status === 200 && shoutAll.data.delivered === 2, 'delivered=' + shoutAll.data.delivered)

const shoutEmpty = await jsonOf(await call('/api/admin/shout', {
  method: 'POST',
  headers: { cookie },
  body: { text: '   ' },
}))
log('空内容被拒绝', shoutEmpty.status === 400)

const onlineNoAuth = await jsonOf(await call('/api/admin/online'))
log('未登录看不到在线设备', onlineNoAuth.status === 401)

// ── 恶意请求初步识别（多因子累计风险分） ──────────────────────────────
const bearer = { authorization: 'Bearer ' + svcToken }
const uaBrowser = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
const uaScan = 'sqlmap/1.7.2#stable (https://sqlmap.org)'
const probeIp = '203.0.113.50'

const riskNoAuth = await jsonOf(await call('/api/admin/risk'))
log('风险清单需要鉴权', riskNoAuth.status === 401)

// 1) 正常请求不应该产生任何风险记录
const normal = await call('/api/announce/poll?deviceId=e0e0e0e0e0e0e0e0&pairCode=700001', {
  headers: { 'x-forwarded-for': '192.0.2.77', 'user-agent': uaBrowser },
})
await flush()
let riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
log('正常请求不进入风险清单', normal.status === 204 && !(riskList.data.items || []).some((x) => x.ip === '192.0.2.77'))

// 2) 只有“探测路径”一个维度 → 中风险，够不上高风险
const probe1 = await call('/api/.env', { headers: { 'x-forwarded-for': probeIp, 'user-agent': uaBrowser } })
await flush()
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const oneShot = (riskList.data.items || []).find((x) => x.ip === probeIp)
log('单一信号只判中风险', probe1.status === 404 && !!oneShot && oneShot.level === 'medium', oneShot && 's=' + oneShot.s)
log('单一信号不会直接定为高风险', !!oneShot && oneShot.s < 60)

// 3) 探测路径 + 扫描器 UA 叠加 → 高风险
await call('/api/.env', { headers: { 'x-forwarded-for': probeIp, 'user-agent': uaScan } })
await flush()
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const multi = (riskList.data.items || []).find((x) => x.ip === probeIp)
log('多因子叠加升级为高风险', !!multi && multi.level === 'high' && multi.reasons.length >= 2,
  multi && multi.reasons.map((r) => r.key).join('+'))

// 4) 已登记设备同样累计，并在设备列表里带出风险等级
const riskDev = '1a2b3c4d5e6f7081'
await store.set('lic:d:' + riskDev, JSON.stringify({
  at: Date.now() - 7 * 3600e3, first: Date.now() - 30 * 86400e3, tail: '', serial: 0,
  _exp: Date.now() + 400 * 86400e3,
}))
await call('/api/.env?from=dev', {
  headers: { 'x-csh-did': riskDev, 'x-forwarded-for': '203.0.113.60', 'user-agent': uaScan },
})
await flush()

const devList = await jsonOf(await call('/api/admin/devices', { headers: bearer }))
const riskRow = (devList.data.devices || []).find((d) => d.d === riskDev)
log('设备列表带出风险等级', !!riskRow && riskRow.risk?.level === 'high' && riskRow.risk.s >= 60,
  riskRow && 's=' + riskRow.risk?.s)

const evDetail = await jsonOf(await call('/api/admin/device-events?device=' + riskDev, { headers: bearer }))
log('设备详情含风险原因与来源 IP', evDetail.status === 200 && evDetail.data.risk?.level === 'high' &&
  evDetail.data.risk.reasons.length >= 2 && !!evDetail.data.ipRisk, evDetail.data.risk?.reasons?.map((r) => r.key).join('+'))

const riskAll = await jsonOf(await call('/api/admin/risk', { headers: bearer }))
log('风险清单同时含设备与 IP 维度', riskAll.status === 200 &&
  riskAll.data.items.some((x) => x.kind === 'd' && x.id === riskDev) &&
  riskAll.data.items.some((x) => x.kind === 'i'))

// 5) 只识别不处置：高风险设备仍可正常调用业务接口
const stillOk = await jsonOf(await call('/api/announce/poll?deviceId=' + riskDev + '&pairCode=700002', {
  headers: { 'x-csh-did': riskDev },
}))
log('高风险不会自动封禁', stillOk.status === 204, 'status=' + stillOk.status)

// 6) 上下文推导：短时间内扫过多个不同路径 → 多路径探测/扫描
const sweepIp = '203.0.113.71'
for (let i = 0; i < 9; i++) {
  await call(`/api/probe-${i}-${Math.random().toString(36).slice(2, 6)}`, {
    headers: { 'x-forwarded-for': sweepIp, 'user-agent': uaBrowser },
  })
}
await flush()
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const sweepRow = (riskList.data.items || []).find((x) => x.ip === sweepIp)
log('多路径扫描被识别', !!sweepRow && sweepRow.reasons.some((r) => r.key === 'path_sweep'),
  sweepRow && sweepRow.reasons.map((r) => r.key).join('+'))

// 7) 注入风格参数独立计分
const injIp = '203.0.113.72'
await call("/api/files?q=1%27%20union%20select%20password%20from%20users", {
  headers: { 'x-forwarded-for': injIp, 'user-agent': uaBrowser },
})
await flush()
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const injRow = (riskList.data.items || []).find((x) => x.ip === injIp)
log('注入风格参数被识别', !!injRow && injRow.reasons.some((r) => r.key === 'sensitive_query'),
  injRow && injRow.reasons.map((r) => r.key).join('+'))

// 8) 后台登录连续失败 → 登录爆破信号（后台路径默认不观测，这里强制计入）
const bruteIp = '203.0.113.73'
for (let i = 0; i < 3; i++) {
  await call('/api/admin/login', {
    method: 'POST',
    headers: { 'x-forwarded-for': bruteIp },
    body: { user: 'admin', pass: 'wrong-' + i },
  })
}
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const bruteRow = (riskList.data.items || []).find((x) => x.ip === bruteIp)
log('后台登录连续失败计入风险', !!bruteRow && bruteRow.reasons.some((r) => r.key === 'auth_brute'),
  bruteRow && bruteRow.reasons.map((r) => r.key).join('+'))

// ── 历史回溯 ──────────────────────────────────────────────────────────
const histIp = '198.51.100.88'
const nowMs = Date.now()
const histEvents = [
  { id: 'h1', ts: nowMs - 3600e3, ip: histIp, path: '/.env', ua: uaScan, method: 'GET', status: 404 },
  { id: 'h2', ts: nowMs - 3000e3, ip: histIp, path: '/wp-login.php', ua: uaScan, method: 'POST', status: 404 },
  { id: 'h3', ts: nowMs - 2400e3, ip: histIp, path: '/../../etc/passwd', ua: '', method: 'GET', status: 400 },
]

const bfNoAuth = await jsonOf(await call('/api/admin/risk/backfill'))
log('历史回溯需要鉴权', bfNoAuth.status === 401)

const statusBefore = await jsonOf(await call('/api/admin/risk/backfill', { headers: bearer }))
const bfDry = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { source: 'events', events: histEvents, dryRun: true },
}))
const statusAfterDry = await jsonOf(await call('/api/admin/risk/backfill', { headers: bearer }))
log('dryRun 不入账', bfDry.status === 200 && bfDry.data.added === 3 &&
  statusAfterDry.data.hist === statusBefore.data.hist, `hist=${statusAfterDry.data.hist}`)

const bf1 = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { source: 'events', events: histEvents },
}))
log('历史可疑请求入账', bf1.status === 200 && bf1.data.added === 3, `added=${bf1.data.added}`)

const bf2 = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { source: 'events', events: histEvents },
}))
log('重复回溯不重复计分', bf2.status === 200 && bf2.data.added === 0 && bf2.data.skipped === 3,
  `added=${bf2.data.added} skipped=${bf2.data.skipped}`)

let histList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const histRow = (histList.data.items || []).find((x) => x.ip === histIp)
log('历史证据进入风险清单', !!histRow && histRow.hs > 0 && (histRow.histReasons || []).length >= 2,
  histRow && `s=${histRow.s} hs=${histRow.hs} ${histRow.histReasons.map((r) => r.key).join('+')}`)
const histScore1 = histRow && histRow.s

// 再次 GET 不应改变历史分
histList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const histRowAgain = (histList.data.items || []).find((x) => x.ip === histIp)
log('重复读取历史分稳定', !!histRowAgain && histRowAgain.s === histScore1)

// 历史 + 实时：取较大值，并标记“历史风险重现”
await call('/api/.env', { headers: { 'x-forwarded-for': histIp, 'user-agent': uaBrowser } })
await flush()
histList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const mixed = (histList.data.items || []).find((x) => x.ip === histIp)
log('历史与实时取较大值不叠加', !!mixed && mixed.s <= 100 && mixed.s >= histScore1 &&
  mixed.reasons.some((r) => r.key === 'repeat_offender'),
  mixed && `s=${mixed.s} ${mixed.reasons.map((r) => r.key).join('+')}`)

// 9) state 源：设备事件日志与封禁记录回溯
const histDev = 'abcdef1234567890'
await store.set('lic:d:' + histDev, JSON.stringify({
  at: Date.now() - 86400e3, first: Date.now() - 30 * 86400e3, tail: '', serial: 0,
  _exp: Date.now() + 400 * 86400e3,
}))
await store.set('lic:ev:' + histDev, JSON.stringify({
  at: Date.now() - 3600e3,
  k: 'rate_limited',
  events: [
    { ts: Date.now() - 7200e3, kind: 'rate_limited', path: '/api/dl-ticket', scope: 'minute', used: 60, limit: 60 },
    { ts: Date.now() - 7100e3, kind: 'banned', path: '/api/oss-sign' },
    { ts: Date.now() - 7000e3, kind: 'request', path: '/.git/config' },
  ],
}))
const stateRun = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { source: 'state', cursor: 0 },
}))
log('设备事件历史回溯', stateRun.status === 200 && stateRun.data.added >= 3, `added=${stateRun.data.added}`)

const devHist = await jsonOf(await call('/api/admin/device-events?device=' + histDev, { headers: bearer }))
log('设备历史证据可见', devHist.status === 200 && devHist.data.risk?.hs > 0 &&
  (devHist.data.risk.histReasons || []).length >= 2,
  devHist.data.risk && `hs=${devHist.data.risk.hs} ${devHist.data.risk.histReasons.map((r) => r.key).join('+')}`)

const stateAgain = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { source: 'state', cursor: 0 },
}))
log('设备事件重复回溯不叠加', stateAgain.status === 200 && stateAgain.data.added === 0,
  `added=${stateAgain.data.added} skipped=${stateAgain.data.skipped}`)

// 10) 重置历史分
const resetRun = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { reset: true, source: 'events' },
}))
log('可重置历史分', resetRun.status === 200 && resetRun.data.reset === true && resetRun.data.summary.hist === 0,
  'hist=' + resetRun.data.summary.hist)

// ── 分面识别：下载 / OSS / 镜像 ────────────────────────────────────────
// 下载面：缺少签名参数 + 外链 Referer + 多段 Range
const dlIp = '198.51.100.210'
await call('/api/dl?k=upload%2Fx.zip&e=1&s=&h=&f=', {
  headers: { 'x-forwarded-for': dlIp, 'user-agent': uaBrowser, referer: 'https://evil.example/page' },
})
await call('/api/icon?k=icon%2Fx.png', {
  headers: {
    'x-forwarded-for': dlIp,
    'user-agent': uaBrowser,
    range: 'bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13,14-15,16-17',
  },
})
await flush()
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const dlRow = (riskList.data.items || []).find((x) => x.ip === dlIp)
log('下载面识别签名探测/外链/多段 Range', !!dlRow &&
  ['dl_probe', 'dl_hotlink', 'dl_range_abuse'].every((k) => dlRow.reasons.some((r) => r.key === k)),
  dlRow && dlRow.reasons.map((r) => r.key).join('+'))

// OSS 面：匿名列举 + 鉴权失败
const ossApiIp = '198.51.100.211'
await call('/api/files?source=bucket&prefix=soft%2F', {
  headers: { 'x-forwarded-for': ossApiIp, 'user-agent': uaBrowser },
})
await flush()
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const ossRow = (riskList.data.items || []).find((x) => x.ip === ossApiIp)
log('OSS 面识别列举与鉴权失败', !!ossRow &&
  ['oss_list', 'oss_auth_fail'].every((k) => ossRow.reasons.some((r) => r.key === k)),
  ossRow && ossRow.reasons.map((r) => r.key).join('+'))

// 镜像面：目标指向内网/非 GitHub 主机
const mirIp = '198.51.100.212'
await call('/api/mirror-sign?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F', {
  headers: { 'x-forwarded-for': mirIp, 'user-agent': uaBrowser },
})
await flush()
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const mirRow = (riskList.data.items || []).find((x) => x.ip === mirIp)
log('镜像面识别内网目标与仓库探测', !!mirRow &&
  ['mirror_path', 'mirror_repo_probe'].every((k) => mirRow.reasons.some((r) => r.key === k)),
  mirRow && mirRow.reasons.map((r) => r.key).join('+'))

// ── 服务器侧事件：SSH / OSS 洪峰 / 下载 / 镜像 ──────────────────────────
const sshIp = '198.51.100.220'
const sshEvents = [
  { ts: nowMs - 30e3, ip: sshIp, src: 'ssh', user: 'root', op: 'password', result: 'failed', n: 12 },
  { ts: nowMs - 25e3, ip: sshIp, src: 'ssh', user: 'admin', op: 'password', result: 'invalid', n: 3 },
  { ts: nowMs - 20e3, ip: sshIp, src: 'ssh', user: 'root', op: 'publickey', result: 'accepted', n: 1 },
]
const sshRun = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { source: 'ssh', events: sshEvents },
}))
log('SSH 事件回溯入账', sshRun.status === 200 && sshRun.data.source === 'ssh' && sshRun.data.added === 3,
  `added=${sshRun.data.added}`)
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const sshRow = (riskList.data.items || []).find((x) => x.ip === sshIp)
log('SSH 爆破/非法用户/root/成功登录均可识别', !!sshRow &&
  ['ssh_brute', 'ssh_invalid_user', 'ssh_root_attempt', 'ssh_accepted'].every((k) =>
    sshRow.histReasons.some((r) => r.key === k)),
  sshRow && sshRow.histReasons.map((r) => r.key).join('+'))
const sshAgain = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST', headers: bearer, body: { source: 'ssh', events: sshEvents },
}))
log('SSH 事件重复回溯不叠加', sshAgain.status === 200 && sshAgain.data.added === 0 && sshAgain.data.skipped === 3,
  `added=${sshAgain.data.added} skipped=${sshAgain.data.skipped}`)

const sshBurstIp = '198.51.100.221'
const sshBurst = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST',
  headers: bearer,
  body: {
    source: 'ssh',
    events: [
      { ts: nowMs - 15e3, ip: sshBurstIp, src: 'ssh', user: 'oracle', op: 'password', result: 'failed', n: 30 },
      { ts: nowMs - 10e3, ip: sshBurstIp, src: 'ssh', user: 'ubuntu', op: 'password', result: 'failed', n: 25 },
    ],
  },
}))
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const sshBurstRow = (riskList.data.items || []).find((x) => x.ip === sshBurstIp)
log('SSH 高频爆破合成为洪峰信号', sshBurst.status === 200 && sshBurst.data.added === 3 &&
  !!sshBurstRow && sshBurstRow.histReasons.some((r) => r.key === 'ssh_brute'),
  `added=${sshBurst.data.added}`)

const ossEvtIp = '198.51.100.222'
const ossRun = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST',
  headers: bearer,
  body: {
    source: 'oss',
    events: [
      { ts: nowMs - 120e3, ip: ossEvtIp, src: 'oss', method: 'GET', status: 403, op: 'list', path: '/bucket?list-type=2&prefix=soft/', n: 80 },
      { ts: nowMs - 60e3, ip: ossEvtIp, src: 'oss', method: 'GET', status: 403, op: 'list', path: '/bucket?list-type=2&prefix=soft/', n: 80 },
      { ts: nowMs - 30e3, ip: ossEvtIp, src: 'oss', method: 'DELETE', status: 403, op: 'delete', path: '/bucket/soft/a.zip', n: 80 },
    ],
  },
}))
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const ossEvtRow = (riskList.data.items || []).find((x) => x.ip === ossEvtIp)
log('OSS 事件识别高频鉴权失败/列举/删除', ossRun.status === 200 && ossRun.data.added === 4 &&
  !!ossEvtRow && ['oss_auth_fail', 'oss_burst', 'oss_list', 'oss_delete'].every((k) =>
    ossEvtRow.histReasons.some((r) => r.key === k)),
  ossEvtRow && ossEvtRow.histReasons.map((r) => r.key).join('+'))

const dlEvtIp = '198.51.100.223'
const dlEvt = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST',
  headers: bearer,
  body: {
    source: 'download',
    events: [
      { ts: nowMs - 30e3, ip: dlEvtIp, src: 'download', method: 'GET', status: 403, path: '/dl/a.zip', n: 1 },
      { ts: nowMs - 20e3, ip: dlEvtIp, src: 'download', method: 'GET', status: 200, op: 'hotlink', path: '/dl/b.zip', n: 1 },
    ],
  },
}))
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const dlEvtRow = (riskList.data.items || []).find((x) => x.ip === dlEvtIp)
log('下载服务事件识别签名失败/盗链', dlEvt.status === 200 && dlEvt.data.added === 2 && !!dlEvtRow &&
  ['dl_sign_fail', 'dl_hotlink'].every((k) => dlEvtRow.histReasons.some((r) => r.key === k)),
  dlEvtRow && dlEvtRow.histReasons.map((r) => r.key).join('+'))

const mirEvtIp = '198.51.100.224'
const mirEvt = await jsonOf(await call('/api/admin/risk/backfill', {
  method: 'POST',
  headers: bearer,
  body: {
    source: 'mirror',
    events: [
      { ts: nowMs - 30e3, ip: mirEvtIp, src: 'mirror', method: 'GET', status: 404, path: '/a/b/../../etc/passwd', n: 1 },
    ],
  },
}))
riskList = await jsonOf(await call('/api/admin/risk?kind=i', { headers: bearer }))
const mirEvtRow = (riskList.data.items || []).find((x) => x.ip === mirEvtIp)
log('镜像服务事件识别路径穿越', mirEvt.status === 200 && mirEvt.data.added === 1 && !!mirEvtRow &&
  mirEvtRow.histReasons.some((r) => r.key === 'mirror_path'),
  mirEvtRow && mirEvtRow.histReasons.map((r) => r.key).join('+'))

const bfStatus = await jsonOf(await call('/api/admin/risk/backfill', { headers: bearer }))
log('回溯状态按来源记录', !!bfStatus.data.marker && bfStatus.data.marker.servers &&
  ['ssh', 'oss', 'download', 'mirror'].every((k) => bfStatus.data.marker.servers[k]))


// ── 安全回归 ──────────────────────────────────────────────────────────
// 1) 伪造 XFF 首段不能绕过登录锁定：限流取可信头 / XFF 末段
for (let i = 0; i < 10; i++) {
  await call('/api/admin/login', {
    method: 'POST',
    headers: { 'x-forwarded-for': `10.9.9.${i}, 203.0.113.9` },
    body: { user: 'admin', pass: 'wrong-' + i },
  })
}
const locked = await jsonOf(await call('/api/admin/login', {
  method: 'POST',
  headers: { 'x-forwarded-for': '172.16.0.1, 203.0.113.9' },
  body: { user: 'admin', pass: 'wrong-again' },
}))
log('伪造 XFF 首段仍被锁定', locked.status === 429)

// 2) 触点只接受 16–64 位十六进制设备码，随机字符串不写入存储
const before = store.size
await call('/api/mirror-sign?url=https://github.com/x/y/releases/download/v1/tag', {
  headers: { 'x-csh-did': 'not-a-real-device-id' },
})
await flush()
log('非法设备码不写存储', store.size === before)

// 3) 每来源每日新设备配额 500 台，超限后不再新增记录
const regDay = new Date().toISOString().slice(0, 10)
const ipHash = (await sha256HexLocal('198.51.100.7')).slice(0, 24)
const regKey = 'lic:reg:' + ipHash + ':' + regDay
await store.set(regKey, JSON.stringify({ n: 500 }))
await call('/api/mirror-sign?url=https://github.com/x/y/releases/download/v1/tag', {
  headers: { 'x-csh-did': 'eeee111122223333', 'x-forwarded-for': '198.51.100.7' },
})
await flush()
// 设备信誉计数（lic:rep / lic:ev）属于另一套机制，这里只断言“设备登记”没发生。
const regAfter = JSON.parse(await store.get(regKey))
log('新设备配额用尽后不再登记', regAfter.n === 500 &&
  ![...store.keys()].includes('lic:d:eeee111122223333'))

// 4) 单个配对码在线设备上限，防止随机设备码撑大注册表
let full = 0
for (let i = 0; i < 130; i++) {
  const dev = i.toString(16).padStart(16, '0')
  const r = await jsonOf(await call(`/api/announce/poll?deviceId=${dev}&pairCode=777001`))
  if (r.status === 429) full += 1
}
log('配对码在线设备数有上限', full >= 1, 'rejected=' + full)

// 5) 激活接口拒绝畸形设备码
const badAct = await jsonOf(await call('/api/license/activate', {
  method: 'POST', body: { code: issued.data.codes[1].code, device: '../../etc/passwd' },
}))
log('激活接口校验设备码格式', badAct.status === 400)

// 6) 删除接口的令牌比较改为定长比较（行为不变：错令牌仍 401）
const badPurge = await jsonOf(await call('/api/purge', {
  method: 'POST', headers: { 'x-purge-token': 'wrong-token' }, body: { key: 'upload/x.zip' },
}))
log('错 purge 令牌被拒', badPurge.status === 401)

const noCookie = await jsonOf(await call('/api/admin/codes'))
log('无 Cookie 拿不到签发记录', noCookie.status === 401)

// 未配置密码时必须明确报错，而不是允许空密码登录
const noPass = await jsonOf(await onRequest({
  request: new Request('https://api.test/api/admin/login', {
    method: 'POST',
    headers: { origin: 'https://api.test', 'sec-fetch-site': 'same-origin' },
    body: JSON.stringify({ user: 'admin', pass: '' }),
  }),
  env: Object.assign({}, env, { CSH_ADMIN_PASS: '', CSH_ADMIN_PASS_SHA256: '' }),
  waitUntil() {},
}))
log('未配置后台密码时拒绝登录', noPass.status === 503 && noPass.data.error === '后台未配置')

const adminHtml = await adminPage().text()
log('后台页面可渲染', adminHtml.includes('管理后台') && adminHtml.includes('/api/admin'))
log('后台页面含参数设置与日志', adminHtml.includes('参数设置') && adminHtml.includes('操作日志'))

// ── 参数设置 ──────────────────────────────────────────────────────────
const setAnon = await jsonOf(await call('/api/admin/settings'))
log('未登录读不到参数', setAnon.status === 401)

const setGet = await jsonOf(await call('/api/admin/settings', { headers: { cookie } }))
const groupIds = (setGet.data.groups || []).map((g) => g.id)
const fieldCount = (setGet.data.groups || []).reduce((n, g) => n + g.fields.length, 0)
log('参数分组齐全', setGet.status === 200 && groupIds.includes('download') &&
  groupIds.includes('license') && groupIds.includes('admin') && fieldCount >= 20, 'fields=' + fieldCount)

const repGroup = (setGet.data.groups || []).find((g) => g.id === 'reputation')
log('设备信誉档位可调', !!repGroup && repGroup.fields.length === 14 &&
  repGroup.fields.some((f) => f.key === 'repDlTicketMin' && f.value === 60))

const dlField = setGet.data.groups.flatMap((g) => g.fields).find((f) => f.key === 'dlDailyLimit')
log('参数带默认值与当前值', dlField && dlField.value === 25 && dlField.def === 25 && dlField.overridden === false)

const badRange = await jsonOf(await call('/api/admin/settings', {
  method: 'POST', headers: { cookie },
  body: { patch: { dlDailyLimit: -5 } },
}))
log('越界值被拒并说明原因', badRange.status === 400 && !!badRange.data.errors.dlDailyLimit)

const unknownKey = await jsonOf(await call('/api/admin/settings', {
  method: 'POST', headers: { cookie },
  body: { patch: { notARealKey: 1 } },
}))
log('未知参数被拒', unknownKey.status === 400 && unknownKey.data.errors.notARealKey === '未知参数')

const saved = await jsonOf(await call('/api/admin/settings', {
  method: 'POST', headers: { cookie },
  body: { patch: { dlDailyLimit: 3, annPairDeviceMax: 2, licEnforceAt: '2027-01-01T00:00:00Z' } },
}))
log('批量保存参数', saved.status === 200 && saved.data.changed === 3)

const setAfter = await jsonOf(await call('/api/admin/settings', { headers: { cookie } }))
const afterMap = {}
setAfter.data.groups.forEach((g) => g.fields.forEach((f) => { afterMap[f.key] = f }))
log('保存后读到新值并标记已改', afterMap.dlDailyLimit.value === 3 && afterMap.dlDailyLimit.overridden === true)
log('时间参数被规范成 ISO', afterMap.licEnforceAt.value === '2027-01-01T00:00:00.000Z', afterMap.licEnforceAt.value)

// 生效性：配对码在线设备上限改成 2 后，第三台应当被拒
const pair = '881122'
const p1 = await jsonOf(await call(`/api/announce/poll?deviceId=aaaa000011112222&pairCode=${pair}`))
const p2 = await jsonOf(await call(`/api/announce/poll?deviceId=bbbb000011112222&pairCode=${pair}`))
const p3 = await jsonOf(await call(`/api/announce/poll?deviceId=cccc000011112222&pairCode=${pair}`))
log('改动的上限立刻生效', p1.status < 300 && p2.status < 300 && p3.status === 429, 'p1=' + p1.status + ' p2=' + p2.status + ' p3=' + p3.status)

// 缓存失效：保存时已经作废进程内缓存，这里确认读到的是新值而不是 15 秒前的旧值
const afterSave = await jsonOf(await call('/api/admin/settings', { headers: { cookie } }))
const freshField = afterSave.data.groups.flatMap((g) => g.fields).find((f) => f.key === 'annPairDeviceMax')
log('保存后缓存立即失效', freshField.value === 2)

const resetOne = await jsonOf(await call('/api/admin/settings', {
  method: 'POST', headers: { cookie },
  body: { reset: ['annPairDeviceMax'] },
}))
log('单项还原', resetOne.status === 200 && resetOne.data.changed === 1)

const resetAll = await jsonOf(await call('/api/admin/settings', {
  method: 'POST', headers: { cookie },
  body: { reset: true },
}))
const backToDef = await jsonOf(await call('/api/admin/settings', { headers: { cookie } }))
const backField = backToDef.data.groups.flatMap((g) => g.fields).find((f) => f.key === 'dlDailyLimit')
log('全部还原出厂值', resetAll.status === 200 && backField.value === 25 && backField.overridden === false)

// 跨站提交仍然拒绝
const crossSave = await jsonOf(await call('/api/admin/settings', {
  method: 'POST', headers: { cookie, origin: 'https://evil.test', 'sec-fetch-site': 'cross-site' },
  body: { patch: { dlDailyLimit: 99 } },
}))
log('跨站改参数被拒', crossSave.status === 403)

// 生效性：设备信誉档位（每分钟 1 次）改动后按设备码计数
await call('/api/admin/settings', {
  method: 'POST', headers: { cookie }, body: { patch: { repMirrorSignMin: 1 } },
})
const repDev = 'abcd000011112222'
const repCall = () => call('/api/mirror-sign?url=https://github.com/x/y/releases/download/v1/tag', {
  headers: { 'x-csh-did': repDev },
})
const rep1 = await jsonOf(await repCall())
const rep2 = await jsonOf(await repCall())
log('设备信誉限速按设置生效',
  rep1.data.code !== 'csh_device_rate_limited' && rep2.status === 429 &&
  rep2.data.code === 'csh_device_rate_limited',
  'first=' + rep1.status + ' second=' + rep2.status)
await call('/api/admin/settings', {
  method: 'POST', headers: { cookie }, body: { reset: ['repMirrorSignMin'] },
})

// ── 操作日志 ──────────────────────────────────────────────────────────
const audit = await jsonOf(await call('/api/admin/audit', { headers: { cookie } }))
const acts = (audit.data.audit || []).map((a) => a.act)
log('操作日志记录了签发/封禁/参数', audit.status === 200 &&
  acts.includes('settings') && acts.includes('code-issue') && acts.includes('ban'), acts.join(',').slice(0, 80))
log('日志带操作者', (audit.data.audit || []).every((a) => !!a.by))
log('未登录读不到日志', (await jsonOf(await call('/api/admin/audit'))).status === 401)
