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
