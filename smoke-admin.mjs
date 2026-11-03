// 本地烟测：用内存 KV 跑通「登录 → 签发 → 激活 → 封禁」全链路。
// 仅用于开发期验证，不参与部署。
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
}

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
log('被封禁设备无法激活', actBanned.status === 403 && actBanned.data.code === 'csh_device_banned', actBanned.data.error)

const gated = await jsonOf(await call('/api/echocave', { method: 'POST', headers: { 'x-csh-device': device }, body: {} }))
log('被封禁设备请求受保护接口被拒', gated.status === 403 && gated.data.code === 'csh_device_banned')

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
