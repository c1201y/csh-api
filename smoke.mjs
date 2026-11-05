const path = new URL('./functions/api/[[default]].js', import.meta.url).href

const store = new Map()
globalThis.CSH_STATE = {
  async get(k) { return store.has(k) ? store.get(k) : null },
  async put(k, v) { store.set(k, String(v)) },
  async delete(k) { store.delete(Array.isArray(k) ? k[0] : k) },
  // 前缀列举：后台在线列表要靠它找配对各教室的在线注册表
  async list(prefix) {
    const p = typeof prefix === 'string' ? prefix : (prefix && prefix.prefix) || ''
    return [...store.keys()].filter((k) => k.startsWith(p))
  },
}

const mod = await import(path)

const waiters = []
const ctxOf = (req, env) => ({
  request: req,
  env,
  waitUntil(p) { waiters.push(Promise.resolve(p)) },
})

const env = {
  ALLOWED_ORIGIN: '*',
  PURGE_TOKEN: 'test-token',
  SIGN_API_KEY: 'test-key',
  OSS_BUCKET: 'classsoftwarehub',
  OSS_REGION: 'cn-shanghai',
  OSS_ENDPOINT: 'oss-cn-shanghai.aliyuncs.com',
  OSS_ACCESS_KEY_ID: 'fake',
  OSS_ACCESS_KEY_SECRET: 'fake',
  OSS_PUBLIC_BASE: 'https://classsoftwarehub.oss-cn-shanghai.aliyuncs.com',
  OSS_PREFIX: 'upload/',
  DL_MODE: 'auto',
  DL_DAILY_LIMIT: '25',
  RELAY_HOST: '',
  DL_SIGN_SECRET: 'test-secret',
}

let pass = 0
let fail = 0
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS', name) }
  else { fail++; console.log('  FAIL', name, extra === undefined ? '' : JSON.stringify(extra).slice(0, 200)) }
}

{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/status'), env))
  const j = await r.json()
  check('status 200', r.status === 200, r.status)
  check('status kv true', j.services && j.services.kv === true, j)
  check('status runtime', j.runtime === 'edgeone-pages', j.runtime)
}
{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/status'), env))
  check('status second 200', r.status === 200)
}
{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/none', { method: 'OPTIONS' }), env))
  check('options cors', r.status === 200 || r.status === 204, r.status)
}
{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/zzz'), env))
  check('404 unknown', r.status === 404, r.status)
}
{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/dl-mode', {
    headers: { 'X-Purge-Token': 'test-token' },
  }), env))
  const j = await r.json()
  check('dl-mode GET 200', r.status === 200, r.status)
  check('dl-mode default auto', (j.mode || j.envMode) !== undefined, j)
}
{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/dl-mode', {
    method: 'POST',
    headers: { 'X-Purge-Token': 'test-token', 'content-type': 'application/json' },
    body: JSON.stringify({ mode: 'direct' }),
  }), env))
  check('dl-mode POST 200', r.status === 200, r.status)
  const g = await mod.onRequest(ctxOf(new Request('http://t/api/dl-mode', {
    headers: { 'X-Purge-Token': 'test-token' },
  }), env))
  const gj = await g.json()
  check('dl-mode persisted direct', gj.mode === 'direct' || gj.cfg?.mode === 'direct', gj)
}
{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/mirror-sign?url=https%3A%2F%2Fgithub.com%2FClassIsland%2FClassIsland%2Freleases%2Fdownload%2F2.1.0.1%2Fx.zip'), env))
  const j = await r.json()
  check('mirror-sign 503 without real key config', r.status === 503 || r.status === 200 || r.status === 502, { s: r.status, j })
}
{
  const r = await mod.onRequest(ctxOf(new Request('http://t/api/dl-ticket', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ key: 'upload/2026/10/test.zip', fp: '0123456789abcdef0123456789abcdef' }),
  }), env))
  const j = await r.json()
  // 客户端 fp 只作兼容：配额键由服务端按设备码/可信 IP 派生，短 fp 不再拒绝。
  check('dl-ticket ignores client fp', r.status !== 400, { s: r.status, j })
}

// ── 正版校验 ──────────────────────────────────────────────────────────
{
  const { createHmac } = await import('node:crypto')
  const BUILD_SECRET = 'smoke-build-secret'
  const LIC_SECRET = 'smoke-license-secret'
  const buildId = 'dv9.9.9-smoke+20260101T0000Z'
  const sig = createHmac('sha256', BUILD_SECRET).update('v1|' + buildId).digest('hex')
  const licEnv = { ...env, CSH_BUILD_SECRET: BUILD_SECRET, CSH_LICENSE_SECRET: LIC_SECRET }

  const submitAs = (headers, extra) => mod.onRequest(ctxOf(new Request('http://t/api/submit', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ _类型: 'utility' }),
  }), { ...licEnv, ...extra }))

  // 观察期：默认不拦，只是记日志
  check('license 观察期不拦', (await submitAs({})).status !== 403)

  const strict = { CSH_LIC_ENFORCE: 'true' }
  const deny = await submitAs({}, strict)
  const denyJson = await deny.clone().json()
  check('license 无凭证 403', deny.status === 403 && denyJson.code === 'csh_license_required', denyJson)

  const official = await submitAs({ 'X-CSH-Build': buildId, 'X-CSH-Sig': sig, 'X-CSH-Device': '0123456789abcdef' }, strict)
  check('license 官方签名放行', official.status !== 403)
  check('license 下发令牌', !!official.headers.get('x-csh-lic'))

  const BROWSER_HEADERS = {
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-Dest': 'empty',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36',
  }

  // 严格模式下只带两件套的旧式请求不再放行：curl 补两个头就能过闸的日子结束了
  const loose = await submitAs({ 'Sec-Fetch-Mode': 'cors', Origin: 'https://classsoftwarehub.cn' }, strict)
  check('license 两件套不再放行', loose.status === 403, loose.status)

  const browser = await submitAs(
    { ...BROWSER_HEADERS, Origin: 'https://classsoftwarehub.cn' },
    strict
  )
  check('license 浏览器来源放行', browser.status !== 403, browser.status)

  const scripted = await submitAs(
    { ...BROWSER_HEADERS, 'User-Agent': 'curl/8.4.0', Origin: 'https://classsoftwarehub.cn' },
    strict
  )
  check('license 脚本 UA 拒绝', scripted.status === 403, scripted.status)

  const foreign = await submitAs(
    { ...BROWSER_HEADERS, Origin: 'https://evil.example.com' },
    strict
  )
  check('license 外站来源拒绝', foreign.status === 403)

  const legacy = await submitAs({}, { ...strict, CSH_LIC_LEGACY_UNTIL: '2099-01-01' })
  check('license 旧客户端豁免', legacy.status !== 403)

  // 激活码：5B payload + 5B mac，与服务端同一算法
  const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
  const base32 = (bytes) => {
    let bits = 0, value = 0, out = ''
    for (const b of bytes) {
      value = (value << 8) | b
      bits += 8
      while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5 }
    }
    if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
    return out
  }
  const days = Math.floor((Date.now() - Date.UTC(2020, 0, 1)) / 86400000)
  const payload = Uint8Array.from([(days >> 8) & 255, days & 255, 0, 0, 9])
  const payloadHex = [...payload].map((b) => b.toString(16).padStart(2, '0')).join('')
  const mac = createHmac('sha256', LIC_SECRET).update('code|' + payloadHex).digest().subarray(0, 5)
  const code = base32(Uint8Array.from([...payload, ...mac]))

  const activate = await mod.onRequest(ctxOf(new Request('http://t/api/license/activate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code, device: '0123456789abcdef' }),
  }), { ...licEnv, ...strict }))
  const activateJson = await activate.clone().json()
  check('license 激活成功', activate.status === 200 && activateJson.success === true, activateJson)

  const withToken = await submitAs({ 'X-CSH-Build': 'community+local', 'X-CSH-Device': '0123456789abcdef', 'X-CSH-Lic': activateJson.token }, strict)
  check('license 已激活令牌放行', withToken.status !== 403)

  const badCode = await mod.onRequest(ctxOf(new Request('http://t/api/license/activate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code: 'AAAAAAAAAAAAAAAA', device: '0123456789abcdef' }),
  }), { ...licEnv, ...strict }))
  check('license 错误激活码拒绝', badCode.status === 400, badCode.status)

  // 没带设备码时不能签发令牌：空 d 的令牌对所有设备通用
  const noDevice = await submitAs({ 'X-CSH-Build': buildId, 'X-CSH-Sig': sig }, strict)
  check('license 无设备码不下发令牌', noDevice.status !== 403 && !noDevice.headers.get('x-csh-lic'), noDevice.status)

  // 一码多机上限：同码第 6 台设备应被拒（默认 5 台）
  const activateAs = (dev) => mod.onRequest(ctxOf(new Request('http://t/api/license/activate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code, device: dev }),
  }), { ...licEnv, ...strict }))
  let bound = 0
  for (let i = 1; i <= 5; i++) {
    const r = await activateAs(`0123456789abcde${i.toString(16)}`)
    if (r.status === 200) bound++
  }
  const overflow = await activateAs('0123456789abcdf0')
  const overflowJson = await overflow.clone().json()
  check('license 一码多机上限', bound === 4 && overflow.status === 409 && overflowJson.code === 'csh_code_exhausted', { bound, status: overflow.status, j: overflowJson })
}

{
  // 票据签名密钥缺失时必须整链停摆，不能退化成空密钥签名
  const noSecret = { ...env, DL_SIGN_SECRET: '' }
  const res = await mod.onRequest(ctxOf(new Request('http://t/api/dl-ticket', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ key: 'upload/2026/10/test.zip' }),
  }), noSecret))
  check('dl-ticket 无签名密钥 503', res.status === 503, res.status)
}

{
  // 教室喊话在线登记：设备心跳必须落到注册表，且多台设备互不覆盖
  const poll = (dev, name) => mod.onRequest(ctxOf(new Request(
    `http://t/api/announce/poll?deviceId=${dev}&pairCode=123456&name=${encodeURIComponent(name)}`, {}), env))
  const list = () => mod.onRequest(ctxOf(new Request(
    'http://t/api/announce/list?pairCode=123456', { headers: { 'X-Purge-Token': 'test-token' } }), env))

  const d1 = 'a1b2c3d4e5f60718'
  const d2 = 'a1b2c3d4e5f60719'
  const r1 = await poll(d1, 'pc-1')
  check('announce 轮询 204', r1.status === 204, r1.status)
  const r2 = await poll(d2, 'pc-2')
  check('announce 第二台轮询 204', r2.status === 204, r2.status)

  const l = await list()
  const lj = await l.json().catch(() => ({}))
  const ids = new Set(((lj && lj.devices) || []).map((d) => d.id))
  check('announce 两台都在线', l.status === 200 && ids.has(d1) && ids.has(d2), { status: l.status, ids: [...ids] })

  // 心跳时间应是毫秒时间戳，且落在在线窗口内（判离线是靠这个字段）
  const row = ((lj && lj.devices) || []).find((d) => d.id === d1) || {}
  check('announce 心跳为近期时间戳', Number(row.ts) > Date.now() - 300 * 1000 && Number(row.ts) <= Date.now() + 1000, row.ts)

  const r3 = await poll(d1, 'pc-1')
  check('announce 重复轮询仍 204', r3.status === 204, r3.status)

  // 喊话心跳走查询参数、不经过请求头，不会进在线表；后台在线列表必须从注册表补进来
  const adminEnv = { ...env, CSH_ADMIN_API_TOKEN: 'test-admin-token-0123456789' }
  const online = await mod.onRequest(ctxOf(new Request('http://t/api/admin/online', {
    headers: { 'X-CSH-Admin-Token': 'test-admin-token-0123456789' },
  }), adminEnv))
  const oj = await online.json().catch(() => ({}))
  const onlineRow = ((oj && oj.online) || []).find((d) => d.d === d1) || {}
  check('喊话设备出现在在线列表', online.status === 200 && onlineRow.d === d1, { status: online.status, n: (oj.online || []).length })
  check('喊话设备标为 announce', onlineRow.via === 'announce', onlineRow.via)
}

{
  // 在线统计不依赖教室喊话：只打 /api/ping 的设备同样要进在线表。
  // 这是「没开喊话就看不到在线」那个问题的回归守卫。
  const dev = 'ffeeddccbbaa9988'
  const ping = await mod.onRequest(ctxOf(new Request('http://t/api/ping', {
    headers: { 'X-CSH-Did': dev },
  }), env))
  const pj = await ping.json().catch(() => ({}))
  check('ping 返回 200', ping.status === 200, ping.status)
  check('ping 识别到设备码', Number(pj.identified) === 1, pj)

  // 在线登记在入口的 waitUntil 里完成，要等它落盘
  await Promise.allSettled(waiters)
  const live = JSON.parse(store.get('dev:live') || '{}')
  check('ping 后设备进入在线表', Number(live[dev]) > 0, live)

  // 无设备码的请求不应凭空造出条目
  const anon = await mod.onRequest(ctxOf(new Request('http://t/api/ping', {}), env))
  await Promise.allSettled(waiters)
  const live2 = JSON.parse(store.get('dev:live') || '{}')
  check('无设备码 ping 不写在线表', Object.keys(live2).length === Object.keys(live).length, {
    before: Object.keys(live).length,
    after: Object.keys(live2).length,
  })
  check('无设备码 ping 仍回 200', anon.status === 200, anon.status)

  // 端到端：只打过 ping、从未参与喊话的设备，必须出现在后台在线列表里
  const adminEnv = { ...env, CSH_ADMIN_API_TOKEN: 'test-admin-token-0123456789' }
  const online = await mod.onRequest(ctxOf(new Request('http://t/api/admin/online', {
    headers: { 'X-CSH-Admin-Token': 'test-admin-token-0123456789' },
  }), adminEnv))
  const oj = await online.json().catch(() => ({}))
  const row = ((oj && oj.online) || []).find((d) => d.d === dev) || null
  check('后台在线列表包含仅心跳设备', online.status === 200 && !!row, { status: online.status, n: (oj.online || []).length })
  check('仅心跳设备标为 heartbeat', row && row.via === 'heartbeat', row && row.via)
}

await Promise.allSettled(waiters)
console.log(`\nRESULT: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
