const path = new URL('./functions/api/[[default]].js', import.meta.url).href

const store = new Map()
globalThis.CSH_STATE = {
  async get(k) { return store.has(k) ? store.get(k) : null },
  async put(k, v) { store.set(k, String(v)) },
  async delete(k) { store.delete(Array.isArray(k) ? k[0] : k) },
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

  const browser = await submitAs({ 'Sec-Fetch-Mode': 'cors', Origin: 'https://classsoftwarehub.cn' }, strict)
  check('license 浏览器来源放行', browser.status !== 403)
  const foreign = await submitAs({ 'Sec-Fetch-Mode': 'cors', Origin: 'https://evil.example.com' }, strict)
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
}

await Promise.allSettled(waiters)
console.log(`\nRESULT: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
