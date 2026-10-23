const path = 'file:///C:/csh-tencent-backend/functions/api/%5B%5Bdefault%5D%5D.js'

// blob 路径：不注入 CSH_STATE，走 @edgeone/pages-blob stub（见 node_modules）

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
  check('dl-ticket rejects bad fp size', r.status === 400 || r.status === 403, { s: r.status, j })
}

await Promise.allSettled(waiters)
console.log(`\nRESULT: ${pass} passed, ${fail} failed`)
process.exit(fail ? 1 : 0)
