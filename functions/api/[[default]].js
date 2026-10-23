
const CATEGORIES = ['system', 'schedule', 'teaching', 'other']

const ECHO_MAX_LEN = 200
const ECHO_MARKER = '回声洞'

const FEEDBACK_KINDS = ['report', 'suggestion']
const FEEDBACK_SUBKINDS = ['interaction', 'link', 'other']
const FEEDBACK_TITLE_MAX = 80
const FEEDBACK_DETAIL_MAX = 4000
const FEEDBACK_CONTACT_MAX = 4000

const AGE_ARMOR_PREFIX = '-----BEGIN AGE ENCRYPTED FILE-----'

if (typeof Response.json !== 'function') {
  Response.json = (data, init) => {
    const h = new Headers((init && init.headers) || {})
    if (!h.has('content-type')) h.set('content-type', 'application/json')
    return new Response(JSON.stringify(data), { status: (init && init.status) || 200, headers: h })
  }
}

const OSS_ALGO = 'OSS4-HMAC-SHA256'

const OSS_SIGN_TTL = 3600

const OSS_MAX_BYTES = 2.5 * 1024 * 1024 * 1024

const SIGN_PER_IP_PER_DAY = 20
const SIGN_GLOBAL_PER_DAY = 3000
const SIGN_GLOBAL_BYTES_PER_DAY = 20 * 1024 * 1024 * 1024

const SIGN_DAY_KEY_PREFIX = 'sg:'

const DL_TICKET_TTL = 900

const DL_DAILY_LIMIT = 25

function dlDailyLimit(env) {
  return pickNum(null, env && env.DL_DAILY_LIMIT, DL_DAILY_LIMIT)
}

const DL_KEY_PREFIX = /^(?:upload|soft|releases)\//

const RELEASE_PREFIX = 'releases'

const DL_RELAY_PORT = 8091

const DL_MODE_DEFAULT = 'auto'

const DIRECT_TTL_TIERS = [
  [50 * 1024 * 1024, 300],
  [250 * 1024 * 1024, 900],
  [1024 * 1024 * 1024, 1200],
  [Infinity, 1800],
]

function directTtlFor(size) {
  const max = DIRECT_TTL_TIERS[DIRECT_TTL_TIERS.length - 1][1]
  const n = Number(size) || 0
  if (n <= 0) return max
  for (const [limit, ttl] of DIRECT_TTL_TIERS) if (n <= limit) return ttl
  return max
}

const GC_ORPHAN_MINUTES = 15

const GC_MAX_DELETE = 100

const GC_STALE_RECORD_HOURS = 24

const REGISTRY_ID = '__index__'

const FILE_KEY_PREFIX = 'f:'

const BYTES_KEY_PREFIX = 'm:'

const CFG_KEY = 'cfg'

const FILE_LIST_MAX = 1000

const MAX_PURGE_BATCH = 200

const ICON_PREFIX = 'icon'

const ICON_MAX_BYTES = 5 * 1024 * 1024

const ICON_SIGN_MAX_BYTES = 1024 * 1024

const ICON_EDGE_TTL = 604800

const CONTENT_TYPE_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/
const DEFAULT_CONTENT_TYPE = 'application/octet-stream'

const MAX_DOWNLOADS_PER_APP = 5

const SUBMIT_REQUIRE_SOURCE = true

const SUBMIT_MAX_PENDING = 3

const SUBMIT_MAX_PER_DAY = 6

const SUBMIT_WINDOW_MS = 24 * 3600 * 1000

const SUBMIT_KEY_PREFIX = 's:'

const ANN_ID = '__announce__'

const ANN_BIND_PREFIX = 'ann:d:'

const ANN_MSG_PREFIX = 'ann:m:'

const ANN_RL_PREFIX = 'ann:r:'

const ANN_TEXT_MAX = 100

const ANN_FROM_MAX = 20

const ANN_TTL = 180

const ANN_BIND_TTL = 12 * 3600

const ANN_RATE_MS = 10 * 1000

const ANN_DURATION_MIN = 10
const ANN_DURATION_MAX = 120
const ANN_DURATION_DEFAULT = 30

const UNSAFE_NAME_RE = /[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\\:*?"<>|%#]+/g

function pad2(n) {
  return String(n).padStart(2, '0')
}

function uriEncode(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase()
  )
}

function toHex(buffer) {
  const bytes = new Uint8Array(buffer)
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

async function hmacSha256(keyBytes, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const payload = typeof data === 'string' ? new TextEncoder().encode(data) : data
  return crypto.subtle.sign('HMAC', key, payload)
}

const textEncoder = new TextEncoder()

async function sha256Hex(text) {
  return toHex(await crypto.subtle.digest('SHA-256', textEncoder.encode(text)))
}

function ossSafeName(raw) {
  const base = String(raw || '')
    .replace(/^.*[\\/]/, '')
    .replace(UNSAFE_NAME_RE, '_')
    .replace(/^\.+/, '')
    .replace(/\.{2,}/g, '.')
    .replace(/[ .]+$/, '')
    .trim()
  return (base || 'file').slice(0, 100)
}

function cleanText(raw, max) {
  const s = String(raw ?? '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
  return typeof max === 'number' ? s.slice(0, max) : s
}

function sniffImage(bytes) {
  const b = new Uint8Array(bytes)

  const at = (i, arr) => arr.every((v, k) => b[i + k] === v)
  if (at(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png'
  if (at(0, [0xff, 0xd8, 0xff])) return 'image/jpeg'
  if (at(0, [0x47, 0x49, 0x46, 0x38])) return 'image/gif'
  if (at(0, [0x42, 0x4d])) return 'image/bmp'
  if (at(0, [0x52, 0x49, 0x46, 0x46]) && at(8, [0x57, 0x45, 0x42, 0x50])) return 'image/webp'
  if (at(0, [0x00, 0x00, 0x01, 0x00])) return 'image/x-icon'
  return ''
}

async function ossPresignPut(env, key, contentType, expiresIn) {
  const bucket = String(env.OSS_BUCKET).trim()
  const region = String(env.OSS_REGION || 'cn-shanghai').trim()
  const endpoint = String(env.OSS_ENDPOINT || `oss-${region}.aliyuncs.com`).trim()
  const host = `${bucket}.${endpoint}`

  const now = new Date()
  const dateStr = `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}`
  const amzDate = `${dateStr}T${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}Z`

  const credentialScope = `${dateStr}/${region}/oss/aliyun_v4_request`
  const canonicalUri = `/${bucket}/${key.split('/').map(uriEncode).join('/')}`





  const additionalHeaders = 'host'

  const query = {
    'x-oss-additional-headers': additionalHeaders,
    'x-oss-credential': `${env.OSS_ACCESS_KEY_ID}/${credentialScope}`,
    'x-oss-date': amzDate,
    'x-oss-expires': String(expiresIn),
    'x-oss-signature-version': OSS_ALGO,
  }
  const canonicalQuery = Object.keys(query)
    .sort()
    .map((k) => `${uriEncode(k)}=${uriEncode(query[k])}`)
    .join('&')

  const canonicalHeaders = `content-type:${contentType}\nhost:${host}\n`
  const canonicalRequest = [
    'PUT',
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    additionalHeaders,
    'UNSIGNED-PAYLOAD',
  ].join('\n')

  const stringToSign = [
    OSS_ALGO,
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n')

  const secretBytes = textEncoder.encode(`aliyun_v4${env.OSS_ACCESS_KEY_SECRET}`)
  const kDate = await hmacSha256(secretBytes, dateStr)
  const kRegion = await hmacSha256(kDate, region)
  const kService = await hmacSha256(kRegion, 'oss')
  const kSigning = await hmacSha256(kService, 'aliyun_v4_request')
  const signature = toHex(await hmacSha256(kSigning, stringToSign))

  const signedQuery = `${canonicalQuery}&x-oss-signature=${signature}`
  return {
    url: `https://${host}/${key.split('/').map(uriEncode).join('/')}?${signedQuery}`,
    publicUrl: `${String(env.OSS_PUBLIC_BASE || `https://${host}`).replace(/\/+$/, '')}/${key
      .split('/')
      .map(uriEncode)
      .join('/')}`,
    host,
  }
}

/**
 * 生成对象的**下载**地址（V4 预签名 GET）。
 *
 * 与上传版的差别有三处：方法换成 GET、CanonicalHeaders 只剩 host（GET 不订 content-type）、
 * 额外把 `response-content-disposition` 一起签进查询串 —— 这是 OSS 支持的子资源，
 * 会让 OSS 自己在响应里带上保存名，等于「直链」也具备下载语义。
 *
 * 这条地址就是**直连通道**：浏览器拿着它直接去 OSS 取，Worker 与 ECS 都不在链路上。
 * 所以有效期必须短（跟票据同寿 15 分钟），否则被转发出去就是一条长期有效的公开直链。
 */
async function ossPresignGet(env, key, expiresIn, fileName) {
  const bucket = String(env.OSS_BUCKET).trim()
  const region = String(env.OSS_REGION || 'cn-shanghai').trim()
  const endpoint = String(env.OSS_ENDPOINT || `oss-${region}.aliyuncs.com`).trim()
  const host = `${bucket}.${endpoint}`

  const now = new Date()
  const dateStr = `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}`
  const amzDate = `${dateStr}T${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}Z`
  const credentialScope = `${dateStr}/${region}/oss/aliyun_v4_request`

  const query = {
    'x-oss-additional-headers': 'host',
    'x-oss-credential': `${env.OSS_ACCESS_KEY_ID}/${credentialScope}`,
    'x-oss-date': amzDate,
    'x-oss-expires': String(expiresIn),
    'x-oss-signature-version': OSS_ALGO,
  }
  if (fileName) {
    query['response-content-disposition'] =
      `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`
  }
  const canonicalQuery = Object.keys(query)
    .sort()
    .map((k) => `${uriEncode(k)}=${uriEncode(query[k])}`)
    .join('&')

  const canonicalUri = `/${bucket}/${key.split('/').map(uriEncode).join('/')}`
  const canonicalHeaders = `host:${host}\n`
  const additionalHeaders = 'host'
  const canonicalRequest = [
    'GET',
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    additionalHeaders,
    'UNSIGNED-PAYLOAD',
  ].join('\n')

  const stringToSign = [
    OSS_ALGO,
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n')

  const secretBytes = textEncoder.encode(`aliyun_v4${env.OSS_ACCESS_KEY_SECRET}`)
  const kDate = await hmacSha256(secretBytes, dateStr)
  const kRegion = await hmacSha256(kDate, region)
  const kService = await hmacSha256(kRegion, 'oss')
  const kSigning = await hmacSha256(kService, 'aliyun_v4_request')
  const signature = toHex(await hmacSha256(kSigning, stringToSign))

  return `https://${host}/${key.split('/').map(uriEncode).join('/')}?${canonicalQuery}&x-oss-signature=${signature}`
}

async function registryOp(env, payload) {
  if (!env.DL_GATE) return null
  try {
    const id = env.DL_GATE.idFromName(REGISTRY_ID)
    const res = await env.DL_GATE.get(id).fetch('https://dl-gate/op', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    return await res.json()
  } catch (err) {
    console.error('registry op error:', err && err.message)
    return null
  }
}

function registryPut(env, record) {
  return registryOp(env, { op: 'file-put', record })
}

async function registryGet(env, key) {
  const out = await registryOp(env, { op: 'file-get', key })
  return (out && out.file) || null
}

function registryClaim(env, keys) {
  const list = [...new Set((keys || []).filter(Boolean))]
  if (!list.length) return null
  return registryOp(env, { op: 'file-claim', keys: list })
}

async function registryUnclaimed(env) {
  const out = await registryOp(env, { op: 'unclaimed-list' })
  return out && Array.isArray(out.files) ? out.files : null
}

async function registryCfgGet(env) {
  const out = await registryOp(env, { op: 'cfg-get' })
  return (out && out.cfg) || null
}

function registryCfgSet(env, patch) {
  return registryOp(env, { op: 'cfg-set', cfg: patch })
}

function ossKeyOfUrl(url) {
  const raw = String(url ?? '').trim()
  if (!raw) return ''
  const key = (() => {
    const m = /^oss:\/\/(.+)$/i.exec(raw)
    if (m) {
      const body = m[1].split(/[?#]/)[0].replace(/^\/+/, '')


      try {
        return decodeURIComponent(body)
      } catch {
        return ''
      }
    }
    try {
      const u = new URL(raw)
      if (u.pathname === '/api/icon' || u.pathname === '/api/dl') {
        return u.searchParams.get('k') || ''
      }
    } catch {

    }
    return ''
  })()


  if (!key || key.includes('..') || /[\u0000-\u001f\u007f\\]/.test(key)) return ''
  return key
}

function collectOssKeys(data) {
  const keys = [ossKeyOfUrl(data?.icon)]
  for (const item of Array.isArray(data?.downloads) ? data.downloads : []) {
    keys.push(ossKeyOfUrl(item?.url))
  }
  return [...new Set(keys.filter(Boolean))]
}

function pickNum(cfgValue, envValue, fallback) {
  for (const v of [cfgValue, envValue]) {
    if (v === null || v === undefined || v === '') continue
    const n = Number(v)
    if (Number.isFinite(n)) return n
  }
  return fallback
}

function pickBool(cfgValue, envValue, fallback) {
  for (const v of [cfgValue, envValue]) {
    if (v === true || v === 'true' || v === 1 || v === '1') return true
    if (v === false || v === 'false' || v === 0 || v === '0') return false
  }
  return fallback
}

async function registryHas(env, key) {
  const out = await registryOp(env, { op: 'file-get', key })
  if (out === null) return null
  const f = out.file
  return !!(f && !f.deleted)
}

async function submitterIdOf(data) {
  const raw = String((data && (data._设备 || data.fp)) || '').trim()
  if (raw.length < 8 || raw.length > 256) return ''
  return (await sha256Hex(raw)).slice(0, 16)
}

async function countPendingIssues(env, sid) {
  if (!sid) return -1
  const q = `repo:${env.GITHUB_OWNER}/${env.GITHUB_REPO} is:issue is:open label:待审核 "csh-submitter:${sid}"`
  try {
    const res = await fetch(
      `https://api.github.com/search/issues?q=${encodeURIComponent(q)}&per_page=1`,
      { headers: githubHeaders(env) }
    )
    if (!res.ok) {
      console.error('pending search failed:', res.status)
      return -1
    }
    const j = await res.json()
    const n = Number(j && j.total_count)
    return Number.isFinite(n) ? n : -1
  } catch (err) {
    console.error('pending search error:', err && err.message)
    return -1
  }
}

async function submitGate(env, data, sid) {
  const cfg = await registryCfgGet(env)
  const requireSource = pickBool(cfg && cfg.requireSource, env.SUBMIT_REQUIRE_SOURCE, SUBMIT_REQUIRE_SOURCE)
  const maxPending = pickNum(cfg && cfg.maxPending, env.SUBMIT_MAX_PENDING, SUBMIT_MAX_PENDING)
  const maxPerDay = pickNum(cfg && cfg.maxPerDay, env.SUBMIT_MAX_PER_DAY, SUBMIT_MAX_PER_DAY)

  if (requireSource) {
    const hasUpload = collectOssKeys(data).some((k) => /^upload\//.test(k))
    const hasGithub = !!String(data.github || '').trim()
    if (!hasUpload && !hasGithub) {
      return {
        ok: false,
        status: 403,
        error:
          '本站只受理「上传了安装包」或「填写了 GitHub 仓库」的投稿。' +
          '只填外链的话，请直接到仓库提 Issue，或先把安装包上传到本站。',
      }
    }
  }

  if (!sid) return { ok: true }

  if (maxPerDay > 0) {
    const tick = await registryOp(env, { op: 'submit-tick', sid })
    if (tick && tick.ok && Number(tick.used) > maxPerDay) {
      return {
        ok: false,
        status: 429,
        error: `提交太频繁：同一台设备 24 小时内最多提交 ${maxPerDay} 次，请稍后再试。`,
      }
    }
  }

  if (maxPending > 0) {
    const n = await countPendingIssues(env, sid)
    if (n >= 0 && n >= maxPending) {
      return {
        ok: false,
        status: 429,
        error: `你还有 ${n} 条投稿在等待审核（上限 ${maxPending} 条），请等管理员处理完再提交新的。`,
      }
    }
  }

  return { ok: true }
}

async function signGate(env, src, bytes) {
  if (!env.DL_GATE) return { allowed: true }
  try {
    const id = env.DL_GATE.idFromName('__sign__')
    const res = await env.DL_GATE.get(id).fetch('https://dl-gate/sign-check', {
      method: 'POST',
      body: JSON.stringify({


        op: 'sign-check',
        ip: src,
        bytes: Math.max(0, Number(bytes) || 0),

        perIp: pickNum(null, env.SIGN_PER_IP_PER_DAY, SIGN_PER_IP_PER_DAY),
        perDay: pickNum(null, env.SIGN_GLOBAL_PER_DAY, SIGN_GLOBAL_PER_DAY),
        bytesPerDay: pickNum(null, env.SIGN_GLOBAL_BYTES_PER_DAY, SIGN_GLOBAL_BYTES_PER_DAY),
      }),
    })
    const out = await res.json()
    if (out && out.allowed === false) {
      return {
        allowed: false,
        scope: out.scope || 'global',
        message:
          out.scope === 'ip'
            ? '上传请求过于频繁，请稍后再试。'
            : '今天的上传配额已用完，请明天再试，或改用官网 / GitHub 外链。',
      }
    }
    return { allowed: true }
  } catch (err) {
    console.error('sign gate error:', err && err.message)
    return { allowed: true }
  }
}

async function handleOssSign(request, env, ctx) {
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }

  if (!env.OSS_BUCKET || !env.OSS_ACCESS_KEY_ID || !env.OSS_ACCESS_KEY_SECRET) {
    return json({ error: '上传服务未配置' }, 503, request, env)
  }

  const isIcon = String(data?.purpose || '') === 'icon'
  const size = Number(data?.size)
  if (!Number.isFinite(size) || size <= 0) {
    return json({ error: '缺少文件大小' }, 400, request, env)
  }


  const sizeLimit = isIcon ? ICON_SIGN_MAX_BYTES : OSS_MAX_BYTES
  if (size > sizeLimit) {
    return json({ error: isIcon ? '图标文件太大' : '文件太大' }, 413, request, env)
  }





  const srcRaw = request.headers.get('CF-Connecting-IP') || request.headers.get('x-forwarded-for') || 'unknown'
  const src = (await sha256Hex(String(srcRaw).split(',')[0].trim())).slice(0, 24)
  const gate = await signGate(env, src, size)
  if (!gate.allowed) {
    return json({ error: gate.message, scope: gate.scope }, 429, request, env)
  }


  const rawType = String(data?.contentType || '').trim().toLowerCase().split(';')[0].trim()
  const contentType = CONTENT_TYPE_RE.test(rawType) ? rawType : DEFAULT_CONTENT_TYPE

  const now = new Date()
  const stamp = `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}`
  const uniq = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`

  const prefix = isIcon ? ICON_PREFIX : String(env.OSS_PREFIX || 'upload').replace(/^\/+|\/+$/g, '')
  const key = `${prefix}/${stamp.slice(0, 4)}/${stamp.slice(4, 6)}/${uniq}-${ossSafeName(data?.name)}`



  const fph = data?.fp ? (await sha256Hex(String(data.fp))).slice(0, 16) : ''
  const regTask = registryPut(env, {
    key,
    size,
    name: ossSafeName(data?.name),
    ctype: contentType,
    origin: isIcon ? ICON_PREFIX : 'file',
    fph,
    ts: Date.now(),
    deleted: 0,
  })

  if (ctx) ctx.waitUntil(regTask)
  else await regTask

  try {
    const signed = await ossPresignPut(env, key, contentType, OSS_SIGN_TTL)
    return json(
      {
        success: true,
        url: signed.url,
        publicUrl: signed.publicUrl,
        key,
        contentType,
        expiresIn: OSS_SIGN_TTL,
        maxBytes: sizeLimit,


        orphanMinutes: await gcOrphanMinutes(env),
      },
      200,
      request,
      env
    )
  } catch (err) {
    console.error('oss sign error:', err && err.message)
    return json({ error: '签发上传地址失败' }, 500, request, env)
  }
}

const MIRROR_SIGN_HOST = 'download.classsoftwarehub.cn'

function isGithubFileUrl(raw) {
  let parsed
  try {
    parsed = new URL(raw)
  } catch {
    return false
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false
  const host = parsed.hostname.toLowerCase()
  if (host === 'github.com' || host === 'www.github.com') {
    return /^\/[^/]+\/[^/]+\/(releases\/download|archive)\//.test(parsed.pathname)
  }
  return (
    host === 'objects.githubusercontent.com' ||
    host === 'github-releases.githubusercontent.com' ||
    host === 'codeload.github.com' ||
    host === 'raw.githubusercontent.com'
  )
}

async function handleMirrorSign(request, env) {
  if (!env.SIGN_API_KEY) {
    return json({ error: '加速服务未配置' }, 503, request, env)
  }

  const target = (new URL(request.url).searchParams.get('url') || '').trim()
  if (!isGithubFileUrl(target)) {
    return json({ error: '仅支持 GitHub 文件直链' }, 400, request, env)
  }

  try {
    const srcIp = (request.headers.get('CF-Connecting-IP') || (request.headers.get('x-forwarded-for') || '').split(',')[0] || '').trim()
    const res = await fetch(
      `https://${MIRROR_SIGN_HOST}/sign?url=${encodeURIComponent(target)}${srcIp ? `&ip=${encodeURIComponent(srcIp)}` : ''}`,
      {
        headers: {
          'X-Api-Key': env.SIGN_API_KEY,
          'User-Agent': 'classsoftwarehub-worker',
        },
      }
    )
    if (!res.ok) {
      console.error('mirror sign error:', res.status, (await res.text()).slice(0, 200))
      return json({ error: '签发加速链接失败' }, 502, request, env)
    }
    const data = await res.json()
    if (!data || !data.url) {
      return json({ error: '签发加速链接失败' }, 502, request, env)
    }
    return json(
      {
        success: true,
        url: data.url,
        expiresAt: typeof data.expiresAt === 'number' ? data.expiresAt : null,
        ttl: typeof data.ttl === 'number' ? data.ttl : null,
      },
      200,
      request,
      env
    )
  } catch (err) {
    console.error('mirror sign error:', err && err.message)
    return json({ error: '签发加速链接失败' }, 502, request, env)
  }
}

function getOrigin(request, env) {
  const raw = (env.ALLOWED_ORIGIN || '').trim()
  if (!raw) return '*'

  const list = raw.split(',').map(s => s.trim()).filter(Boolean)
  if (list.includes('*')) return '*'

  const origin = request.headers.get('Origin') || ''
  return list.includes(origin) ? origin : ''
}

function corsHeaders(request, env) {
  const origin = getOrigin(request, env)
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  }
  if (origin) headers['Access-Control-Allow-Origin'] = origin
  return headers
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request, env) },
  })
}

function toBase64(str) {
  const bytes = new TextEncoder().encode(str)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary)
}

function encodePath(path) {
  return path.split('/').map(encodeURIComponent).join('/')
}

function githubHeaders(env) {
  return {
    Authorization: `Bearer ${env.GITHUB_TOKEN}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'classsoftwarehub-worker',
    'X-GitHub-Api-Version': '2022-11-28',
  }
}

const ID_RE = /^[a-z0-9][a-z0-9-]*$/

const ALLOWED_URL_SCHEMES = new Set(['http', 'https', 'oss', 'ms-windows-store'])

function urlSchemeOk(url) {
  const m = /^([a-z][a-z0-9+.-]*):/i.exec(String(url).trim())
  if (!m) return true
  return ALLOWED_URL_SCHEMES.has(m[1].toLowerCase())
}

function validate(d) {
  const errors = []

  if (!d.id || !ID_RE.test(d.id)) errors.push('id 只能用小写英文、数字、短横线，且以字母或数字开头')
  if (d.id && d.id.length > 60) errors.push('id 太长')
  if (!d.name) errors.push('缺少软件名称')
  if (!d.category) errors.push('缺少分类')
  if (d.category && !CATEGORIES.includes(d.category)) errors.push('分类不合法')
  if (!d.tagline) errors.push('缺少一句话简介')
  if (!d.description) errors.push('缺少详细介绍')

  if (d.downloads && !Array.isArray(d.downloads)) errors.push('downloads 必须是数组')


  if (Array.isArray(d.downloads) && d.downloads.length > MAX_DOWNLOADS_PER_APP) {
    errors.push(`下载项最多 ${MAX_DOWNLOADS_PER_APP} 个，更多版本请在详情里给官网或 GitHub Releases 链接`)
  }
  if (d.name && String(d.name).length > 120) errors.push('软件名称太长（最多 120 字）')
  if (d.tagline && String(d.tagline).length > 300) errors.push('一句话简介太长（最多 300 字）')
  if (d.description && String(d.description).length > 8000) errors.push('详细介绍太长（最多 8000 字）')

  for (const key of ['icon', 'website', 'github', 'store']) {
    if (d[key] && typeof d[key] === 'string' && !/^https?:\/\//.test(d[key])) {
      errors.push(`${key} 必须以 http:// 或 https:// 开头`)
    }
  }


  if (Array.isArray(d.downloads)) {
    d.downloads.forEach((item, i) => {
      const url = item && typeof item.url === 'string' ? item.url.trim() : ''
      if (url && !urlSchemeOk(url)) {
        errors.push(`第 ${i + 1} 个下载项的地址协议不受支持（只允许 http(s):// 或 oss://）`)
      }
    })
  }

  return errors
}

async function handleSubmit(request, env) {
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }

  const errors = validate(data)
  if (errors.length) return json({ error: errors.join('；') }, 400, request, env)


  const sid = await submitterIdOf(data)
  const gate = await submitGate(env, data, sid)
  if (!gate.ok) return json({ error: gate.error }, gate.status, request, env)




  const unknown = []
  for (const k of collectOssKeys(data)) {
    if (!/^upload\//.test(k)) continue
    if ((await registryHas(env, k)) === false) unknown.push(k)
  }
  if (unknown.length) {
    return json(
      {
        error:
          '下载项里有本站未登记的文件地址（可能已被自动清理，或不是由本站上传的）。' +
          '请重新在页面上传一次再提交。',
        invalid: unknown,
      },
      400,
      request,
      env
    )
  }







  const referenced = collectOssKeys(data).filter((k) => /^upload\//.test(k))
  if (referenced.length) {
    const gone = []
    for (const k of referenced) {
      try {
        const probe = await relayOpen(env, k, 'HEAD')
        if (probe.reader) {
          try { probe.reader.releaseLock() } catch {}
          try { probe.socket.close() } catch {}
          if (probe.status === 404) gone.push(k)
        }
      } catch (err) {
        console.error('submit probe error:', err && err.message)
      }
    }
    if (gone.length) {
      const mins = await gcOrphanMinutes(env)
      return json(
        {
          error: `附件已因长时间未提交被自动清理（上传后 ${mins} 分钟内需完成提交），请重新上传后再提交`,
          missing: gone,
        },
        409,
        request,
        env
      )
    }
  }

  const timestamp = Date.now()
  const filePath = `submissions/${data.id}-${timestamp}.json`
  const apiBase = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents`
  const headers = githubHeaders(env)

  const appsPath = `软件数据/apps/${data.id}.json`
  const appsCheckRes = await fetch(
    `${apiBase}/${encodePath(appsPath)}?ref=${env.GITHUB_BRANCH}`,
    { headers }
  )
  const idAlreadyExists = appsCheckRes.ok

  const downloads = (data.downloads || [])
    .filter(x => x && x.url)
    .map(x => {
      const item = { platform: cleanText(x.platform, 120) }
      const note = cleanText(x.note, 500)
      if (note) item.note = note
      const sizeLabel = cleanText(x.size, 60)
      if (sizeLabel) item.size = sizeLabel



      const hash = typeof x.hash === 'string' ? x.hash.replace(/[^0-9a-f]/gi, '').toLowerCase() : ''
      if (hash) item.hash = hash
      item.url = cleanText(x.url, 1000)
      return item
    })

  const fileContent = {
    id: data.id,
    name: cleanText(data.name, 120),
    icon: cleanText(data.icon, 1000),
    category: data.category,
    tagline: cleanText(data.tagline, 300),
    description: cleanText(data.description, 8000),
    version: cleanText(data.version, 60),
    size: cleanText(data.size, 60),
    system: cleanText(data.system, 200),
    website: cleanText(data.website, 1000),
    github: cleanText(data.github, 1000),
    downloads,
    sort: typeof data.sort === 'number' ? data.sort : 99,
  }
  const notice = cleanText(data.notice, 1000)
  if (notice) fileContent.notice = notice
  const store = cleanText(data.store, 1000)
  if (store) fileContent.store = store
  const maintainerNote = cleanText(data.维护备注, 1000)
  if (maintainerNote) fileContent['维护备注'] = maintainerNote

  const submissionContent = {
    _提交时间: new Date(timestamp).toISOString(),
    _原始ID冲突: idAlreadyExists,
    ...fileContent,
  }



  if (sid) submissionContent._提交指纹 = sid











  const SUBMISSION_META_KEYS = new Set(['_联系方式'])
  for (const key of Object.keys(data)) {
    if (!SUBMISSION_META_KEYS.has(key) || key in submissionContent) continue
    const value = data[key]
    if (typeof value === 'string') {



      const limit = key === '_联系方式' ? 4000 : 300
      const cleaned = cleanText(value, limit)
      if (cleaned) submissionContent[key] = cleaned
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      submissionContent[key] = value
    }
  }

  const content = JSON.stringify(submissionContent, null, 2)

  const createRes = await fetch(`${apiBase}/${encodePath(filePath)}`, {
    method: 'PUT',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: `submit: ${data.name} (${data.id})`,
      content: toBase64(content),
      branch: env.GITHUB_BRANCH,
    }),
  })

  if (!createRes.ok) {
    const errText = await createRes.text()
    console.error('GitHub API error:', createRes.status, errText)
    return json({ error: '提交失败，请稍后再试' }, 500, request, env)
  }





  try {
    const claimed = await registryClaim(env, collectOssKeys(fileContent))
    if (claimed && Array.isArray(claimed.claimed) && claimed.claimed.length) {
      console.log('claimed:', claimed.claimed.length)
    }
  } catch (err) {
    console.error('claim error:', err && err.message)
  }

  return json({
    success: true,
    message: idAlreadyExists
      ? '提交成功！该 ID 已存在，管理员审核后会处理。'
      : '提交成功！管理员审核通过后会自动上线。',
  }, 200, request, env)
}

async function handleEchoCave(request, env) {
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }

  const text = typeof data?.text === 'string' ? data.text.trim() : ''
  if (!text) return json({ error: '先写一句话再投稿吧。' }, 400, request, env)
  if (text.length > ECHO_MAX_LEN) {
    return json({ error: `字条太长啦，最多 ${ECHO_MAX_LEN} 个字。` }, 400, request, env)
  }

  const apiBase = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents`
  const headers = githubHeaders(env)


  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const filePath = `submissions/echo-${stamp}.json`
  const content =
    JSON.stringify(
      { _类型: ECHO_MARKER, text, _提交时间: new Date().toISOString() },
      null,
      2
    ) + '\n'

  const createRes = await fetch(`${apiBase}/${encodePath(filePath)}`, {
    method: 'PUT',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: 'submit: 回声洞字条',
      content: toBase64(content),
      branch: env.GITHUB_BRANCH,
    }),
  })

  if (!createRes.ok) {
    console.error('echo draft error:', createRes.status, await createRes.text())
    return json({ error: '投稿失败，请稍后再试' }, 500, request, env)
  }

  return json(
    { success: true, message: '投稿成功！审核通过后会出现在回声洞里。' },
    200,
    request,
    env
  )
}

async function handleFeedback(request, env) {
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }

  const str = (value) => (typeof value === 'string' ? value.trim() : '')
  const kind = str(data?.kind)
  const subKind = str(data?.subKind)
  const appId = str(data?.appId)

  const title = str(data?.title).replace(/\s+/g, ' ')
  const detail = str(data?.detail)
  const contact = str(data?.contact)

  if (!FEEDBACK_KINDS.includes(kind)) {
    return json({ error: '请选择反馈类型' }, 400, request, env)
  }
  if (kind === 'report' && !FEEDBACK_SUBKINDS.includes(subKind)) {
    return json({ error: '请选择问题类型' }, 400, request, env)
  }
  if (!title) return json({ error: '请填写标题' }, 400, request, env)
  if (title.length > FEEDBACK_TITLE_MAX) {
    return json({ error: `标题太长啦，最多 ${FEEDBACK_TITLE_MAX} 个字。` }, 400, request, env)
  }
  if (!detail) return json({ error: '请填写详细描述' }, 400, request, env)
  if (detail.length > FEEDBACK_DETAIL_MAX) {
    return json({ error: `描述太长啦，最多 ${FEEDBACK_DETAIL_MAX} 个字。` }, 400, request, env)
  }


  if (appId && !/^[a-z0-9-]{1,60}$/.test(appId)) {
    return json({ error: '涉及的软件 ID 不合法' }, 400, request, env)
  }
  if (contact.length > FEEDBACK_CONTACT_MAX) {
    return json({ error: '联系方式太长啦。' }, 400, request, env)
  }

  if (contact && !contact.startsWith(AGE_ARMOR_PREFIX)) {
    return json({ error: '联系方式必须先在本地加密后再提交' }, 400, request, env)
  }

  const draft = {
    _类型: '反馈',
    kind,
    subKind: kind === 'report' ? subKind : '',
    appId,
    title,
    detail,
  }
  if (contact) draft.contact = contact
  draft._提交时间 = new Date().toISOString()

  const apiBase = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents`
  const headers = githubHeaders(env)
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const filePath = `submissions/feedback-${stamp}.json`
  const content = JSON.stringify(draft, null, 2) + '\n'

  const createRes = await fetch(`${apiBase}/${encodePath(filePath)}`, {
    method: 'PUT',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: `submit: 反馈 ${title.slice(0, 40)}`,
      content: toBase64(content),
      branch: env.GITHUB_BRANCH,
    }),
  })

  if (!createRes.ok) {
    console.error('feedback draft error:', createRes.status, await createRes.text())
    return json({ error: '提交失败，请稍后再试' }, 500, request, env)
  }

  return json(
    { success: true, message: '反馈已提交！会尽快出现在公开议题列表里。' },
    200,
    request,
    env
  )
}

function dlKeyOk(key) {
  if (typeof key !== 'string') return false
  if (key.length < 8 || key.length > 400) return false
  if (!DL_KEY_PREFIX.test(key)) return false
  if (key.includes('..') || key.includes('//')) return false
  if (/[\u0000-\u001f\u007f\\]/.test(key)) return false
  return true
}

function dlFileName(key, override) {
  const raw = (override && String(override)) || key.split('/').pop() || 'download'
  const clean = raw
    .replace(/^.*[\\/]/, '')
    .replace(/[\u0000-\u001f\u007f\\:*?"<>|]+/g, '_')
    .replace(/^\.+/, '')
    .trim()
  return clean || 'download'
}

async function dlTicketSig(env, exp, fpHash, key) {
  const secret = textEncoder.encode(String(env.DL_SIGN_SECRET || ''))
  return toHex(await hmacSha256(secret, `${exp}|${fpHash}|${key}`)).slice(0, 32)
}

function indexOfCrlfCrlf(buf) {
  for (let i = 3; i < buf.length; i++) {
    if (buf[i - 3] === 13 && buf[i - 2] === 10 && buf[i - 1] === 13 && buf[i] === 10) return i - 3
  }
  return -1
}

async function ossSignedUrl(env, method, key, extraQuery) {
  const bucket = String(env.OSS_BUCKET).trim()
  const region = String(env.OSS_REGION || 'cn-shanghai').trim()
  const endpoint = String(env.OSS_ENDPOINT || `oss-${region}.aliyuncs.com`).trim()
  const host = `${bucket}.${endpoint}`
  const now = new Date()
  const dateStr = `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}`
  const amzDate = `${dateStr}T${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}Z`
  const credentialScope = `${dateStr}/${region}/oss/aliyun_v4_request`
  const encKey = key.split('/').map(uriEncode).join('/')
  const canonicalUri = `/${bucket}/${encKey}`
  const query = Object.assign({
    'x-oss-additional-headers': 'host',
    'x-oss-credential': `${env.OSS_ACCESS_KEY_ID}/${credentialScope}`,
    'x-oss-date': amzDate,
    'x-oss-expires': '900',
    'x-oss-signature-version': OSS_ALGO,
  }, extraQuery || {})
  const canonicalQuery = Object.keys(query)
    .sort()
    .map((k) => `${uriEncode(k)}=${uriEncode(query[k])}`)
    .join('&')
  const canonicalHeaders = `host:${host}\n`
  const canonicalRequest = [method, canonicalUri, canonicalQuery, canonicalHeaders, 'host', 'UNSIGNED-PAYLOAD'].join('\n')
  const stringToSign = [OSS_ALGO, amzDate, credentialScope, await sha256Hex(canonicalRequest)].join('\n')
  const secretBytes = textEncoder.encode(`aliyun_v4${env.OSS_ACCESS_KEY_SECRET}`)
  const kDate = await hmacSha256(secretBytes, dateStr)
  const kRegion = await hmacSha256(kDate, region)
  const kService = await hmacSha256(kRegion, 'oss')
  const kSigning = await hmacSha256(kService, 'aliyun_v4_request')
  const signature = toHex(await hmacSha256(kSigning, stringToSign))
  return `https://${host}/${encKey}?${canonicalQuery}&x-oss-signature=${signature}`
}

async function relayOpen(env, key, method, range) {
  let url
  try {
    url = await ossSignedUrl(env, method, key)
  } catch (err) {
    return { status: 503, text: '下载服务未配置' }
  }
  let res
  try {
    res = await fetch(url, { method, headers: range ? { Range: range } : {} })
  } catch (err) {
    return { status: 502, text: '存储暂不可用' }
  }
  const hdrs = {}
  res.headers.forEach((v, k) => { hdrs[k.toLowerCase()] = v })
  const sock = {
    close() {
      try { if (res.body) res.body.cancel() } catch {}
    },
  }
  if (method === 'HEAD') {
    const dummy = new ReadableStream().getReader()
    return { status: res.status, headers: hdrs, reader: dummy, socket: sock, first: new Uint8Array(0) }
  }
  if (method === 'DELETE') {
    const reader = res.body ? res.body.getReader() : new ReadableStream().getReader()
    return { status: res.status, headers: hdrs, reader, socket: sock, first: new Uint8Array(0) }
  }
  if (!res.ok) {
    let t = ''
    try { t = await res.text() } catch {}
    return { status: res.status, text: t.slice(0, 200) }
  }
  return { status: res.status, headers: hdrs, reader: res.body.getReader(), socket: sock, first: new Uint8Array(0) }
}

function relayRespond(relay, method, fileName) {
  const upstream = relay.headers['content-length']
  const out = new Headers()
  if (relay.headers['content-type']) out.set('Content-Type', relay.headers['content-type'])
  if (relay.headers['content-range']) out.set('Content-Range', relay.headers['content-range'])
  if (upstream) out.set('Content-Length', upstream)
  out.set('Accept-Ranges', 'bytes')
  out.set('Cache-Control', 'private, no-store')
  out.set('X-Content-Type-Options', 'nosniff')
  if (method !== 'HEAD' && fileName) {
    out.set('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`)
  }

  if (method === 'HEAD') {
    try { relay.reader.releaseLock() } catch {}
    try { relay.socket.close() } catch {}
    return new Response(null, { status: relay.status, headers: out })
  }

  const stream = new ReadableStream({
    start(controller) {
      if (relay.first && relay.first.length) controller.enqueue(relay.first)
    },
    async pull(controller) {
      try {
        const { value, done } = await relay.reader.read()
        if (done) {
          controller.close()
          try { relay.socket.close() } catch {}
          return
        }
        if (value && value.length) controller.enqueue(value)
      } catch (err) {
        controller.error(err)
        try { relay.socket.close() } catch {}
      }
    },
    cancel() {
      try { relay.reader.releaseLock() } catch {}
      try { relay.socket.close() } catch {}
    },
  })
  return new Response(stream, { status: relay.status, headers: out })
}

async function relayListDetailed(env, prefix) {
  let token = ''
  const objects = []
  for (let page = 0; page < 20; page++) {
    const q = { 'list-type': '2', prefix, 'max-keys': '1000' }
    if (token) q['continuation-token'] = token
    let res
    try {
      res = await fetch(await ossSignedUrl(env, 'GET', '', q))
    } catch (err) {
      return null
    }
    if (!res.ok) return null
    const xml = await res.text()
    const blocks = xml.split('<Contents>').slice(1)
    for (const b of blocks) {
      const keyM = /<Key>([\s\S]*?)<\/Key>/.exec(b)
      const sizeM = /<Size>([\s\S]*?)<\/Size>/.exec(b)
      const lmM = /<LastModified>([\s\S]*?)<\/LastModified>/.exec(b)
      if (keyM) {
        objects.push({
          key: decodeXml(keyM[1]),
          size: Number(sizeM ? sizeM[1] : 0) || 0,
          lastModified: lmM ? lmM[1] : '',
        })
      }
    }
    const truncM = /<IsTruncated>([\s\S]*?)<\/IsTruncated>/.exec(xml)
    const nextM = /<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/.exec(xml)
    if (truncM && truncM[1].trim() === 'true' && nextM) {
      token = decodeXml(nextM[1])
    } else {
      return { objects, truncated: false }
    }
  }
  return { objects, truncated: true }
}

function decodeXml(s) {
  return s
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&amp;/g, '&')
}

async function relayListObjects(env, prefix) {
  const out = await relayListDetailed(env, prefix)
  return out === null ? null : out.objects
}

async function relayList(env, prefix) {
  const objs = await relayListObjects(env, prefix)
  return objs === null ? null : objs.map((o) => o.key)
}

async function dlModeWanted(env) {
  const out = await registryOp(env, { op: 'cfg-get' })
  const stored = out && out.cfg && out.cfg.mode
  const raw = String(stored || env.DL_MODE || DL_MODE_DEFAULT).trim().toLowerCase()
  return raw === 'relay' || raw === 'direct' ? raw : 'auto'
}

function gbToBytes(value) {
  const n = Number(value)
  return Number.isFinite(n) && n > 0 ? Math.round(n * 1024 * 1024 * 1024) : 0
}

async function buildDirectUrl(env, key, fileName, ttl) {
  if (!env.OSS_BUCKET || !env.OSS_ACCESS_KEY_ID || !env.OSS_ACCESS_KEY_SECRET) return null
  try {
    return await ossPresignGet(env, key, ttl || DL_TICKET_TTL, fileName)
  } catch (err) {
    console.error('direct presign error:', err && err.message)
    return null
  }
}

async function handleDlTicket(request, env, ctx) {
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }

  const relayReady = !!(env.RELAY_HOST && env.RELAY_TOKEN)
  const ossReady = !!(env.OSS_BUCKET && env.OSS_ACCESS_KEY_ID && env.OSS_ACCESS_KEY_SECRET)
  if (!relayReady && !ossReady) {
    return json({ error: '下载服务未配置' }, 503, request, env)
  }

  const key = String(data?.key || '').trim()
  if (!dlKeyOk(key)) return json({ error: '下载地址无效' }, 400, request, env)

  const fp = String(data?.fp || '').trim()
  if (fp.length < 8 || fp.length > 256) return json({ error: '设备标识无效' }, 400, request, env)






  const reg = await registryOp(env, { op: 'file-get', key })
  if (reg && reg.ok) {
    if (reg.file && reg.file.deleted) return json({ error: '文件已被清理' }, 404, request, env)
    if (!reg.file && key.startsWith('upload/')) {
      return json({ error: '下载地址无效' }, 404, request, env)
    }
  }

  const fpHash = (await sha256Hex(fp)).slice(0, 16)

  if (env.DL_GATE) {
    try {
      const id = env.DL_GATE.idFromName(fpHash)
      const res = await env.DL_GATE.get(id).fetch('https://dl-gate/check', {
        method: 'POST',
        body: JSON.stringify({ limit: dlDailyLimit(env) }),
      })
      const gate = await res.json()
      if (!gate.allowed) {
        return json(
          {
            error: `今天的下载额度已用完（每台设备每天 ${gate.limit} 次），明天再来吧`,
            used: gate.used,
            limit: gate.limit,
            remaining: 0,
          },
          429,
          request,
          env
        )
      }
      var gateInfo = gate
    } catch (err) {
      console.error('dl gate error:', err && err.message)
    }
  }



  const rec = await registryGet(env, key)
  const size = rec && Number.isFinite(Number(rec.size)) ? Number(rec.size) : 0

  const want =
    String(data?.prefer || '').trim().toLowerCase() === 'relay' || String(data?.prefer || '').trim().toLowerCase() === 'direct'
      ? String(data.prefer).trim().toLowerCase()
      : await dlModeWanted(env)
  const stats = (await registryOp(env, { op: 'stats' })) || {}
  const relayUsed = Number(stats.relay) || 0
  const directUsed = Number(stats.direct) || 0
  const relayCap = gbToBytes(env.DL_RELAY_MONTHLY_GB)
  const directCap = gbToBytes(env.DL_DIRECT_MONTHLY_GB)
  const relayFull = relayCap > 0 && relayUsed >= relayCap
  const directFull = directCap > 0 && directUsed >= directCap

  const exp = Math.floor(Date.now() / 1000) + DL_TICKET_TTL
  const sig = await dlTicketSig(env, exp, fpHash, key)
  const origin = new URL(request.url).origin
  const relayPath = relayReady
    ? `${origin}/api/dl?k=${encodeURIComponent(key)}&e=${exp}&h=${fpHash}&s=${sig}` +
      `&f=${encodeURIComponent(fp)}`
    : null


  const directTtl = directTtlFor(size)
  const directPath = await buildDirectUrl(env, key, dlFileName(key), directTtl)


  let mode = want === 'auto' ? (relayFull && !directFull ? 'direct' : 'relay') : want
  if (mode === 'relay' && !relayPath) mode = 'direct'
  if (mode === 'direct' && !directPath) mode = 'relay'
  if (!relayPath && !directPath) {
    return json({ error: '下载服务暂时不可用' }, 503, request, env)
  }










  if (want === 'auto' && mode === 'relay' && directPath) {
    let alive = false
    try {
      const probe = await relayOpen(env, key, 'HEAD')
      const status = probe.status || 0
      alive = !!(probe.reader && status < 500 && status !== 401 && status !== 403)
      if (probe.reader) {
        try { probe.reader.releaseLock() } catch {}
        try { probe.socket.close() } catch {}
      }
    } catch (err) {
      console.error('relay probe error:', err && err.message)
    }
    if (!alive) mode = 'direct'
  }

  const url = mode === 'direct' ? directPath : relayPath


  if (size > 0) {
    const meter = registryOp(env, { op: 'bytes-add', mode, bytes: size })
    if (ctx) ctx.waitUntil(meter)
    else await meter
  }

  return json(
    {
      success: true,
      mode,
      url,
      key,
      size: size || undefined,

      expiresIn: mode === 'direct' ? directTtl : DL_TICKET_TTL,
      dailyLimit: dlDailyLimit(env),
      remaining: gateInfo ? Math.max(0, gateInfo.limit - gateInfo.used) : undefined,
    },
    200,
    request,
    env
  )
}

async function handleDl(request, env) {
  const url = new URL(request.url)
  const key = url.searchParams.get('k') || ''
  const exp = Number(url.searchParams.get('e') || 0)
  const fpHash = url.searchParams.get('h') || ''
  const sig = url.searchParams.get('s') || ''
  const fp = url.searchParams.get('f') || ''

  if (!dlKeyOk(key)) return json({ error: '下载地址无效' }, 400, request, env)
  if (!Number.isFinite(exp) || exp * 1000 < Date.now()) {
    return json({ error: '下载链接已过期，请回站点重新点击下载' }, 410, request, env)
  }
  if (sig !== (await dlTicketSig(env, exp, fpHash, key))) {
    return json({ error: '下载地址无效' }, 403, request, env)
  }
  if (!fp || (await sha256Hex(fp)).slice(0, 16) !== fpHash) {
    return json({ error: '设备校验失败，请回站点重新点击下载' }, 403, request, env)
  }

  const method = request.method === 'HEAD' ? 'HEAD' : 'GET'
  let relay
  try {
    relay = await relayOpen(env, key, method, request.headers.get('Range'))
  } catch (err) {
    console.error('relay error:', err && err.message)
    return json({ error: '下载服务暂时不可用' }, 502, request, env)
  }
  if (!relay.reader) {
    return json({ error: relay.text || '下载失败' }, relay.status || 502, request, env)
  }
  return relayRespond(relay, method, dlFileName(key, url.searchParams.get('n')))
}

function adminOk(request, env) {
  const expect = String(env.PURGE_TOKEN || '')
  return !!expect && request.headers.get('X-Purge-Token') === expect
}

function objectKeyOk(key) {
  return dlKeyOk(key) || iconKeyOk(key)
}

async function purgeOne(env, key, options) {


  if (options && options.onlyRegistry) {
    try {
      await registryOp(env, { op: 'file-del', key })
      return { key, ok: true, registryOnly: true }
    } catch (err) {
      return { key, ok: false, error: err && err.message }
    }
  }
  const relay = await relayOpen(env, key, 'DELETE')
  if (!relay.reader) {
    return { key, ok: false, status: relay.status || 0, error: relay.text || '' }
  }

  let text = new TextDecoder().decode(relay.first)
  while (true) {
    const { value, done } = await relay.reader.read()
    if (done) break
    text += new TextDecoder().decode(value)
  }
  try { relay.socket.close() } catch {}
  const ok = relay.status >= 200 && relay.status < 300
  if (ok) await registryOp(env, { op: 'file-del', key })
  return { key, ok, status: relay.status, body: text.slice(0, 120) }
}

async function handlePurge(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)

  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }

  const keys = []
  if (data?.key) keys.push(String(data.key).trim())
  if (Array.isArray(data?.keys)) for (const k of data.keys) keys.push(String(k || '').trim())

  const prefix = String(data?.prefix || '').trim()
  if (prefix) {
    if (prefix.length < 8 || !/^(?:upload|soft|icon|releases)\//.test(prefix) || prefix.includes('..')) {
      return json(
        { error: 'prefix 非法：只允许 upload/ soft/ icon/ releases/ 之下的路径' },
        400,
        request,
        env
      )
    }

    let listed = null
    try {
      listed = await relayList(env, prefix)
    } catch (err) {
      console.error('purge list error:', err && err.message)
    }
    if (listed === null) {
      return json({ error: '列目录失败（中继不可用或返回异常），未执行任何删除' }, 502, request, env)
    }

    const safe = listed.filter((k) => k.startsWith(prefix) && objectKeyOk(k))
    if (!safe.length) {
      return json(
        { success: true, count: 0, results: [], note: '桶里这个前缀下没有对象' },
        200,
        request,
        env
      )
    }
    if (safe.length > MAX_PURGE_BATCH) {
      return json(
        {
          error: `这个前缀下有 ${safe.length} 个对象，超过一次 ${MAX_PURGE_BATCH} 个的上限；请缩小 prefix 或分批传 keys`,
          count: safe.length,
          deleted: 0,
        },
        400,
        request,
        env
      )
    }
    for (const k of safe) keys.push(k)
  }

  const unique = [...new Set(keys.filter(Boolean))]
  if (!unique.length) return json({ error: '缺少 key / keys / prefix' }, 400, request, env)
  const invalid = unique.filter((k) => !objectKeyOk(k))
  if (invalid.length) {
    return json({ error: 'key 非法', invalid: invalid.slice(0, 5) }, 400, request, env)
  }








  if (data?.requireRegistry) {
    const foreign = []
    for (const k of unique) {
      if ((await registryHas(env, k)) === false) foreign.push(k)
    }
    if (foreign.length) {
      return json(
        { error: 'key 不在登记表里（不是本站签出的对象），已拒绝删除', invalid: foreign.slice(0, 5) },
        400,
        request,
        env
      )
    }
  }

  const results = []
  for (const key of unique) {
    try {
      results.push(await purgeOne(env, key))
    } catch (err) {
      results.push({ key, ok: false, error: err && err.message })
    }
  }
  return json(
    { success: results.every((r) => r.ok), count: results.length, results },
    200,
    request,
    env
  )
}

async function handleFiles(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  const url = new URL(request.url)
  const prefix = url.searchParams.get('prefix') || ''

  if (url.searchParams.get('source') === 'bucket') {
    let objs = null
    try {
      objs = await relayListObjects(env, prefix)
    } catch (err) {
      console.error('files bucket list error:', err && err.message)
    }
    if (objs === null) return json({ error: '列目录失败（中继不可用或返回异常）' }, 502, request, env)

    return json(
      {
        ok: true,
        source: 'bucket',
        prefix,
        count: objs.length,
        keys: objs.map((o) => o.key),
        objects: objs,
      },
      200,
      request,
      env
    )
  }

  const out = await registryOp(env, {
    op: 'file-list',
    prefix,
    limit: Number(url.searchParams.get('limit')) || FILE_LIST_MAX,
    all: url.searchParams.get('all') === '1',
  })
  if (!out) return json({ error: '登记表不可用' }, 503, request, env)
  return json({ ...out, source: 'registry' }, 200, request, env)
}

async function handleDlStats(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  const out = await registryOp(env, { op: 'stats' })
  if (!out) return json({ error: '统计不可用' }, 503, request, env)
  const cfg = await registryCfgGet(env)
  return json(
    {
      ...out,
      mode: await dlModeWanted(env),
      modeSource: cfg && cfg.mode ? 'runtime' : 'env',
      envMode: String(env.DL_MODE || DL_MODE_DEFAULT),
      orphanMinutes: await gcOrphanMinutes(env),
      staleRecordHours: await gcStaleRecordHours(env),
      relayMonthlyGB: Number(env.DL_RELAY_MONTHLY_GB) || 0,
      directMonthlyGB: Number(env.DL_DIRECT_MONTHLY_GB) || 0,


      lastGc: (cfg && cfg.lastGc) || null,
      submitGate: {
        requireSource: pickBool(cfg && cfg.requireSource, env.SUBMIT_REQUIRE_SOURCE, SUBMIT_REQUIRE_SOURCE),
        maxPending: pickNum(cfg && cfg.maxPending, env.SUBMIT_MAX_PENDING, SUBMIT_MAX_PENDING),
        maxPerDay: pickNum(cfg && cfg.maxPerDay, env.SUBMIT_MAX_PER_DAY, SUBMIT_MAX_PER_DAY),
      },
    },
    200,
    request,
    env
  )
}

async function handleOssCheck(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  const base = String(env.OSS_PUBLIC_BASE || '').replace(/\/+$/, '')
  if (!base) return json({ error: '未配置 OSS_PUBLIC_BASE，无法探测' }, 503, request, env)

  const url = new URL(request.url)
  let key = url.searchParams.get('k') || ''
  if (!key) {
    for (const prefix of ['icon/', 'upload/', 'releases/', '']) {
      const objs = await relayListObjects(env, prefix)
      if (objs && objs.length) {
        key = objs[0].key
        break
      }
    }
  }
  if (!key) return json({ ok: false, error: '桶里没有可用对象做探测' }, 409, request, env)

  const target = `${base}/${key.split('/').map(encodeURIComponent).join('/')}`
  let status = 0
  try {
    const res = await fetch(target, { method: 'GET', headers: { Range: 'bytes=0-0' } })
    status = res.status
  } catch (err) {
    return json({ ok: false, error: `探测请求失败：${(err && err.message) || err}` }, 502, request, env)
  }
  const isPrivate = status === 403 || status === 401 || status === 404
  return json(
    {
      ok: true,
      key,
      status,
      private: isPrivate,
      hint: isPrivate
        ? '桶是私有的，匿名直读被拒（预期）'
        : '⚠️ 桶当前可被匿名直读：请把 Bucket ACL 改回 private，并检查有没有给对象设 public-read',
    },
    200,
    request,
    env
  )
}

async function handleDlMode(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)

  if (request.method === 'GET') {
    const cfg = await registryCfgGet(env)
    return json(
      {
        success: true,
        mode: await dlModeWanted(env),
        modeSource: cfg && cfg.mode ? 'runtime' : 'env',
        envMode: String(env.DL_MODE || DL_MODE_DEFAULT),
        orphanMinutes: await gcOrphanMinutes(env),
        staleRecordHours: await gcStaleRecordHours(env),


        requireSource: pickBool(cfg && cfg.requireSource, env.SUBMIT_REQUIRE_SOURCE, SUBMIT_REQUIRE_SOURCE),
        maxPending: pickNum(cfg && cfg.maxPending, env.SUBMIT_MAX_PENDING, SUBMIT_MAX_PENDING),
        maxPerDay: pickNum(cfg && cfg.maxPerDay, env.SUBMIT_MAX_PER_DAY, SUBMIT_MAX_PER_DAY),
        lastGc: (cfg && cfg.lastGc) || null,
        updatedAt: (cfg && cfg.updatedAt) || null,
        options: ['auto', 'relay', 'direct'],
      },
      200,
      request,
      env
    )
  }

  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }



  const patch = {}

  if (data && data.mode !== undefined) {
    const raw = String(data.mode || '').trim().toLowerCase()


    if (raw !== 'auto' && raw !== 'relay' && raw !== 'direct') {
      return json({ error: 'mode 只接受 auto / relay / direct' }, 400, request, env)
    }
    patch.mode = raw
  }

  if (data && data.orphanMinutes !== undefined) {
    const n = Number(data.orphanMinutes)
    if (!Number.isFinite(n) || n < 1 || n > 7 * 24 * 60) {
      return json({ error: 'orphanMinutes 必须是 1 ~ 10080 之间的分钟数' }, 400, request, env)
    }
    patch.orphanMinutes = Math.round(n)
  }

  if (data && data.staleRecordHours !== undefined) {
    const n = Number(data.staleRecordHours)
    if (!Number.isFinite(n) || n < 1 || n > 24 * 365) {
      return json({ error: 'staleRecordHours 必须是 1 ~ 8760 之间的小时数' }, 400, request, env)
    }
    patch.staleRecordHours = Math.round(n)
  }

  if (data && data.maxPending !== undefined) {
    const n = Number(data.maxPending)
    if (!Number.isFinite(n) || n < 0 || n > 100) {
      return json({ error: 'maxPending 必须是 0 ~ 100 之间的整数（0 = 关闭这道闸门）' }, 400, request, env)
    }
    patch.maxPending = Math.round(n)
  }

  if (data && data.maxPerDay !== undefined) {
    const n = Number(data.maxPerDay)
    if (!Number.isFinite(n) || n < 0 || n > 1000) {
      return json({ error: 'maxPerDay 必须是 0 ~ 1000 之间的整数（0 = 关闭这道闸门）' }, 400, request, env)
    }
    patch.maxPerDay = Math.round(n)
  }

  if (data && data.requireSource !== undefined) {
    patch.requireSource = pickBool(data.requireSource, undefined, SUBMIT_REQUIRE_SOURCE)
  }

  if (!Object.keys(patch).length) {
    return json(
      {
        error:
          '没有要改的项。可传 mode / orphanMinutes / staleRecordHours / maxPending / maxPerDay / requireSource',
      },
      400,
      request,
      env
    )
  }

  const saved = await registryCfgSet(env, patch)
  if (!saved) return json({ error: '配置保存失败（DO 不可用）' }, 503, request, env)
  return json(
    { success: true, changed: Object.keys(patch), ...patch, updatedAt: saved.updatedAt || null },
    200,
    request,
    env
  )
}

async function handleLink(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }
  const key = String(data?.key || '').trim()
  if (!objectKeyOk(key)) return json({ error: 'key 非法' }, 400, request, env)
  const ttl = Math.min(Math.max(Number(data?.ttl) || DL_TICKET_TTL, 60), 3600)
  const url = await buildDirectUrl(env, key, dlFileName(key), ttl)
  if (!url) return json({ error: 'OSS 未配置或签名失败' }, 503, request, env)
  return json({ success: true, mode: 'direct', url, key, expiresIn: ttl }, 200, request, env)
}

async function ossPresignCopy(env, fromKey, toKey) {
  const bucket = String(env.OSS_BUCKET).trim()
  const region = String(env.OSS_REGION || 'cn-shanghai').trim()
  const endpoint = String(env.OSS_ENDPOINT || `oss-${region}.aliyuncs.com`).trim()
  const host = `${bucket}.${endpoint}`

  const now = new Date()
  const dateStr = `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}`
  const amzDate = `${dateStr}T${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}Z`
  const credentialScope = `${dateStr}/${region}/oss/aliyun_v4_request`



  const encodeKey = (k) => k.split('/').map(uriEncode).join('/')
  const copySource = `/${bucket}/${encodeKey(fromKey)}`
  const contentType = 'application/octet-stream'

  const query = {
    'x-oss-additional-headers': 'host',
    'x-oss-credential': `${env.OSS_ACCESS_KEY_ID}/${credentialScope}`,
    'x-oss-date': amzDate,
    'x-oss-expires': String(OSS_SIGN_TTL),
    'x-oss-signature-version': OSS_ALGO,
  }
  const canonicalQuery = Object.keys(query)
    .sort()
    .map((k) => `${uriEncode(k)}=${uriEncode(query[k])}`)
    .join('&')

  const canonicalUri = `/${bucket}/${encodeKey(toKey)}`

  const canonicalHeaders =
    `content-type:${contentType}\nhost:${host}\nx-oss-copy-source:${copySource}\n`
  const canonicalRequest = [
    'PUT',
    canonicalUri,
    canonicalQuery,
    canonicalHeaders,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n')

  const stringToSign = [OSS_ALGO, amzDate, credentialScope, await sha256Hex(canonicalRequest)].join('\n')
  const secretBytes = textEncoder.encode(`aliyun_v4${env.OSS_ACCESS_KEY_SECRET}`)
  const kDate = await hmacSha256(secretBytes, dateStr)
  const kRegion = await hmacSha256(kDate, region)
  const kService = await hmacSha256(kRegion, 'oss')
  const kSigning = await hmacSha256(kService, 'aliyun_v4_request')
  const signature = toHex(await hmacSha256(kSigning, stringToSign))

  return {
    url: `https://${host}/${encodeKey(toKey)}?${canonicalQuery}&x-oss-signature=${signature}`,
    headers: { 'content-type': contentType, 'x-oss-copy-source': copySource },
  }
}

async function handlePromote(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  if (!env.OSS_BUCKET || !env.OSS_ACCESS_KEY_ID || !env.OSS_ACCESS_KEY_SECRET) {
    return json({ error: 'OSS 未配置' }, 503, request, env)
  }
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }
  const fromKey = String(data?.key || '').trim()

  if (!/^upload\//.test(fromKey) || !dlKeyOk(fromKey)) {
    return json({ error: 'key 非法：只能迁移 upload/ 之下的对象' }, 400, request, env)
  }


  const base = fromKey.split('/').pop() || 'file'
  const now = new Date()
  const yyyy = String(now.getUTCFullYear())
  const mm = pad2(now.getUTCMonth() + 1)
  const toKey = String(data?.to || '').trim() || `${RELEASE_PREFIX}/${yyyy}/${mm}/${base}`
  if (!dlKeyOk(toKey) || !toKey.startsWith(RELEASE_PREFIX + '/')) {
    return json({ error: 'to 非法：目标必须落在 releases/ 之下' }, 400, request, env)
  }
  if (toKey === fromKey) return json({ error: '源和目标相同' }, 400, request, env)

  try {
    const signed = await ossPresignCopy(env, fromKey, toKey)
    const res = await fetch(signed.url, { method: 'PUT', headers: signed.headers })
    const text = await res.text()
    if (!res.ok) {
      console.error('promote copy failed:', res.status, text.slice(0, 300))
      return json(
        { error: `OSS 复制失败（HTTP ${res.status}）`, detail: text.slice(0, 300) },
        502,
        request,
        env
      )
    }

    const rec = await registryGet(env, fromKey)
    await registryPut(env, {
      key: toKey,
      size: (rec && Number(rec.size)) || 0,
      name: (rec && rec.name) || base,
      ctype: (rec && rec.ctype) || 'application/octet-stream',
      origin: RELEASE_PREFIX,
      fph: (rec && rec.fph) || '',
      ts: Date.now(),
      promotedFrom: fromKey,
      claimed: Date.now(),
      synced: 1,
      deleted: 0,
    })
    return json({ success: true, from: fromKey, to: toKey }, 200, request, env)
  } catch (err) {
    console.error('promote error:', err && err.message)
    return json({ error: `OSS 复制异常：${err && err.message}` }, 502, request, env)
  }
}

async function gcStaleRecordHours(env) {
  const cfg = await registryCfgGet(env)
  const fromCfg = Number(cfg && cfg.staleRecordHours)
  if (Number.isFinite(fromCfg) && fromCfg > 0) return fromCfg
  const fromEnv = Number(env && env.GC_STALE_RECORD_HOURS)
  if (Number.isFinite(fromEnv) && fromEnv > 0) return fromEnv
  return GC_STALE_RECORD_HOURS
}

async function gcOrphanMinutes(env) {
  const cfg = await registryCfgGet(env)
  const fromCfg = Number(cfg && cfg.orphanMinutes)
  if (Number.isFinite(fromCfg) && fromCfg > 0) return fromCfg
  const n = Number(env.GC_ORPHAN_MINUTES)
  return Number.isFinite(n) && n > 0 ? n : GC_ORPHAN_MINUTES
}

async function runGc(env, options) {
  const opts = options || {}
  const dry = opts.dry !== false
  const minutes = Number(opts.minutes) > 0 ? Number(opts.minutes) : await gcOrphanMinutes(env)
  const cutoff = Date.now() - minutes * 60000

  const pool = await registryUnclaimed(env)
  if (pool === null) {
    return { ok: false, error: '登记表不可用，整轮跳过（未做任何删除）' }
  }
  const pending = new Map()
  for (const f of pool) if (f && f.key) pending.set(f.key, f)

  const report = {
    dry,
    minutes,
    scanned: 0,
    pending: pending.size,
    orphan: [],
    deleted: [],
    failed: [],
    skipped: false,

    staleRecords: [],
    droppedRecords: [],
    listingComplete: true,
    staleRecordHours: null,
  }


  const present = new Set()
  let listingComplete = true
  report.listingComplete = true
  for (const prefix of ['upload/', 'icon/']) {
    const page = await relayListDetailed(env, prefix)
    if (page === null) {
      return { ok: false, error: `列桶失败（${prefix}），整轮跳过（未做任何删除）` }
    }
    if (page.truncated) {
      listingComplete = false
      report.listingComplete = false
    }
    report.scanned += page.objects.length
    for (const o of page.objects) {
      present.add(o.key)
      if (!pending.has(o.key)) continue
      const t = Date.parse(o.lastModified)
      if (!Number.isFinite(t)) continue
      if (t > cutoff) continue
      report.orphan.push({
        key: o.key,
        size: o.size,
        lastModified: o.lastModified,
        ageMinutes: Math.floor((Date.now() - t) / 60000),
      })
    }
  }








  const staleRecordHours = await gcStaleRecordHours(env)
  report.staleRecordHours = staleRecordHours
  const staleCutoff = Date.now() - staleRecordHours * 3600000
  if (listingComplete) {
    for (const f of pool) {
      if (!f || !f.key || present.has(f.key)) continue
      if (!Number.isFinite(f.ts) || f.ts > staleCutoff) continue
      report.staleRecords.push({
        key: f.key,
        size: f.size,
        signedAgoHours: Math.floor((Date.now() - f.ts) / 3600000),
      })
    }
    if (!dry) {
      for (const item of report.staleRecords) {
        const r = await purgeOne(env, item.key, { onlyRegistry: true })
        if (r.ok) report.droppedRecords.push(item.key)
        else report.failed.push({ key: item.key, error: r.error || `HTTP ${r.status}` })
      }
    }
  }


  if (report.orphan.length > GC_MAX_DELETE) {
    report.skipped = true
    report.error = `候选 ${report.orphan.length} 个，超过单轮上限 ${GC_MAX_DELETE}，本轮不执行删除`
    return { ok: true, ...report }
  }

  if (!dry) {
    for (const item of report.orphan) {
      const r = await purgeOne(env, item.key)
      if (r.ok) report.deleted.push(item.key)
      else report.failed.push({ key: item.key, error: r.error || `HTTP ${r.status}` })
    }
  }
  return { ok: true, ...report }
}

async function handleGc(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  let data = {}
  try {
    data = (await request.json()) || {}
  } catch {
    data = {}
  }
  const minutes = Number(data?.minutes) || 0
  if (minutes > 0 && data?.persist === true) {
    const saved = await registryCfgSet(env, { orphanMinutes: minutes })
    if (!saved) return json({ error: '配置保存失败（DO 不可用）' }, 503, request, env)
  }
  const out = await runGc(env, {
    dry: data?.dry !== false,
    minutes,
  })
  return json({ ...out, persisted: minutes > 0 && data?.persist === true }, out.ok ? 200 : 503, request, env)
}

async function handleRegistrySync(request, env) {
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  let data = {}
  try {
    data = (await request.json()) || {}
  } catch {
    data = {}
  }
  const dry = data?.dry !== false

  const known = await registryOp(env, { op: 'file-map' })
  if (!known || !Array.isArray(known.files)) {
    return json({ error: '登记表不可用' }, 503, request, env)
  }
  const have = new Set(known.files.filter((f) => f && !f.deleted).map((f) => f.key))

  const bucket = []
  for (const prefix of ['upload/', 'icon/', 'releases/', 'soft/']) {
    const objs = await relayListObjects(env, prefix)
    if (objs === null) {
      return json({ error: `列桶失败（${prefix}），本轮跳过` }, 502, request, env)
    }
    for (const o of objs) bucket.push(o)
  }

  const missing = bucket.filter((o) => !have.has(o.key))
  const ghost = known.files
    .filter((f) => f && !f.deleted && !have.has(f.key))
    .filter((f) => !bucket.some((o) => o.key === f.key))
    .map((f) => f.key)

  const added = []
  if (!dry) {
    for (const o of missing) {
      const origin = o.key.split('/')[0]
      await registryPut(env, {
        key: o.key,
        size: o.size,
        name: o.key.split('/').pop() || '',
        ctype: '',
        origin,
        fph: '',
        ts: Number.isFinite(Date.parse(o.lastModified)) ? Date.parse(o.lastModified) : Date.now(),
        synced: 1,
        deleted: 0,
      })
      added.push(o.key)
    }
  }

  return json(
    {
      ok: true,
      dry,
      bucket: bucket.length,
      registry: have.size,

      missingCount: missing.length,
      missing: missing.slice(0, 50).map((o) => ({ key: o.key, size: o.size, lastModified: o.lastModified })),

      ghostCount: ghost.length,
      ghost: ghost.slice(0, 50),
      added: added.length,
    },
    200,
    request,
    env
  )
}

const KV_FILES = 'gate:files'
const KV_META = 'gate:meta'
const KV_CFG = 'gate:cfg'
const KV_SUBMIT = 'gate:submit'
const KV_HB = 'gate:hb'

let blobKvPromise = null

function blobKey(key) {
  return String(key).split('/').map(encodeURIComponent).join('/')
}

async function blobKv() {
  if (!blobKvPromise) {
    blobKvPromise = (async () => {
      try {
        const mod = await import('@edgeone/pages-blob')
        const store = mod.getStore('csh-state')
        return {
          async get(key) {
            const v = await store.get(blobKey(key), { type: 'text', consistency: 'strong' })
            return v === undefined ? null : v
          },
          async put(key, value) {
            await store.set(blobKey(key), String(value))
          },
          async delete(key) {
            await store.delete(blobKey(key))
          },
        }
      } catch (err) {
        return null
      }
    })()
  }
  return blobKvPromise
}

async function gateKv() {
  if (typeof CSH_STATE !== 'undefined' && CSH_STATE) return CSH_STATE
  return blobKv()
}

async function kvJson(kv, key) {
  const v = await kv.get(key)
  if (v === null || v === undefined) return null
  try { return JSON.parse(v) } catch { return null }
}

async function kvSave(kv, key, value) {
  await kv.put(key, JSON.stringify(value))
}

function alive(v) {
  return !!v && (!Number.isFinite(v._exp) || v._exp > Date.now())
}

function gateDay() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10)
}

function gateMonth() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 7)
}

async function gateSignCheck(kv, body) {
  const day = gateDay()
  const key = 'gate:sg:' + day
  let rec = (await kvJson(kv, key)) || null
  if (!alive(rec) || rec.day !== day) rec = { day, n: 0, bytes: 0, ips: {} }
  const ips = rec.ips && typeof rec.ips === 'object' ? rec.ips : {}
  const src = String(body.ip || 'unknown').slice(0, 32)
  const perIp = Math.max(1, Number(body.perIp) || SIGN_PER_IP_PER_DAY)
  const perDay = Math.max(1, Number(body.perDay) || SIGN_GLOBAL_PER_DAY)
  const bytesCap = Number(body.bytesPerDay)
  const bytes = Math.max(0, Number(body.bytes) || 0)
  const ipN = Number(ips[src]) || 0
  const n = Number(rec.n) || 0
  const used = Number(rec.bytes) || 0
  if (n >= perDay) return { allowed: false, scope: 'global', limit: perDay, used: n, remaining: 0 }
  if (Number.isFinite(bytesCap) && bytesCap > 0 && used + bytes > bytesCap) {
    return { allowed: false, scope: 'global', limit: perDay, used: n, remaining: 0 }
  }
  if (ipN >= perIp) return { allowed: false, scope: 'ip', limit: perIp, used: ipN, remaining: 0 }
  rec.n = n + 1
  rec.bytes = used + bytes
  ips[src] = ipN + 1
  rec.ips = ips
  await kvSave(kv, key, rec)
  if (Math.random() < 0.02) {
    try { await kv.delete('gate:sg:' + new Date(Date.now() - 2 * 86400000).toISOString().slice(0, 10)) } catch {}
  }
  return { allowed: true, used: rec.n, limit: perDay, remaining: Math.max(0, perDay - rec.n) }
}

async function gateQuota(kv, name, body) {
  let limit = DL_DAILY_LIMIT
  if (Number.isFinite(Number(body.limit))) limit = Number(body.limit)
  const day = gateDay()
  const key = 'gate:q:' + String(name).slice(0, 80)
  let rec = (await kvJson(kv, key)) || null
  if (!alive(rec) || rec.day !== day) rec = { day, n: 0 }
  if (rec.n >= limit) return { allowed: false, day, used: rec.n, limit }
  rec.n += 1
  await kvSave(kv, key, rec)
  return { allowed: true, day, used: rec.n, limit }
}

async function gateRegistry(kv, body) {
  const op = String(body.op || '')
  if (op === 'file-put') {
    const rec = body.record || {}
    const key = String(rec.key || '')
    if (!key) return { ok: false, error: 'key 为空' }
    const files = (await kvJson(kv, KV_FILES)) || {}
    const prev = files[key] || null
    files[key] = Object.assign({}, rec, { key })
    await kvSave(kv, KV_FILES, files)
    if (!prev || prev.deleted) {
      const meta = (await kvJson(kv, KV_META)) || { files: 0, icons: 0, pending: 0 }
      meta.files = (Number(meta.files) || 0) + 1
      if (String(rec.origin) === ICON_PREFIX) meta.icons = (Number(meta.icons) || 0) + 1
      if (!rec.claimed && !rec.synced) meta.pending = (Number(meta.pending) || 0) + 1
      meta.updated = Date.now()
      await kvSave(kv, KV_META, meta)
    }
    return { ok: true, key, existed: !!prev }
  }
  if (op === 'file-get') {
    const files = (await kvJson(kv, KV_FILES)) || {}
    return { ok: true, file: files[String(body.key || '')] || null }
  }
  if (op === 'file-del') {
    const files = (await kvJson(kv, KV_FILES)) || {}
    const cur = files[String(body.key || '')]
    if (!cur) return { ok: true, existed: false }
    if (!cur.deleted) {
      files[cur.key] = Object.assign({}, cur, { deleted: 1, deletedAt: Date.now() })
      await kvSave(kv, KV_FILES, files)
      const meta = (await kvJson(kv, KV_META)) || { files: 0, icons: 0, pending: 0 }
      meta.files = Math.max(0, (Number(meta.files) || 0) - 1)
      if (String(cur.origin) === ICON_PREFIX) meta.icons = Math.max(0, (Number(meta.icons) || 0) - 1)
      if (!cur.claimed && !cur.synced) meta.pending = Math.max(0, (Number(meta.pending) || 0) - 1)
      meta.updated = Date.now()
      await kvSave(kv, KV_META, meta)
    }
    return { ok: true, existed: true }
  }
  if (op === 'file-claim') {
    const keys = Array.isArray(body.keys) ? body.keys : []
    const files = (await kvJson(kv, KV_FILES)) || {}
    const claimed = []
    let metaDirty = false
    const meta = (await kvJson(kv, KV_META)) || { files: 0, icons: 0, pending: 0 }
    for (const k of keys) {
      const cur = files[String(k || '')]
      if (!cur || cur.claimed) continue
      files[cur.key] = Object.assign({}, cur, { claimed: Date.now() })
      claimed.push(cur.key)
      if (!cur.deleted && !cur.synced) {
        meta.pending = Math.max(0, (Number(meta.pending) || 0) - 1)
        metaDirty = true
      }
    }
    if (metaDirty) {
      meta.updated = Date.now()
      await kvSave(kv, KV_META, meta)
    }
    await kvSave(kv, KV_FILES, files)
    return { ok: true, claimed }
  }
  if (op === 'unclaimed-list' || op === 'file-map' || op === 'file-list') {
    const files = (await kvJson(kv, KV_FILES)) || {}
    let filesOut = []
    if (op === 'unclaimed-list') {
      for (const k of Object.keys(files)) {
        const v = files[k]
        if (!v || v.deleted || v.claimed || v.synced) continue
        filesOut.push(v)
        if (filesOut.length >= FILE_LIST_MAX) break
      }
    } else if (op === 'file-map') {
      for (const k of Object.keys(files)) {
        if (files[k]) filesOut.push(files[k])
        if (filesOut.length >= FILE_LIST_MAX) break
      }
    } else {
      const pfx = String(body.prefix || '')
      const limit = Math.min(Number(body.limit) || FILE_LIST_MAX, FILE_LIST_MAX)
      for (const k of Object.keys(files)) {
        if (!k.startsWith(pfx)) continue
        const v = files[k]
        if (!body.all && v.deleted) continue
        filesOut.push(v)
      }
      filesOut.sort((a, b) => (b.ts || 0) - (a.ts || 0))
      filesOut = filesOut.slice(0, limit)
    }
    return { ok: true, count: filesOut.length, files: filesOut }
  }
  if (op === 'bytes-add') {
    const mode = body.mode === 'direct' ? 'direct' : 'relay'
    const bytes = Math.max(0, Number(body.bytes) || 0)
    const month = gateMonth()
    const key = 'gate:m:' + month
    let rec = (await kvJson(kv, key)) || null
    if (!alive(rec) || rec.month !== month) rec = { month, relay: 0, direct: 0 }
    rec[mode] = (Number(rec[mode]) || 0) + bytes
    await kvSave(kv, key, rec)
    return { ok: true, month, relay: rec.relay, direct: rec.direct }
  }
  if (op === 'stats') {
    const month = gateMonth()
    const used = (await kvJson(kv, 'gate:m:' + month)) || {}
    const meta = (await kvJson(kv, KV_META)) || { files: 0, icons: 0, pending: 0 }
    return {
      ok: true,
      month,
      relay: Number(used.relay) || 0,
      direct: Number(used.direct) || 0,
      files: Number(meta.files) || 0,
      icons: Number(meta.icons) || 0,
      pending: Number(meta.pending) || 0,
    }
  }
  if (op === 'cfg-get') {
    const cfg = (await kvJson(kv, KV_CFG)) || null
    return { ok: true, cfg }
  }
  if (op === 'cfg-set') {
    const cur = (await kvJson(kv, KV_CFG)) || {}
    const patch = body.cfg || {}
    const next = Object.assign({}, cur)
    for (const k of Object.keys(patch)) {
      if (patch[k] === null || patch[k] === undefined) delete next[k]
      else next[k] = patch[k]
    }
    next.updatedAt = Date.now()
    await kvSave(kv, KV_CFG, next)
    return { ok: true, cfg: next, updatedAt: next.updatedAt }
  }
  if (op === 'submit-tick') {
    const sid = String(body.sid || '').slice(0, 32)
    if (!sid) return { ok: false, error: 'sid 为空' }
    const blob = (await kvJson(kv, KV_SUBMIT)) || {}
    const now = Date.now()
    const prev = blob[sid] || { ts: [] }
    const ts = (Array.isArray(prev.ts) ? prev.ts : []).filter(
      (t) => Number.isFinite(t) && now - t < SUBMIT_WINDOW_MS
    )
    ts.push(now)
    blob[sid] = { ts, updated: now }
    for (const k of Object.keys(blob)) {
      if (!blob[k] || !Number.isFinite(blob[k].updated) || now - blob[k].updated > 30 * 86400000) delete blob[k]
    }
    await kvSave(kv, KV_SUBMIT, blob)
    return { ok: true, used: ts.length }
  }
  if (op === 'submit-prune') {
    const days = Number(body.days) > 0 ? Number(body.days) : 30
    const cutoff = Date.now() - days * 86400000
    const blob = (await kvJson(kv, KV_SUBMIT)) || {}
    let removed = 0
    for (const k of Object.keys(blob)) {
      if (!blob[k] || !Number.isFinite(blob[k].updated) || blob[k].updated < cutoff) {
        delete blob[k]
        removed += 1
      }
    }
    if (removed) await kvSave(kv, KV_SUBMIT, blob)
    return { ok: true, removed }
  }
  return { ok: false, error: 'unknown op' }
}

async function gateAnn(kv, body) {
  const op = String(body.op || '')
  const pairCode = String(body.pairCode || '')
  if (op === 'ann-send') {
    const rateKey = 'gate:ann:r:' + pairCode
    const prev = (await kvJson(kv, rateKey)) || null
    if (alive(prev) && Number.isFinite(prev.t) && Date.now() - prev.t < ANN_RATE_MS) {
      return { ok: false, error: 'rate_limited' }
    }
    const regKey = 'gate:ann:d:' + pairCode
    const reg = (await kvJson(kv, regKey)) || {}
    const cutoff = Date.now() - ANN_BIND_TTL * 1000
    for (const dev of Object.keys(reg)) {
      const v = reg[dev]
      const t = v && typeof v === 'object' ? v.t : v
      if (!Number.isFinite(t) || t < cutoff) delete reg[dev]
    }
    await kvSave(kv, regKey, reg)
    let targets
    if (Array.isArray(body.targets)) {
      targets = [...new Set(body.targets.map(String).filter((t) => reg[t]))]
      if (targets.length === 0) return { ok: false, error: 'no_device' }
    } else {
      targets = Object.keys(reg)
      if (targets.length === 0) return { ok: false, error: 'no_device' }
    }
    await kvSave(kv, rateKey, { t: Date.now() })
    await kvSave(kv, 'gate:ann:m:' + pairCode, {
      _exp: Date.now() + ANN_TTL * 1000,
      id: String(body.id || ''),
      text: String(body.text || ''),
      from: String(body.from || ''),
      duration: Number(body.duration) || ANN_DURATION_DEFAULT,
      ts: Date.now(),
      targets,
      consumed: {},
    })
    return { ok: true, devices: targets.length, skipped: body.targets ? body.targets.length - targets.length : 0 }
  }
  if (op === 'ann-poll') {
    const deviceId = String(body.deviceId || '')
    const regKey = 'gate:ann:d:' + pairCode
    const reg = (await kvJson(kv, regKey)) || {}
    reg[deviceId] = { t: Date.now(), n: String(body.name || '').slice(0, 32) }
    await kvSave(kv, regKey, reg)
    const msgKey = 'gate:ann:m:' + pairCode
    const msg = await kvJson(kv, msgKey)
    if (!alive(msg)) {
      if (msg) { try { await kv.delete(msgKey) } catch {} }
      return { ok: true, msg: null }
    }
    if (Array.isArray(msg.targets) && !msg.targets.includes(deviceId)) return { ok: true, msg: null }
    if (msg.consumed && msg.consumed[deviceId]) return { ok: true, msg: null }
    if (!msg.consumed) msg.consumed = {}
    msg.consumed[deviceId] = true
    const tgt = Array.isArray(msg.targets) && msg.targets.length ? msg.targets : [deviceId]
    if (Object.keys(msg.consumed).length >= tgt.length) {
      try { await kv.delete(msgKey) } catch {}
    } else {
      await kvSave(kv, msgKey, msg)
    }
    return { ok: true, msg }
  }
  if (op === 'ann-list') {
    const regKey = 'gate:ann:d:' + pairCode
    const reg = (await kvJson(kv, regKey)) || {}
    const cutoff = Date.now() - ANN_BIND_TTL * 1000
    const devices = []
    for (const [dev, v] of Object.entries(reg)) {
      const t = v && typeof v === 'object' ? v.t : v
      if (!Number.isFinite(t) || t < cutoff) {
        delete reg[dev]
        continue
      }
      devices.push({ id: dev, name: v && typeof v === 'object' ? String(v.n || '') : '', ts: t })
    }
    await kvSave(kv, regKey, reg)
    devices.sort((a, b) => b.ts - a.ts)
    return { ok: true, devices }
  }
  return { ok: false, error: 'unknown op' }
}

async function gateDispatch(kv, name, body) {
  const op = String(body.op || 'check')
  if (name === ANN_ID) return gateAnn(kv, body)
  if (op === 'sign-check') return gateSignCheck(kv, body)
  if (name === REGISTRY_ID) return gateRegistry(kv, body)
  return gateQuota(kv, name, body)
}

function makeGate(kv) {
  if (!kv) return null
  const makeStub = (name) => ({
    async fetch(_url, init) {
      let body = {}
      try { body = JSON.parse((init && init.body) || '{}') } catch {}
      let out
      try {
        out = await gateDispatch(kv, name, body)
      } catch (err) {
        out = { ok: false, error: String((err && err.message) || err).slice(0, 120) }
      }
      return new Response(JSON.stringify(out || { ok: false }), {
        headers: { 'content-type': 'application/json' },
      })
    },
  })
  return {
    idFromName(name) { return makeStub(name) },
    get(stub) { return stub },
  }
}

function iconKeyOk(key) {
  if (typeof key !== 'string') return false
  if (key.length < 6 || key.length > 300) return false
  if (!key.startsWith(ICON_PREFIX + '/')) return false
  if (key.includes('..') || key.includes('//')) return false
  if (/[\u0000-\u001f\u007f\\]/.test(key)) return false
  return true
}

async function handleIcon(request, env, ctx) {
  const url = new URL(request.url)
  const key = url.searchParams.get('k') || ''
  if (!iconKeyOk(key)) return json({ error: '图标地址无效' }, 400, request, env)

  const method = request.method === 'HEAD' ? 'HEAD' : 'GET'






  const cache = globalThis.caches && globalThis.caches.default
  const cacheKey = new Request(`https://icon.cache.invalid/?k=${encodeURIComponent(key)}`)
  if (ctx && cache) {
    try {
      const hit = await cache.match(cacheKey)
      if (hit) {
        const headers = new Headers(hit.headers)
        headers.set('X-Icon-Cache', 'HIT')
        return new Response(method === 'HEAD' ? null : hit.body, { status: hit.status, headers })
      }
    } catch (err) {

      console.error('icon cache read error:', err && err.message)
    }
  }

  let relay
  try {
    relay = await relayOpen(env, key, method, request.headers.get('Range'))
  } catch (err) {
    console.error('icon relay error:', err && err.message)
    return json({ error: '图标服务暂时不可用' }, 502, request, env)
  }
  if (!relay.reader) return json({ error: relay.text || '图标不存在' }, relay.status || 502, request, env)

  const size = Number(relay.headers['content-length'] || 0)
  if (size > ICON_MAX_BYTES) {
    try { relay.reader.releaseLock() } catch {}
    try { relay.socket.close() } catch {}
    return json({ error: '图标文件过大' }, 413, request, env)
  }

  const res = relayRespond(relay, method, null)
  const headers = new Headers(res.headers)
  headers.set('Cache-Control', `public, max-age=${ICON_EDGE_TTL}, immutable`)
  headers.set('Access-Control-Allow-Origin', '*')



  headers.set('X-Content-Type-Options', 'nosniff')
  headers.set('Content-Security-Policy', "default-src 'none'; sandbox")


  headers.set('Content-Type', DEFAULT_CONTENT_TYPE)

  if (method === 'HEAD') {
    return new Response(null, { status: res.status, headers })
  }



  const body = await res.arrayBuffer()






  const sniffed = sniffImage(body)
  if (!sniffed) {
    return json({ error: '不是受支持的图片格式（只收 PNG / JPEG / GIF / WebP / BMP / ICO）' }, 415, request, env)
  }
  headers.set('Content-Type', sniffed)

  if (ctx && cache && res.status === 200) {
    const cacheHeaders = new Headers(headers)
    cacheHeaders.delete('X-Icon-Cache')
    ctx.waitUntil(
      cache.put(cacheKey, new Response(body, { status: 200, headers: cacheHeaders })).catch((err) => {
        console.error('icon cache write error:', err && err.message)
      })
    )
  }

  headers.set('X-Icon-Cache', 'MISS')
  return new Response(body, { status: res.status, headers })
}

async function announceOp(env, payload) {
  if (!env.DL_GATE) return null
  try {
    const id = env.DL_GATE.idFromName(ANN_ID)
    const res = await env.DL_GATE.get(id).fetch('https://dl-gate/op', {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    return await res.json()
  } catch (err) {
    console.error('announce op error:', err && err.message)
    return null
  }
}

async function handleAnnounceSend(request, env) {
  let data
  try {
    data = await request.json()
  } catch {
    return json({ error: 'bad_request' }, 400, request, env)
  }

  const pairCode = String(data?.pairCode || '').trim()
  const text = String(data?.text || '').trim()
  const from = String(data?.from || '').trim()
  let duration = Number(data?.duration) || ANN_DURATION_DEFAULT

  if (!/^\d{6}$/.test(pairCode)) return json({ error: 'bad_request' }, 400, request, env)
  if (!text || text.length > ANN_TEXT_MAX) {
    return json({ error: 'bad_request' }, 400, request, env)
  }
  if (from.length > ANN_FROM_MAX) return json({ error: 'bad_request' }, 400, request, env)
  if (!(duration >= ANN_DURATION_MIN && duration <= ANN_DURATION_MAX)) {
    duration = ANN_DURATION_DEFAULT
  }

  const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`


  const targets = Array.isArray(data?.targets)
    ? data.targets.map((t) => String(t).trim()).filter((t) => /^[0-9a-f]{16,64}$/i.test(t))
    : undefined
  const out = await announceOp(env, { op: 'ann-send', pairCode, text, from, duration, id, targets })
  if (!out) return json({ error: 'internal' }, 500, request, env)
  if (out.ok) return json({ ok: true, id, devices: out.devices || 0 }, 200, request, env)
  if (out.error === 'rate_limited') return json({ error: 'rate_limited' }, 429, request, env)
  if (out.error === 'no_device') return json({ error: 'no_device' }, 403, request, env)
  return json({ error: 'internal' }, 500, request, env)
}

async function handleAnnouncePoll(request, env) {
  const url = new URL(request.url)
  const deviceId = (url.searchParams.get('deviceId') || '').trim()
  const pairCode = (url.searchParams.get('pairCode') || '').trim()
  const name = (url.searchParams.get('name') || '').trim().slice(0, 32)
  if (!/^[0-9a-f]{16,64}$/i.test(deviceId) || !/^\d{6}$/.test(pairCode)) {
    return json({ error: 'bad_request' }, 400, request, env)
  }

  const out = await announceOp(env, { op: 'ann-poll', deviceId, pairCode, name })
  if (!out) return json({ error: 'internal' }, 500, request, env)
  if (!out.ok) {
    return json({ error: out.error || 'unknown_pair' }, 403, request, env)
  }
  if (!out.msg) return new Response(null, { status: 204, headers: corsHeaders(request, env) })
  return json(
    {
      id: out.msg.id,
      text: out.msg.text,
      from: out.msg.from,
      duration: out.msg.duration,
      ts: out.msg.ts,
    },
    200,
    request,
    env
  )
}

async function handleAnnounceList(request, env) {
  const url = new URL(request.url)
  const pairCode = (url.searchParams.get('pairCode') || '').trim()
  if (!/^\d{6}$/.test(pairCode)) return json({ error: 'bad_request' }, 400, request, env)

  const out = await announceOp(env, { op: 'ann-list', pairCode })
  if (!out) return json({ error: 'internal' }, 500, request, env)
  return json({ ok: true, devices: out.devices || [] }, 200, request, env)
}

async function workerFetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(request, env) })
    }

    const url = new URL(request.url)

    if (url.pathname === '/api/status' && request.method === 'GET') return handleStatus(request, env)
    if (url.pathname === '/api/submit' && request.method === 'POST') {
      return handleSubmit(request, env)
    }
    if (url.pathname === '/api/echocave' && request.method === 'POST') {
      return handleEchoCave(request, env)
    }
    if (url.pathname === '/api/feedback' && request.method === 'POST') {
      return handleFeedback(request, env)
    }
    if (url.pathname === '/api/oss-sign' && request.method === 'POST') {
      return handleOssSign(request, env, ctx)
    }
    if (url.pathname === '/api/mirror-sign' && request.method === 'GET') {
      return handleMirrorSign(request, env)
    }
    if (url.pathname === '/api/icon' && (request.method === 'GET' || request.method === 'HEAD')) {
      return handleIcon(request, env, ctx)
    }
    if (url.pathname === '/api/dl-ticket' && request.method === 'POST') {
      return handleDlTicket(request, env, ctx)
    }
    if (url.pathname === '/api/dl' && (request.method === 'GET' || request.method === 'HEAD')) {
      return handleDl(request, env)
    }
    if (url.pathname === '/api/purge' && request.method === 'POST') {
      return handlePurge(request, env)
    }

    if (url.pathname === '/api/files' && request.method === 'GET') {
      return handleFiles(request, env)
    }
    if (url.pathname === '/api/dl-stats' && request.method === 'GET') {
      return handleDlStats(request, env)
    }
    if (url.pathname === '/api/link' && request.method === 'POST') {
      return handleLink(request, env)
    }
    if (url.pathname === '/api/promote' && request.method === 'POST') {
      return handlePromote(request, env)
    }
    if (url.pathname === '/api/gc' && request.method === 'POST') {
      return handleGc(request, env)
    }
    if (url.pathname === '/api/registry-sync' && request.method === 'POST') {
      return handleRegistrySync(request, env)
    }
    if (url.pathname === '/api/dl-mode' && (request.method === 'GET' || request.method === 'POST')) {
      return handleDlMode(request, env)
    }
    if (url.pathname === '/api/oss-check' && request.method === 'GET') {
      return handleOssCheck(request, env)
    }
    if (url.pathname === '/api/announce/send' && request.method === 'POST') {
      return handleAnnounceSend(request, env)
    }
    if (url.pathname === '/api/announce/poll' && request.method === 'GET') {
      return handleAnnouncePoll(request, env)
    }
    if (url.pathname === '/api/announce/list' && request.method === 'GET') {
      return handleAnnounceList(request, env)
    }

    return json({ error: 'Not Found' }, 404, request, env)
}

async function handleStatus(request, env) {
  const started = Date.now()
  const kv = await gateKv()
  const out = { ok: true, time: new Date().toISOString(), runtime: 'edgeone-pages', services: {}, stats: null, lastGc: null }
  out.services.kv = false
  if (kv) {
    try {
      await kvSave(kv, KV_HB, { t: started })
      const hb = await kvJson(kv, KV_HB)
      out.services.kv = !!(hb && hb.t === started)
    } catch (err) {
      out.kvError = String((err && err.message) || err).slice(0, 160)
    }
  }
  out.services.ossConfig = !!(env.OSS_ACCESS_KEY_ID && env.OSS_ACCESS_KEY_SECRET && env.OSS_BUCKET)
  out.services.signConfig = !!env.SIGN_API_KEY
  out.services.githubConfig = !!(env.GITHUB_TOKEN && env.GITHUB_OWNER && env.GITHUB_REPO)
  try {
    const t0 = Date.now()
    const l = await relayListDetailed(env, 'icon/')
    out.services.oss = l !== null
    out.ossProbeMs = Date.now() - t0
    out.ossObjectsProbed = l ? l.objects.length : 0
  } catch (err) {
    out.services.oss = false
  }
  try {
    const r = await fetch('https://api.github.com/rate_limit', {
      headers: { 'User-Agent': 'csh-status' },
    })
    out.services.githubApi = r.ok
  } catch (err) {
    out.services.githubApi = false
  }
  try {
    const s = await registryOp(env, { op: 'stats' })
    if (s && s.ok) out.stats = { files: s.files, icons: s.icons, pending: s.pending, month: s.month, relay: s.relay, direct: s.direct }
  } catch (err) {}
  try {
    const c = await registryOp(env, { op: 'cfg-get' })
    if (c && c.cfg) out.lastGc = c.cfg.lastGc || null
  } catch (err) {}
  const checks = [out.services.kv, out.services.oss, out.services.githubApi]
  out.ok = checks.every(Boolean)
  out.ms = Date.now() - started
  return json(out, out.ok ? 200 : 503, request, env)
}

export async function onRequest(context) {
  const env = Object.assign({}, context.env || {})
  const kv = await gateKv()
  env.DL_GATE = makeGate(kv)
  const ctx = {
    waitUntil(p) {
      if (context.waitUntil) context.waitUntil(Promise.resolve(p).catch(() => {}))
    },
  }
  const req = context.request
  try {
    if (kv && req.method === 'POST') {
      const u = new URL(req.url)
      if (u.pathname === '/api/dl-ticket') {
        const cfg = (await kvJson(kv, KV_CFG)) || {}
        const last = (cfg.lastGc && Number(cfg.lastGc.at)) || 0
        if (Date.now() - last > 20 * 60 * 1000) {
          cfg.lastGc = { at: Date.now(), lazy: true }
          await kvSave(kv, KV_CFG, cfg)
          ctx.waitUntil(runGc(env, { dry: false }).catch(() => {}))
        }
      }
    }
  } catch (err) {}
  return workerFetch(req, env, ctx)
}
