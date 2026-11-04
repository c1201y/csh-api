
// 必须与站点 软件数据/categories.json 的 key 保持一致（2026-10 前端改版后为以下六类）
const CATEGORIES = ['classroom', 'office', 'system', 'media', 'network', 'utility']

// 下载项 kind 白名单，与站点 downloadLink.ts 的 DECLARED 一致；
// 不在白名单内的值不入库，详情页会按链接自动推断
const DOWNLOAD_KINDS = ['file', 'store', 'netdisk', 'page']

// 投稿「系统」多选：platforms 是平台 key 数组（与站点 软件数据/platforms.json 对齐），
// 首页「系统」筛选直接用；_系统版本 是审核用元数据（平台 key → 版本 key 数组），
// 审核合并进站点数据时会被 review-submission.yml 剥掉，不会污染软件数据
const PLATFORM_KEY_RE = /^[a-z0-9][a-z0-9.-]{0,30}$/
const MAX_PLATFORMS_PER_APP = 16
const MAX_VERSIONS_PER_PLATFORM = 32
const PLATFORMS_JSON_PATH = '软件数据/platforms.json'

const ECHO_MAX_LEN = 200
const ECHO_MARKER = '回声洞'

// 回声洞 / 反馈的每来源每日上限：两者都会在 GitHub 仓库落提交，不设限会被刷成垃圾
const ECHO_MAX_PER_DAY = 10
const FEEDBACK_MAX_PER_DAY = 10

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

async function dlDailyLimit(env, S) {
  const values = S || (await settingsOf(env))
  return Number(values.dlDailyLimit) >= 0 ? Number(values.dlDailyLimit) : DL_DAILY_LIMIT
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
const ANN_SEND_PER_MIN = 20

const ANN_DURATION_MIN = 10
const ANN_DURATION_MAX = 120
const ANN_DURATION_DEFAULT = 30

// 单个配对码下最多登记的在线设备数（机房一班 60 台够用），防随机设备码撑大注册表
const ANN_PAIR_DEVICE_MAX = 128

// 每来源每天最多新建多少个配对码注册表：pairCode 只有 6 位，不设限可被刷出百万个 KV 键
const ANN_NEW_PAIR_PER_IP_DAY = 100

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
 * 生成 OSS **POST Policy** 上传表单（V4）。
 *
 * 预签名 PUT 的 Content-Length 无法进入签名，客户端可声明 1 字节再传 2.5GB。
 * POST Policy 的 `content-length-range` 由 OSS 在上传时强制校验，是唯一能在
 * 落盘前绑定大小的方式。字段以表单形式返回，旧客户端仍可用 url 走 PUT。
 */
async function ossPresignPost(env, key, contentType, maxBytes, expiresIn) {
  const bucket = String(env.OSS_BUCKET).trim()
  const region = String(env.OSS_REGION || 'cn-shanghai').trim()
  const endpoint = String(env.OSS_ENDPOINT || `oss-${region}.aliyuncs.com`).trim()
  const host = `${bucket}.${endpoint}`

  const now = new Date()
  const dateStr = `${now.getUTCFullYear()}${pad2(now.getUTCMonth() + 1)}${pad2(now.getUTCDate())}`
  const amzDate = `${dateStr}T${pad2(now.getUTCHours())}${pad2(now.getUTCMinutes())}${pad2(now.getUTCSeconds())}Z`
  const credential = `${env.OSS_ACCESS_KEY_ID}/${dateStr}/${region}/oss/aliyun_v4_request`

  const policy = {
    expiration: new Date(Date.now() + expiresIn * 1000).toISOString(),
    conditions: [
      ['eq', '$key', key],
      ['eq', '$Content-Type', contentType],
      ['content-length-range', 1, Math.max(1, Math.floor(maxBytes))],
      { 'x-oss-signature-version': OSS_ALGO },
      { 'x-oss-credential': credential },
      { 'x-oss-date': amzDate },
    ],
  }
  const policyB64 = toBase64(JSON.stringify(policy))

  const secretBytes = textEncoder.encode(`aliyun_v4${env.OSS_ACCESS_KEY_SECRET}`)
  const kDate = await hmacSha256(secretBytes, dateStr)
  const kRegion = await hmacSha256(kDate, region)
  const kService = await hmacSha256(kRegion, 'oss')
  const kSigning = await hmacSha256(kService, 'aliyun_v4_request')
  const signature = toHex(await hmacSha256(kSigning, policyB64))

  return {
    host: `https://${host}`,
    fields: {
      key,
      policy: policyB64,
      'x-oss-signature-version': OSS_ALGO,
      'x-oss-credential': credential,
      'x-oss-date': amzDate,
      'x-oss-signature': signature,
      'Content-Type': contentType,
      success_action_status: '200',
    },
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

/** 平台 key 归一化：小写、去重、限量；非数组按「旧版投稿」处理返回空数组 */
function normalizePlatforms(raw) {
  if (!Array.isArray(raw)) return []
  const out = []
  for (const item of raw) {
    const key = typeof item === 'string' ? item.trim().toLowerCase() : ''
    if (!key || out.includes(key)) continue
    out.push(key)
    if (out.length >= MAX_PLATFORMS_PER_APP) break
  }
  return out
}

/**
 * 读取站点 软件数据/platforms.json 拿到已定义的平台 key 集合。
 * 任何失败（网络/文件不存在/JSON 坏）都返回 null，由调用方跳过核对——
 * 形状校验已经过 gate，这里只是防乱填 key 污染首页筛选的兜底。
 */
async function knownPlatformKeys(env) {
  try {
    const apiBase = `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/contents`
    const res = await fetch(`${apiBase}/${encodePath(PLATFORMS_JSON_PATH)}?ref=${env.GITHUB_BRANCH}`, {
      headers: githubHeaders(env),
    })
    if (!res.ok) return null
    const info = await res.json()
    const list = JSON.parse(atob(String(info.content || '').replace(/\s/g, '')))
    if (!Array.isArray(list)) return null
    return new Set(list.map((item) => item && item.key).filter((key) => typeof key === 'string'))
  } catch (err) {
    console.error('platforms.json fetch failed:', err && err.message)
    return null
  }
}

/** _系统版本 落库前的清洗：只保留已选平台下的合法版本 key，空结果返回 null */
function sanitizePlatformMeta(raw, allowedPlatforms) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const out = {}
  for (const [pk, versions] of Object.entries(raw)) {
    if (!PLATFORM_KEY_RE.test(pk)) continue
    if (allowedPlatforms.length && !allowedPlatforms.includes(pk)) continue
    if (!Array.isArray(versions)) continue
    const list = []
    for (const v of versions) {
      const key = typeof v === 'string' ? v.trim().toLowerCase() : ''
      if (!key || !PLATFORM_KEY_RE.test(key) || list.includes(key)) continue
      list.push(key)
      if (list.length >= MAX_VERSIONS_PER_PLATFORM) break
    }
    if (list.length) out[pk] = list
  }
  return Object.keys(out).length ? out : null
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

// ── 可调参数 ───────────────────────────────────────────────────────────
//
// 生效值 = 出厂默认（可被同名环境变量覆盖）→ 后台在 `/admin` 里保存的覆盖层。
// 环境变量仍然是“出厂值”，后台改的是覆盖层，可以逐项或整体还原。
//
// 字段结构：{ key, group, label, type, def(env), min, max, unit, options, hint }
// type: num | bool | text | iso | enum

const SETTINGS_KEY = 'cfg:settings'
const SETTINGS_CACHE_MS = 15 * 1000

const SETTING_GROUPS = [
  { id: 'download', title: '下载与分发', hint: '下载票据、上传签名与流量配额' },
  { id: 'submit', title: '投稿与审核', hint: '软件投稿的频次与待审上限' },
  { id: 'community', title: '社区内容', hint: '回声洞与反馈的每日额度，两者都会在 GitHub 仓库落提交' },
  { id: 'announce', title: '教室喊话', hint: '文本长度、在线注册表规模与限频' },
  { id: 'reputation', title: '设备信誉', hint: '按设备码计的上限：超限 429，封禁优先' },
  { id: 'license', title: '授权与激活', hint: '激活有效期、授权闸门与设备登记' },
  { id: 'admin', title: '后台与安全', hint: '会话时长、登录失败锁定' },
]

const SETTING_FIELDS = [
  {
    key: 'dlDailyLimit',
    group: 'download',
    label: '每设备每日下载次数',
    type: 'num',
    min: 0,
    max: 10000,
    unit: '次',
    def: (env) => pickNum(null, env.DL_DAILY_LIMIT, DL_DAILY_LIMIT),
    hint: '同一台设备 24 小时内最多取几次下载票据，0 表示不限。',
  },
  {
    key: 'dlTicketMinutes',
    group: 'download',
    label: '下载票据有效期',
    type: 'num',
    min: 5,
    max: 240,
    unit: '分钟',
    def: () => Math.round(DL_TICKET_TTL / 60),
    hint: '票据与直链同一时间过期。调长会让被转发链接的风险窗口变大。',
  },
  {
    key: 'dlMode',
    group: 'download',
    label: '下载通道',
    type: 'enum',
    options: ['auto', 'relay', 'direct'],
    def: (env) => String(env.DL_MODE || DL_MODE_DEFAULT).toLowerCase(),
    hint: 'auto 优先直连 OSS；relay 强制走中继；direct 只签直链。',
  },
  {
    key: 'signPerIpPerDay',
    group: 'download',
    label: '每来源每日上传签名',
    type: 'num',
    min: 1,
    max: 1000,
    unit: '次',
    def: (env) => pickNum(null, env.SIGN_PER_IP_PER_DAY, SIGN_PER_IP_PER_DAY),
    hint: '上传前取直传签名的次数上限，按来源 IP 计。',
  },
  {
    key: 'signGlobalPerDay',
    group: 'download',
    label: '全局每日上传签名',
    type: 'num',
    min: 1,
    max: 100000,
    unit: '次',
    def: (env) => pickNum(null, env.SIGN_GLOBAL_PER_DAY, SIGN_GLOBAL_PER_DAY),
    hint: '所有来源合计的每日上传签名上限。',
  },
  {
    key: 'signGlobalGbPerDay',
    group: 'download',
    label: '全局每日上送流量',
    type: 'num',
    min: 1,
    max: 2000,
    unit: 'GB',
    def: (env) =>
      Math.round(pickNum(null, env.SIGN_GLOBAL_BYTES_PER_DAY, SIGN_GLOBAL_BYTES_PER_DAY) / 1073741824),
    hint: '每日上传总量上限，防止被当成免费网盘。',
  },
  {
    key: 'submitMaxPerDay',
    group: 'submit',
    label: '每设备每日投稿',
    type: 'num',
    min: 0,
    max: 200,
    unit: '次',
    def: (env) => pickNum(null, env.SUBMIT_MAX_PER_DAY, SUBMIT_MAX_PER_DAY),
    hint: '同一台设备 24 小时内最多提交几次，0 表示不限。',
  },
  {
    key: 'submitMaxPending',
    group: 'submit',
    label: '每设备待审上限',
    type: 'num',
    min: 0,
    max: 100,
    unit: '条',
    def: (env) => pickNum(null, env.SUBMIT_MAX_PENDING, SUBMIT_MAX_PENDING),
    hint: '同设备同时挂起多少条待审投稿后拒绝新提交，0 表示不限。',
  },
  {
    key: 'submitRequireSource',
    group: 'submit',
    label: '强制要求安装包或仓库',
    type: 'bool',
    def: (env) => pickBool(null, env.SUBMIT_REQUIRE_SOURCE, SUBMIT_REQUIRE_SOURCE),
    hint: '打开时只填外链的投稿会被拒绝。',
  },
  {
    key: 'echoMaxPerDay',
    group: 'community',
    label: '回声洞每日条数',
    type: 'num',
    min: 0,
    max: 200,
    unit: '条',
    def: () => ECHO_MAX_PER_DAY,
    hint: '每来源每天最多投几张字条，0 表示不限。',
  },
  {
    key: 'echoMaxLen',
    group: 'community',
    label: '回声洞字数上限',
    type: 'num',
    min: 20,
    max: 2000,
    unit: '字',
    def: () => ECHO_MAX_LEN,
    hint: '单张字条允许的最大字数。',
  },
  {
    key: 'feedbackMaxPerDay',
    group: 'community',
    label: '反馈每日条数',
    type: 'num',
    min: 0,
    max: 200,
    unit: '条',
    def: () => FEEDBACK_MAX_PER_DAY,
    hint: '每来源每天最多提交几条反馈，0 表示不限。',
  },
  {
    key: 'annTextMax',
    group: 'announce',
    label: '喊话字数上限',
    type: 'num',
    min: 10,
    max: 500,
    unit: '字',
    def: () => ANN_TEXT_MAX,
    hint: '客户端与后台共用这个上限。',
  },
  {
    key: 'annTtlSec',
    group: 'announce',
    label: '喊话保留时长',
    type: 'num',
    min: 10,
    max: 3600,
    unit: '秒',
    def: () => ANN_TTL,
    hint: '一条喊话在存储里保留多久；超过仍未被取走就丢弃。',
  },
  {
    key: 'annRateSec',
    group: 'announce',
    label: '喊话最小间隔',
    type: 'num',
    min: 0,
    max: 3600,
    unit: '秒',
    def: () => Math.round(ANN_RATE_MS / 1000),
    hint: '同一配对码两次发送之间的冷却时间，0 表示不限（后台发送不受此限）。',
  },
  {
    key: 'annPairDeviceMax',
    group: 'announce',
    label: '单配对码在线设备上限',
    type: 'num',
    min: 1,
    max: 1024,
    unit: '台',
    def: () => ANN_PAIR_DEVICE_MAX,
    hint: '一个配对码最多登记多少台设备，超过后新设备返回「已满」。',
  },
  {
    key: 'annNewPairPerIpDay',
    group: 'announce',
    label: '每来源每日新建配对码',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '个',
    def: () => ANN_NEW_PAIR_PER_IP_DAY,
    hint: '配对码只有 6 位，这个配额挡住用随机码刷出大量注册表。',
  },
  {
    key: 'repDlTicketMin',
    group: 'reputation',
    label: '下载票据 · 每分钟',
    type: 'num',
    min: 1,
    max: 100000,
    unit: '次',
    def: () => 60,
    hint: '同一设备每分钟能取几次下载票据；7 个接口按设备码分别计数。',
  },
  {
    key: 'repDlTicketDay',
    group: 'reputation',
    label: '下载票据 · 每日',
    type: 'num',
    min: 1,
    max: 1000000,
    unit: '次',
    def: () => 1200,
  },
  {
    key: 'repOssSignMin',
    group: 'reputation',
    label: '上传签名 · 每分钟',
    type: 'num',
    min: 1,
    max: 100000,
    unit: '次',
    def: () => 40,
  },
  {
    key: 'repOssSignDay',
    group: 'reputation',
    label: '上传签名 · 每日',
    type: 'num',
    min: 1,
    max: 1000000,
    unit: '次',
    def: () => 800,
  },
  {
    key: 'repMirrorSignMin',
    group: 'reputation',
    label: '加速签名 · 每分钟',
    type: 'num',
    min: 1,
    max: 100000,
    unit: '次',
    def: () => 40,
  },
  {
    key: 'repMirrorSignDay',
    group: 'reputation',
    label: '加速签名 · 每日',
    type: 'num',
    min: 1,
    max: 1000000,
    unit: '次',
    def: () => 800,
  },
  {
    key: 'repSubmitMin',
    group: 'reputation',
    label: '投稿 · 每分钟',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 6,
  },
  {
    key: 'repSubmitDay',
    group: 'reputation',
    label: '投稿 · 每日',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 30,
  },
  {
    key: 'repEchoMin',
    group: 'reputation',
    label: '回声洞 · 每分钟',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 20,
  },
  {
    key: 'repEchoDay',
    group: 'reputation',
    label: '回声洞 · 每日',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 200,
  },
  {
    key: 'repFeedbackMin',
    group: 'reputation',
    label: '反馈 · 每分钟',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 10,
  },
  {
    key: 'repFeedbackDay',
    group: 'reputation',
    label: '反馈 · 每日',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 100,
  },
  {
    key: 'repActivateMin',
    group: 'reputation',
    label: '激活尝试 · 每分钟',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 10,
  },
  {
    key: 'repActivateDay',
    group: 'reputation',
    label: '激活尝试 · 每日',
    type: 'num',
    min: 1,
    max: 10000,
    unit: '次',
    def: () => 60,
  },
  {
    key: 'licEnforce',
    group: 'license',
    label: '授权闸门',
    type: 'bool',
    def: (env) => String(env.CSH_LIC_ENFORCE || '').toLowerCase() === 'true',
    hint: '关闭时只记日志不拦截；打开后未授权的构建立即被拒绝。',
  },
  {
    key: 'licEnforceAt',
    group: 'license',
    label: '定时开闸时间',
    type: 'iso',
    def: (env) => String(env.CSH_LIC_ENFORCE_AT || ''),
    hint: '到点后自动开闸，无需人工干预。留空表示不定时。',
  },
  {
    key: 'licDays',
    group: 'license',
    label: '激活有效期',
    type: 'num',
    min: 1,
    max: 3650,
    unit: '天',
    def: (env) => Number(env.CSH_LICENSE_DAYS || 365),
    hint: '激活码换来的令牌有效期。',
  },
  {
    key: 'licOfficialDays',
    group: 'license',
    label: '官方构建令牌有效期',
    type: 'num',
    min: 1,
    max: 365,
    unit: '天',
    def: (env) => Number(env.CSH_OFFICIAL_TOKEN_DAYS || 30),
    hint: '带构建签名的客户端自动换来的令牌有效期，缩短可加快密钥轮换的生效速度。',
  },
  {
    key: 'licTryPerDay',
    group: 'license',
    label: '每来源每日激活尝试',
    type: 'num',
    min: 1,
    max: 1000,
    unit: '次',
    def: (env) => Number(env.CSH_LIC_TRY_PER_DAY || 30),
    hint: '防止离线爆破激活码。',
  },
  {
    key: 'licDeviceRegPerIpDay',
    group: 'license',
    label: '每来源每日登记设备',
    type: 'num',
    min: 1,
    max: 100000,
    unit: '台',
    def: () => LIC_DEV_REG_PER_IP_DAY,
    hint: '同一个 IP 每天最多让多少台「首次出现」的设备进入后台列表。',
  },
  {
    key: 'licTouchHours',
    group: 'license',
    label: '设备活跃刷新间隔',
    type: 'num',
    min: 1,
    max: 168,
    unit: '小时',
    def: () => Math.round(LIC_TOUCH_TTL_MS / 3600000),
    hint: '同一设备多久刷新一次最近活跃时间，调小会让写入更频繁。',
  },
  {
    key: 'licLegacyUntil',
    group: 'license',
    label: '旧客户端豁免截止',
    type: 'iso',
    def: (env) => String(env.CSH_LIC_LEGACY_UNTIL || ''),
    hint: '没有构建签名的老版本在此时间前不受闸门影响。留空表示不豁免。',
  },
  {
    key: 'admSessionHours',
    group: 'admin',
    label: '后台会话时长',
    type: 'num',
    min: 1,
    max: 168,
    unit: '小时',
    def: () => ADM_SESSION_TTL_HOURS,
    hint: '登录后 Cookie 的有效期，过期需要重新登录。',
  },
  {
    key: 'admLoginFailLimit',
    group: 'admin',
    label: '登录失败锁定阈值',
    type: 'num',
    min: 1,
    max: 100,
    unit: '次',
    def: () => ADM_LOGIN_FAIL_LIMIT,
    hint: '同一来源在窗口期内失败多少次后暂时禁止登录。',
  },
  {
    key: 'admLoginFailWindowMin',
    group: 'admin',
    label: '登录失败统计窗口',
    type: 'num',
    min: 1,
    max: 1440,
    unit: '分钟',
    def: () => Math.round(ADM_LOGIN_FAIL_WINDOW_MS / 60000),
    hint: '锁定时长与统计窗口一致，从最后一次失败开始算。',
  },
]

/**
 * 参数缓存挂在 env 上：一次请求内多处用到（授权闸门、信誉闸门、下载票据…）
 * 只读一次存储，请求结束随 env 一起丢弃。这样后台改完参数，下一个请求就生效，
 * 不需要等缓存过期——同一进程内不同 env 之间也不会串味。
 */
const SETTINGS_MEMO_KEY = '__settingsMemo'

function settingField(key) {
  return SETTING_FIELDS.find((f) => f.key === key) || null
}

function settingsDefaults(env) {
  const out = {}
  for (const f of SETTING_FIELDS) {
    try {
      out[f.key] = f.def(env || {})
    } catch {
      out[f.key] = null
    }
  }
  return out
}

/** 把后台传来的原始值收敛到字段定义上：类型、范围、选项都要过。 */
function settingCoerce(field, raw) {
  if (field.type === 'bool') {
    if (raw === true || raw === 'true' || raw === 1 || raw === '1') return { ok: true, value: true }
    if (raw === false || raw === 'false' || raw === 0 || raw === '0') return { ok: true, value: false }
    return { ok: false, error: '只能是开或关' }
  }
  if (field.type === 'num') {
    const n = Number(raw)
    if (!Number.isFinite(n)) return { ok: false, error: '需要一个数字' }
    const v = Math.round(n * 1000) / 1000
    if (field.min !== undefined && v < field.min) return { ok: false, error: `不能小于 ${field.min}` }
    if (field.max !== undefined && v > field.max) return { ok: false, error: `不能大于 ${field.max}` }
    return { ok: true, value: v }
  }
  if (field.type === 'enum') {
    const s = String(raw ?? '').trim().toLowerCase()
    if (!Array.isArray(field.options) || !field.options.includes(s)) {
      return { ok: false, error: '取值不在允许范围内' }
    }
    return { ok: true, value: s }
  }
  const s = String(raw ?? '').trim()
  if (s.length > 64) return { ok: false, error: '太长了' }
  if (field.type === 'iso') {
    if (!s) return { ok: true, value: '' }
    const t = Date.parse(s)
    if (!Number.isFinite(t)) return { ok: false, error: '需要形如 2026-12-02T00:00:00Z 的时间' }
    return { ok: true, value: new Date(t).toISOString() }
  }
  return { ok: true, value: s }
}

/** 读一次存储并算出生效值；同一次请求内复用。 */
async function settingsBundle(env) {
  const now = Date.now()
  const memo = env && env[SETTINGS_MEMO_KEY]
  if (memo && memo.values && now - memo.at < SETTINGS_CACHE_MS) return memo

  const defaults = settingsDefaults(env)
  let stored = null
  try {
    const kv = await gateKv()
    if (kv) stored = await kvJson(kv, SETTINGS_KEY)
  } catch {}
  const raw = stored && stored.v && typeof stored.v === 'object' ? stored.v : {}
  const overrides = {}
  const values = Object.assign({}, defaults)
  for (const key of Object.keys(raw)) {
    const field = settingField(key)
    if (!field) continue
    const out = settingCoerce(field, raw[key])
    if (!out.ok) continue
    overrides[key] = out.value
    values[key] = out.value
  }
  const bundle = {
    at: now,
    values,
    defaults,
    overrides,
    meta: stored ? { at: Number(stored.at) || 0, by: String(stored.by || '') } : null,
  }
  if (env && typeof env === 'object') {
    try {
      Object.defineProperty(env, SETTINGS_MEMO_KEY, {
        value: bundle,
        writable: true,
        configurable: true,
        enumerable: false,
      })
    } catch {}
  }
  return bundle
}

/** 最常用的入口：只要生效值。 */
async function settingsOf(env) {
  const bundle = await settingsBundle(env)
  return bundle.values || {}
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

/** 后台是否显式改过这一项（改过就以后台为准，没改过保留旧的注册表配置语义）。 */
function settingOverridden(bundle, key) {
  return !!(bundle && bundle.overrides &&
    Object.prototype.hasOwnProperty.call(bundle.overrides, key))
}

/** 投稿三项限制的生效值：后台设置 → 旧的注册表配置 → 出厂默认。 */
async function submitLimits(env) {
  const cfg = await registryCfgGet(env)
  const bundle = await settingsBundle(env)
  return {
    requireSource: settingOverridden(bundle, 'submitRequireSource')
      ? !!bundle.overrides.submitRequireSource
      : pickBool(cfg && cfg.requireSource, env.SUBMIT_REQUIRE_SOURCE, SUBMIT_REQUIRE_SOURCE),
    maxPending: settingOverridden(bundle, 'submitMaxPending')
      ? Number(bundle.overrides.submitMaxPending)
      : pickNum(cfg && cfg.maxPending, env.SUBMIT_MAX_PENDING, SUBMIT_MAX_PENDING),
    maxPerDay: settingOverridden(bundle, 'submitMaxPerDay')
      ? Number(bundle.overrides.submitMaxPerDay)
      : pickNum(cfg && cfg.maxPerDay, env.SUBMIT_MAX_PER_DAY, SUBMIT_MAX_PER_DAY),
  }
}

async function submitGate(env, data, sid) {
  const { requireSource, maxPending, maxPerDay } = await submitLimits(env)

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
  const S = await settingsOf(env)
  try {
    const id = env.DL_GATE.idFromName('__sign__')
    const res = await env.DL_GATE.get(id).fetch('https://dl-gate/sign-check', {
      method: 'POST',
      body: JSON.stringify({


        op: 'sign-check',
        ip: src,
        bytes: Math.max(0, Number(bytes) || 0),

        perIp: pickNum(null, S.signPerIpPerDay, SIGN_PER_IP_PER_DAY),
        perDay: pickNum(null, S.signGlobalPerDay, SIGN_GLOBAL_PER_DAY),
        bytesPerDay: pickNum(
          null,
          gbToBytes(S.signGlobalGbPerDay),
          SIGN_GLOBAL_BYTES_PER_DAY
        ),
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





  const src = (await sha256Hex(reqIp(request))).slice(0, 24)
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
    // POST Policy 把实际大小硬绑在声明值以内；PUT 仅作旧客户端兼容。
    let post = null
    try {
      post = await ossPresignPost(env, key, contentType, Math.min(size, sizeLimit), OSS_SIGN_TTL)
    } catch (err) {
      console.error('oss post policy error:', err && err.message)
    }
    return json(
      {
        success: true,
        uploadMode: post ? 'post' : 'put',
        url: signed.url,
        post,
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

  const srcIp = clientIpOf(request)
  if (env.DL_GATE) {
    try {
      const src = (await sha256Hex(srcIp)).slice(0, 24)
      const id = env.DL_GATE.idFromName('__mirror__')
      const res = await env.DL_GATE.get(id).fetch('https://dl-gate/mirror-check', {
        method: 'POST',
        body: JSON.stringify({ op: 'mirror-check', ip: src }),
      })
      const gate = await res.json()
      if (gate && gate.allowed === false) {
        console.warn(`mirror-sign rate limited ip=${src} scope=${gate.scope}`)
        return json(
          {
            error: gate.scope === 'ip'
              ? '加速链接申请过于频繁，请稍后再试。'
              : '今天的加速链接配额已用完，请明天再试。',
            scope: gate.scope,
            used: gate.used,
            limit: gate.limit,
          },
          429,
          request,
          env
        )
      }
    } catch (err) {
      console.error('mirror sign gate error:', err && err.message)
    }
  }

  try {
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
    'Access-Control-Allow-Headers':
      'Content-Type, X-CSH-Device, X-CSH-Did, X-CSH-Build, X-CSH-Sig, X-CSH-Lic, X-Purge-Token',
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

  // platforms：新版投稿页多选「系统」后提交的平台 key 数组。
  // 缺省（null/undefined）视为旧版投稿，只有 system 文本，由审核流按文案兜底推导，不报错
  if (d.platforms !== undefined && d.platforms !== null) {
    if (!Array.isArray(d.platforms)) {
      errors.push('platforms 必须是数组')
    } else if (d.platforms.length > MAX_PLATFORMS_PER_APP) {
      errors.push(`platforms 最多 ${MAX_PLATFORMS_PER_APP} 个`)
    } else {
      // 大小写变体放行（落库前会统一小写），非字符串/空串/含非法字符仍拦下
      for (const key of d.platforms) {
        const k = typeof key === 'string' ? key.trim().toLowerCase() : ''
        if (!PLATFORM_KEY_RE.test(k)) {
          errors.push(`platforms 含非法平台标识：${String(key).slice(0, 20)}`)
          break
        }
      }
    }
  }

  // _系统版本：审核用元数据，平台 key → 版本 key 数组；只校验形状，值是否真实由 knownPlatformKeys 兜
  if (d._系统版本 !== undefined && d._系统版本 !== null) {
    if (typeof d._系统版本 !== 'object' || Array.isArray(d._系统版本)) {
      errors.push('_系统版本 格式不正确')
    } else {
      for (const [pk, versions] of Object.entries(d._系统版本)) {
        if (!PLATFORM_KEY_RE.test(String(pk).trim().toLowerCase()) ||
            !Array.isArray(versions) || versions.length > MAX_VERSIONS_PER_PLATFORM) {
          errors.push('_系统版本 格式不正确')
          break
        }
        if (versions.some((v) => !PLATFORM_KEY_RE.test(typeof v === 'string' ? v.trim().toLowerCase() : ''))) {
          errors.push('_系统版本 含非法版本标识')
          break
        }
      }
    }
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
    const oversize = []
    for (const k of referenced) {
      try {
        const probe = await relayOpen(env, k, 'HEAD')
        if (!probe.reader) continue
        try { probe.reader.releaseLock() } catch {}
        try { probe.socket.close() } catch {}
        if (probe.status === 404) {
          gone.push(k)
          continue
        }
        if (probe.status >= 200 && probe.status < 300) {
          // PUT 预签名无法在落盘前绑定 Content-Length：提交时用 HEAD 的实际大小
          // 与登记值/上限比对，超限对象立即删除，避免「签 1 字节传 2.5GB」。
          const actual = Number(probe.headers && probe.headers['content-length'])
          const rec = await registryGet(env, k)
          const declared = rec && Number.isFinite(Number(rec.size)) ? Number(rec.size) : 0
          const limit = rec && String(rec.origin) === ICON_PREFIX ? ICON_SIGN_MAX_BYTES : OSS_MAX_BYTES
          if (Number.isFinite(actual) && actual > 0 && (actual > limit || (declared > 0 && actual > declared))) {
            oversize.push({ key: k, actual, declared, limit })
          }
        }
      } catch (err) {
        console.error('submit probe error:', err && err.message)
      }
    }
    if (oversize.length) {
      for (const item of oversize) {
        try {
          await purgeOne(env, item.key)
        } catch (err) {
          console.error('oversize purge error:', err && err.message)
        }
      }
      return json(
        {
          error: '上传文件的实际大小与登记不符或超出上限，已拒绝并清理，请重新上传。',
          invalid: oversize,
        },
        413,
        request,
        env
      )
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

  // platforms 与站点 platforms.json 核对：形状不合法已在 validate 拦掉，这里防乱填 key
  // （前端只发已定义的 key，对不上多半是旧缓存页面或手工构造的请求）。读不到清单就跳过
  const platforms = normalizePlatforms(data.platforms)
  if (platforms.length) {
    const known = await knownPlatformKeys(env)
    if (known) {
      const unknownKeys = platforms.filter((key) => !known.has(key))
      if (unknownKeys.length) {
        return json(
          { error: `platforms 含站点未定义的平台：${unknownKeys.join('、')}，请刷新页面后重新选择` },
          400,
          request,
          env
        )
      }
    }
  }

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
      const kind = typeof x.kind === 'string' ? x.kind.trim().toLowerCase() : ''
      if (DOWNLOAD_KINDS.includes(kind)) item.kind = kind
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
  // platforms 原样进入站点数据（首页「系统」筛选用）；旧版投稿没有这个字段时不写
  if (platforms.length) fileContent.platforms = platforms
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











  const SUBMISSION_META_KEYS = new Set(['_联系方式', '_系统版本'])
  for (const key of Object.keys(data)) {
    if (!SUBMISSION_META_KEYS.has(key) || key in submissionContent) continue
    const value = data[key]
    if (typeof value === 'string') {
      const limit = key === '_联系方式' ? 4000 : 300
      const cleaned = cleanText(value, limit)
      if (cleaned) submissionContent[key] = cleaned
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      submissionContent[key] = value
    } else if (key === '_系统版本') {
      // 审核 Issue 里展示「每个平台勾了哪些版本」；合并时随 _ 前缀一起被剥掉
      const meta = sanitizePlatformMeta(value, platforms)
      if (meta) submissionContent[key] = meta
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

  const S = await settingsOf(env)
  const text = typeof data?.text === 'string' ? data.text.trim() : ''
  if (!text) return json({ error: '先写一句话再投稿吧。' }, 400, request, env)
  const maxLen = Math.max(20, Number(S.echoMaxLen) || ECHO_MAX_LEN)
  if (text.length > maxLen) {
    return json({ error: `字条太长啦，最多 ${maxLen} 个字。` }, 400, request, env)
  }

  // 每张字条都会在仓库里落一个文件，按来源限量，避免被刷成垃圾提交
  const echoKv = await gateKv()
  const dailyMax = Number(S.echoMaxPerDay) || 0
  if (dailyMax > 0 && !(await ipDailyAllow(echoKv, 'echo', dailyMax, request))) {
    return json({ error: `今天已经投过 ${dailyMax} 条了，明天再来吧。` }, 429, request, env)
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

  // 反馈会开 GitHub Issue，同样按来源限量
  const fbKv = await gateKv()
  const fbMax = Number((await settingsOf(env)).feedbackMaxPerDay) || 0
  if (fbMax > 0 && !(await ipDailyAllow(fbKv, 'fb', fbMax, request))) {
    return json({ error: `今天已经提交过 ${fbMax} 条反馈了，明天再来吧。` }, 429, request, env)
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

async function dlTicketSig(env, exp, fpHash, key, mode) {
  const secret = textEncoder.encode(String(env.DL_SIGN_SECRET || ''))
  // mode 进签名：/api/dl 据此跳过不可用的上游。历史票据不带 m（等价 mode 为空），
  // 负载与旧版一致，仍在 15 分钟有效期内自然放行。
  const payload = mode ? `${exp}|${fpHash}|${key}|${mode}` : `${exp}|${fpHash}|${key}`
  return toHex(await hmacSha256(secret, payload)).slice(0, 32)
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

function relayHttpBase(env) {
  const host = String(env.RELAY_HOST || '').trim()
  const token = String(env.RELAY_TOKEN || '')
  if (!host || !token) return null
  const scheme = String(env.RELAY_SCHEME || 'http').trim() || 'http'
  const port = Number(env.RELAY_PORT) || DL_RELAY_PORT
  return { base: `${scheme}://${host}:${port}`, token }
}

async function wrapUpstream(res, method) {
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
  // GET 成功：只交原生流，不取 reader（getReader 会锁住流，导致无法透传）。
  // reader 留给 DELETE 等需要逐段读的调用方；body 缺失时调用方按空响应处理。
  return { status: res.status, headers: hdrs, body: res.body, socket: sock, first: new Uint8Array(0) }
}

/**
 * 取流入口，承载两条方法：
 *   prefer='relay'（默认）—— 先走 ECS 中继（内网取流，不计 OSS 公网流量）；
 *       中继网络不可达，或给出非确定性回答（5xx / 401 / 404…）时回落 OSS 签名直连；
 *   prefer='oss' —— 只用 OSS 签名直连，即「后端直连 OSS」方法，
 *       供 auto 选路在中继不可用时使用，也用于强制对比测试。
 */
async function relayOpen(env, key, method, range, prefer) {
  const relay = prefer === 'oss' ? null : relayHttpBase(env)
  if (relay) {
    const path = '/' + key.split('/').map(encodeURIComponent).join('/')
    const headers = { 'X-Api-Key': relay.token }
    if (range) headers['Range'] = range
    let res = null
    try {
      res = await fetch(relay.base + path, { method, headers })
    } catch (err) {
      // 中继网络不可达 → 回落 OSS 签名直连
    }
    // 2xx 与 416（对象在、只是区间不合法）视为中继的确定性回答，原样采用；
    // 其余状态（中继故障、令牌被拒、对象视图不一致）一律回落 OSS——
    // 下载可用性优先于通道纯粹性。
    if (res && (res.status < 300 || res.status === 416)) {
      return await wrapUpstream(res, method)
    }
    try { if (res && res.body) res.body.cancel() } catch (err) {}
  }
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
  return await wrapUpstream(res, method)
}

/**
 * 直探测中继活路（不做 OSS 回落）：auto 选路用。
 * 401/403 = 令牌被拒；5xx = 中继故障；网络异常 = 不可达；其余（含 404）算活。
 */
async function relayProbe(env, key) {
  const relay = relayHttpBase(env)
  if (!relay) return false
  const path = key ? '/' + key.split('/').map(encodeURIComponent).join('/') : '/?list&max-keys=1'
  try {
    const res = await fetch(relay.base + path, { method: 'HEAD', headers: { 'X-Api-Key': relay.token } })
    return res.status < 500 && res.status !== 401 && res.status !== 403
  } catch (err) {
    return false
  }
}

/** 中继探测状态码：null = 未配置，0 = 网络不可达，其余为实际 HTTP 状态码 */
async function relayProbeStatus(env) {
  const relay = relayHttpBase(env)
  if (!relay) return null
  try {
    const res = await fetch(`${relay.base}/?list&max-keys=1`, {
      headers: { 'X-Api-Key': relay.token },
    })
    return res.status
  } catch (err) {
    return 0
  }
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

  // 有原生上游流时直接透传：运行时的流转发无需手动 read，
  // 也绕开了「read() 的块不保证是 Uint8Array」的格式差异（曾因按 .length
  // 判断把块全部跳过，表现为 200 但 0 字节）。
  if (relay.body) {
    return new Response(relay.body, { status: relay.status, headers: out })
  }
  if (!relay.reader) {
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
        if (value) {
          // 运行时的块不保证是 Uint8Array（也可能是 ArrayBuffer）——统一成字节视图
          const bytes = value instanceof Uint8Array ? value : new Uint8Array(value.buffer || value)
          if (bytes.length) controller.enqueue(bytes)
        }
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

function parseListXml(xml) {
  const objects = []
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
  const truncated = !!(truncM && truncM[1].trim() === 'true' && nextM)
  return { objects, nextToken: truncated ? decodeXml(nextM[1]) : '' }
}

/**
 * 解析中继 `?list` 的响应。中继返回的是 JSON（数组或 `{ objects, isTruncated }`，
 * 元素既可以是裸键串，也可以是 `{ key, size, lastModified }` 及其首字母大写形态）；
 * 若中继换版本改成透传 OSS 的 XML，则退一级用 XML 再试。两者都解不动返回 null，
 * 由调用方回落 OSS 列举 —— 清单以桶为准，猜不得。
 *
 * `truncated` 必须原样带出：这份清单会被用来判断「某个键到底在不在桶里」，
 * 拿一份被截断的清单去判「不存在」，会把真实存在的对象误判成无主记录。
 */
function parseRelayList(text) {
  let data = null
  try {
    data = JSON.parse(text)
  } catch (err) {
    const xml = parseListXml(text)
    return xml.objects.length ? { objects: xml.objects, truncated: !!xml.nextToken } : null
  }
  const objs = Array.isArray(data) ? data : data?.objects || []
  const objects = objs
    .map((o) =>
      typeof o === 'string'
        ? { key: o, size: 0, lastModified: '' }
        : {
            key: o?.key || o?.Key || '',
            size: Number(o?.size ?? o?.Size) || 0,
            // 中继原样透传 OSS 的 ISO 串（上传完成时刻），交给 Date 解析
            lastModified: o?.lastModified || o?.LastModified || '',
          }
    )
    .filter((o) => typeof o.key === 'string' && o.key)
  return { objects, truncated: data?.isTruncated === true || data?.truncated === true }
}

async function relayListDetailed(env, prefix) {
  const relay = relayHttpBase(env)
  if (relay) {
    try {
      const q = prefix ? `?list&prefix=${encodeURIComponent(prefix)}` : '?list'
      const res = await fetch(`${relay.base}/${q}`, {
        headers: { 'X-Api-Key': relay.token },
      })
      if (res.ok) {
        const parsed = parseRelayList(await res.text())
        if (parsed) return parsed
      }
    } catch (err) {
      // 中继不可达 → 回落 OSS 列举
    }
  }
  let token = ''
  const objects = []
  for (let page = 0; page < 20; page++) {
    const q = { 'list-type': '2', 'max-keys': '1000' }
    if (prefix) q.prefix = prefix
    if (token) q['continuation-token'] = token
    let res
    try {
      res = await fetch(await ossSignedUrl(env, 'GET', '', q))
    } catch (err) {
      return null
    }
    if (!res.ok) return null
    const xml = await res.text()
    const parsed = parseListXml(xml)
    objects.push(...parsed.objects)
    if (!parsed.nextToken) return { objects, truncated: false }
    token = parsed.nextToken
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
  const bundle = await settingsBundle(env)
  const fromAdmin = bundle.overrides && bundle.overrides.dlMode
  if (fromAdmin) return fromAdmin
  const out = await registryOp(env, { op: 'cfg-get' })
  const stored = out && out.cfg && out.cfg.mode
  const raw = String(stored || bundle.values.dlMode || env.DL_MODE || DL_MODE_DEFAULT).trim().toLowerCase()
  return raw === 'relay' || raw === 'backend' || raw === 'direct' ? raw : 'auto'
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

  // 配额键必须由服务端派生：客户端 fp 可任意轮换，等于没有每日限额。
  // 有设备码用设备码；没有设备码退化为「可信 IP + UA」摘要。
  const device = deviceIdOf(request)
  const ua = String(request.headers.get('user-agent') || '').slice(0, 128)
  const fp = device || `ip:${clientIpOf(request)}|ua:${ua}`
  const fpHash = (await sha256Hex(fp)).slice(0, 16)

  if (device) {
    try {
      const ban = await licBanInfo(await gateKv(), device)
      if (ban) {
        return json({ error: licBanMessage(ban), code: 'csh_device_banned' }, 429, request, env)
      }
    } catch (err) {
      console.error('dl ban check error:', err && err.message)
    }
  }






  const reg = await registryOp(env, { op: 'file-get', key })
  if (reg && reg.ok) {
    if (reg.file && reg.file.deleted) return json({ error: '文件已被清理' }, 404, request, env)
    if (!reg.file && key.startsWith('upload/')) {
      return json({ error: '下载地址无效' }, 404, request, env)
    }
  }

  const S = await settingsOf(env)
  const ticketTtl = Math.min(
    86400,
    Math.max(60, Math.round(Number(S.dlTicketMinutes) * 60) || DL_TICKET_TTL)
  )

  if (env.DL_GATE) {
    try {
      const id = env.DL_GATE.idFromName(fpHash)
      const res = await env.DL_GATE.get(id).fetch('https://dl-gate/check', {
        method: 'POST',
        body: JSON.stringify({ limit: await dlDailyLimit(env, S) }),
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

  const preferRaw = String(data?.prefer || '').trim().toLowerCase()
  const want =
    preferRaw === 'relay' || preferRaw === 'backend' || preferRaw === 'direct' ? preferRaw : await dlModeWanted(env)
  const stats = (await registryOp(env, { op: 'stats' })) || {}
  const relayUsed = Number(stats.relay) || 0
  const relayCap = gbToBytes(env.DL_RELAY_MONTHLY_GB)
  const relayFull = relayCap > 0 && relayUsed >= relayCap

  const exp = Math.floor(Date.now() / 1000) + ticketTtl
  const origin = new URL(request.url).origin
  // /api/dl 入口：中继与后端直连都走它，上游由票据里的 m 参数决定
  const backendReady = relayReady || ossReady

  const directTtl = directTtlFor(size)
  // 直链只对已登记对象签发：否则 soft/、releases/ 下任意 key 都能被探测签名。
  const directPath = rec ? await buildDirectUrl(env, key, dlFileName(key), directTtl) : null

  // 双方法优先级（auto）：ECS 中继（内网取流，不计 OSS 公网）→ 后端直连 OSS → 浏览器直连
  let mode
  if (want === 'auto') {
    if (relayReady && !relayFull) mode = 'relay'
    else if (ossReady) mode = 'backend'
    else mode = 'direct'
  } else {
    mode = want
  }
  if (mode === 'relay' && !relayReady) mode = ossReady ? 'backend' : 'direct'
  if (mode === 'backend' && !ossReady) mode = relayReady ? 'relay' : 'direct'
  if (mode === 'direct' && !directPath) mode = relayReady ? 'relay' : ossReady ? 'backend' : 'direct'
  if (!backendReady && !directPath) {
    return json({ error: '下载服务暂时不可用' }, 503, request, env)
  }

  // auto + 中继：直探测活（不走内部回落），令牌被拒或不可达就转后端直连，
  // 避免每个下载请求都先撞一次不可用的中继。
  if (want === 'auto' && mode === 'relay' && backendReady) {
    let alive = false
    try {
      alive = await relayProbe(env, key)
    } catch (err) {
      console.error('relay probe error:', err && err.message)
    }
    if (!alive) mode = ossReady ? 'backend' : 'direct'
  }

  const sig = await dlTicketSig(env, exp, fpHash, key, mode === 'direct' ? '' : mode)
  const url =
    mode === 'direct'
      ? directPath
      : `${origin}/api/dl?k=${encodeURIComponent(key)}&e=${exp}&h=${fpHash}&s=${sig}` +
        `&f=${encodeURIComponent(fp)}&m=${mode}`


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

      expiresIn: mode === 'direct' ? directTtl : ticketTtl,
      dailyLimit: gateInfo && gateInfo.limit > 0 ? gateInfo.limit : undefined,
      remaining:
        gateInfo && gateInfo.limit > 0
          ? Math.max(0, gateInfo.limit - gateInfo.used)
          : undefined,
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
  const mode = url.searchParams.get('m') || ''

  if (!dlKeyOk(key)) return json({ error: '下载地址无效' }, 400, request, env)
  if (!Number.isFinite(exp) || exp * 1000 < Date.now()) {
    return json({ error: '下载链接已过期，请回站点重新点击下载' }, 410, request, env)
  }
  if (!ctEqual(sig, await dlTicketSig(env, exp, fpHash, key, mode))) {
    return json({ error: '下载地址无效' }, 403, request, env)
  }
  if (!fp || !ctEqual((await sha256Hex(fp)).slice(0, 16), fpHash)) {
    return json({ error: '设备校验失败，请回站点重新点击下载' }, 403, request, env)
  }

  const method = request.method === 'HEAD' ? 'HEAD' : 'GET'
  let relay
  try {
    // m=backend：票据签发时已探明中继不可用，直接走后端直连 OSS，不再撞中继
    relay = await relayOpen(env, key, method, request.headers.get('Range'), mode === 'backend' ? 'oss' : 'relay')
  } catch (err) {
    console.error('relay error:', err && err.message)
    return json({ error: '下载服务暂时不可用' }, 502, request, env)
  }
  if (!relay.reader && !relay.body) {
    return json({ error: relay.text || '下载失败' }, relay.status || 502, request, env)
  }
  return relayRespond(relay, method, dlFileName(key, url.searchParams.get('n')))
}

function adminOk(request, env) {
  const expect = String(env.PURGE_TOKEN || '')
  if (!expect) return false
  return ctEqual(request.headers.get('x-purge-token') || '', expect)
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
      submitGate: await submitLimits(env),
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
    const limits = await submitLimits(env)
    return json(
      {
        success: true,
        mode: await dlModeWanted(env),
        modeSource: cfg && cfg.mode ? 'runtime' : 'env',
        envMode: String(env.DL_MODE || DL_MODE_DEFAULT),
        orphanMinutes: await gcOrphanMinutes(env),
        staleRecordHours: await gcStaleRecordHours(env),


        requireSource: limits.requireSource,
        maxPending: limits.maxPending,
        maxPerDay: limits.maxPerDay,
        lastGc: (cfg && cfg.lastGc) || null,
        updatedAt: (cfg && cfg.updatedAt) || null,
        options: ['auto', 'relay', 'backend', 'direct'],
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


    if (raw !== 'auto' && raw !== 'relay' && raw !== 'backend' && raw !== 'direct') {
      return json({ error: 'mode 只接受 auto / relay / backend / direct' }, 400, request, env)
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
          // 枚举同前缀的键（Blob SDK 支持 list；键按段编码存储，这里还原回原始键）
          async list(prefix) {
            const res = await store.list({ prefix: blobKey(prefix), consistency: 'strong' })
            return (res.blobs || []).map((b) =>
              String(b.key || '')
                .split('/')
                .map((seg) => {
                  try {
                    return decodeURIComponent(seg)
                  } catch {
                    return seg
                  }
                })
                .join('/')
            )
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

const MIRROR_SIGN_PER_IP_PER_DAY = 300
const MIRROR_SIGN_GLOBAL_PER_DAY = 20000

/**
 * 加速链接签发配额。与上传配额分开计数，避免一条下载链被批量铸造后
 * 还能顺带把上传额度刷空；IP 由调用方传入可信边缘地址的哈希。
 */
async function gateMirrorCheck(kv, body) {
  const day = gateDay()
  const key = 'gate:ms:' + day
  let rec = (await kvJson(kv, key)) || null
  if (!alive(rec) || rec.day !== day) rec = { day, n: 0, ips: {} }
  const ips = rec.ips && typeof rec.ips === 'object' ? rec.ips : {}
  const src = String(body.ip || 'unknown').slice(0, 32)
  const perIp = Math.max(1, Number(body.perIp) || MIRROR_SIGN_PER_IP_PER_DAY)
  const perDay = Math.max(1, Number(body.perDay) || MIRROR_SIGN_GLOBAL_PER_DAY)
  const ipN = Number(ips[src]) || 0
  const n = Number(rec.n) || 0
  if (n >= perDay) return { allowed: false, scope: 'global', limit: perDay, used: n, remaining: 0 }
  if (ipN >= perIp) return { allowed: false, scope: 'ip', limit: perIp, used: ipN, remaining: 0 }
  rec.n = n + 1
  ips[src] = ipN + 1
  rec.ips = ips
  await kvSave(kv, key, rec)
  if (Math.random() < 0.02) {
    try { await kv.delete('gate:ms:' + new Date(Date.now() - 2 * 86400000).toISOString().slice(0, 10)) } catch {}
  }
  return { allowed: true, used: rec.n, limit: perDay, remaining: Math.max(0, perDay - rec.n) }
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
  // limit <= 0 视为不限：既不计次也不拦（后台把每日下载次数设成 0 就是关掉限制）
  if (limit <= 0) return { allowed: true, day, used: Number(rec.n) || 0, limit: 0, unlimited: true }
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
    // relay = ECS 中继内网取流（不计 OSS 公网）；backend / direct 都经 OSS 公网，计入 direct
    const mode = body.mode === 'relay' ? 'relay' : 'direct'
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
  // 生效参数由调用方随请求带来（见 announceOp），缺省回落到常量
  const C = body && body.cfg && typeof body.cfg === 'object' ? body.cfg : {}
  const annTtlSec = Number(C.ttlSec) > 0 ? Number(C.ttlSec) : ANN_TTL
  const annRateMs = Number.isFinite(Number(C.rateMs)) ? Number(C.rateMs) : ANN_RATE_MS
  const pairDeviceMax = Number(C.pairDeviceMax) > 0 ? Number(C.pairDeviceMax) : ANN_PAIR_DEVICE_MAX
  if (op === 'ann-send') {
    // 按来源（IP + 设备码摘要）限速：仅按 pairCode 限流时，攻击者可轮换 6 位码刷屏。
    const src = String(body.src || '').slice(0, 40)
    if (src && body.rate !== false) {
      const srcKey = 'gate:ann:s:' + src
      const sr = (await kvJson(kv, srcKey)) || null
      const now = Date.now()
      const win = 60 * 1000
      const fresh = sr && Number.isFinite(sr.w) && now - sr.w < win
      const n = fresh ? Number(sr.n) || 0 : 0
      if (n >= ANN_SEND_PER_MIN) return { ok: false, error: 'rate_limited' }
      await kvSave(kv, srcKey, { w: fresh ? sr.w : now, n: n + 1, _exp: now + 3600 * 1000 })
    }
    const rateKey = 'gate:ann:r:' + pairCode
    const prev = (await kvJson(kv, rateKey)) || null
    // rate: false 供管理后台使用：喊话由已登录的维护者触发，不受间隔限制
    if (body.rate !== false && alive(prev) && Number.isFinite(prev.t) && Date.now() - prev.t < annRateMs) {
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
      _exp: Date.now() + annTtlSec * 1000,
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
    // 单个配对码下最多登记这么多台在线设备，防止用随机设备码把注册表撑大
    if (!reg[deviceId] && Object.keys(reg).length >= pairDeviceMax) {
      return { ok: false, error: 'pair_full' }
    }
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
    // 管理端或已与该配对码绑定（至少轮询过一次）的设备才能看设备列表，
    // 避免拿到 6 位码后匿名枚举教室里在线的是谁。
    // 注意：poll 本身不需要鉴权，攻击者可以先 poll 注册自己的设备码再 list，
    // 所以路由层（handleAnnounceList）必须用管理令牌兜底，这里的绑定校验只是补充。
    const deviceId = String(body.deviceId || '').trim()
    const regKey = 'gate:ann:d:' + pairCode
    const reg = (await kvJson(kv, regKey)) || {}
    if (body.admin !== true) {
      if (!/^[0-9a-f]{16,64}$/i.test(deviceId)) return { ok: false, error: 'bad_request' }
      if (!reg[deviceId]) return { ok: false, error: 'forbidden' }
    }
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
  if (op === 'mirror-check') return gateMirrorCheck(kv, body)
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
  if (!relay.reader && !relay.body) return json({ error: relay.text || '图标不存在' }, relay.status || 502, request, env)

  const size = Number(relay.headers['content-length'] || 0)
  if (size > ICON_MAX_BYTES) {
    if (relay.reader) { try { relay.reader.releaseLock() } catch {} }
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
    // 参数随请求下发：门实现（本地 gateDispatch 或 Durable Object）只拿到 kv，
    // 不能自己读设置，所以由这里带上当前的生效值。
    const S = await settingsOf(env)
    const body = Object.assign({}, payload, {
      cfg: {
        textMax: Number(S.annTextMax) || ANN_TEXT_MAX,
        ttlSec: Number(S.annTtlSec) || ANN_TTL,
        rateMs: Number.isFinite(Number(S.annRateSec)) ? Number(S.annRateSec) * 1000 : ANN_RATE_MS,
        pairDeviceMax: Number(S.annPairDeviceMax) || ANN_PAIR_DEVICE_MAX,
      },
    })
    const id = env.DL_GATE.idFromName(ANN_ID)
    const res = await env.DL_GATE.get(id).fetch('https://dl-gate/op', {
      method: 'POST',
      body: JSON.stringify(body),
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
  const annTextMax = Math.max(10, Number((await settingsOf(env)).annTextMax) || ANN_TEXT_MAX)

  if (!/^\d{6}$/.test(pairCode)) return json({ error: 'bad_request' }, 400, request, env)
  if (!text || text.length > annTextMax) {
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
  const src = (await sha256Hex(`${clientIpOf(request)}|${deviceIdOf(request)}`)).slice(0, 24)
  const out = await announceOp(env, { op: 'ann-send', pairCode, text, from, duration, id, targets, src })
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

  // 新配对码注册表按来源限量；已存在的配对码不受影响（轮询本身是正常高频行为）
  const kv = await gateKv()
  const newPairMax = Math.max(1, Number((await settingsOf(env)).annNewPairPerIpDay) || ANN_NEW_PAIR_PER_IP_DAY)
  if (kv) {
    try {
      if (!(await kvJson(kv, 'gate:ann:d:' + pairCode))) {
        const ipHash = (await sha256Hex(reqIp(request))).slice(0, 24)
        const day = new Date().toISOString().slice(0, 10)
        const key = `ann:pair:${ipHash}:${day}`
        const used = Number((await kvJson(kv, key))?.n) || 0
        if (used >= newPairMax) {
          return json({ error: 'pair_quota' }, 429, request, env)
        }
        await kvSave(kv, key, { n: used + 1, _exp: Date.now() + 2 * 86400 * 1000 })
      }
    } catch {}
  }

  const out = await announceOp(env, { op: 'ann-poll', deviceId, pairCode, name })
  if (!out) return json({ error: 'internal' }, 500, request, env)
  if (!out.ok) {
    if (out.error === 'pair_full') {
      return json({ error: 'pair_full', message: '这个配对码下的设备数已满。' }, 429, request, env)
    }
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
  // 设备列表（id/name/ts）属于管理端数据：只凭 6 位配对码就能匿名枚举在线设备，
  // 因此与 /api/files 等管理路由一致，要求 X-Purge-Token。
  if (!adminOk(request, env)) return json({ error: '未授权' }, 401, request, env)
  const url = new URL(request.url)
  const pairCode = (url.searchParams.get('pairCode') || '').trim()
  if (!/^\d{6}$/.test(pairCode)) return json({ error: 'bad_request' }, 400, request, env)

  const out = await announceOp(env, { op: 'ann-list', pairCode, admin: true })
  if (!out) return json({ error: 'internal' }, 500, request, env)
  if (!out.ok) {
    return json({ error: out.error || 'forbidden' }, out.error === 'bad_request' ? 400 : 403, request, env)
  }
  return json({ ok: true, devices: out.devices || [] }, 200, request, env)
}

// ══════════════════════════════════════════════════════════════════════
// 正版校验
//
// 桌面端仓库公开，客户端里任何判定都能被改掉，所以判定放在服务端：
// 官方包里由打包脚本注入一份构建签名（build-stamp.txt），请求头带上；
// 服务端验签通过就下发短期令牌，非官方构建只能靠激活码换令牌。
//
// 协议与迁移顺序见 csh-win7-repo/docs/正版校验与服务端接入.md，
// 客户端实现见 src/Services/License/。
// ══════════════════════════════════════════════════════════════════════

const LIC_ACTIVATE_PATH = '/api/license/activate'

// 需要校验的路由。mirror-sign / dl / dl-ticket / icon / status 不在此列：
// 网页端与下载链路也在用，且下载侧另有票据与限额。
const LIC_GATED_PREFIXES = ['/api/submit', '/api/echocave', '/api/feedback', '/api/oss-sign', '/api/announce/']

const LIC_CODE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'

const LIC_CODE_EPOCH_MS = Date.UTC(2020, 0, 1)

const LIC_CODE_LEN = 16

const LIC_TRY_KEY = 'lic:try:'

const LIC_DEVICE_KEY = 'lic:d:'

const LIC_DENY_BODY = {
  error: '您使用的 ClassSoftwareHub 不是正版，请输入激活码激活。',
  code: 'csh_license_required',
}

// ── 管理后台（登录 / 激活码签发）─────────────────────────────────────
//
// 后台页面是静态 HTML（functions/admin.js），数据全部走 /api/admin/*。
// 会话用 HttpOnly Cookie + HMAC 签名，密钥取 CSH_ADMIN_SESSION_SECRET，
// 未配置时回落 CSH_LICENSE_SECRET；生产环境建议两者分开。
//
// 激活码本身仍是纯离线校验（见 licVerifyCode），后台只负责签发与对账：
// 签发记录、激活记录都存在状态存储里，用于列表展示与封禁，删掉记录不影响
// 已发出的码可用性 —— 要真正作废只能吊销（仅对未激活生效）或轮换密钥。

const ADM_COOKIE = 'csh_adm'

const ADM_SESSION_TTL_HOURS = 12

const ADM_LOGIN_FAIL_LIMIT = 10

const ADM_LOGIN_FAIL_WINDOW_MS = 30 * 60 * 1000

const ADM_MAX_BATCH = 50

const ADM_INDEX_CAP = 200

const ADM_SEQ_KEY = 'lic:seq'

const ADM_CODE_INDEX_KEY = 'lic:c:idx'

const ADM_DEV_INDEX_KEY = 'lic:dev:idx'

const ADM_BAN_KEY = 'lic:ban:'

const ADM_FAIL_KEY = 'adm:fail:'

const ADM_DEV_BACKFILL_KEY = 'lic:dev:backfill'

function admUser(env) {
  return String((env && env.CSH_ADMIN_USER) || 'admin').trim().slice(0, 64) || 'admin'
}

function admSecret(env) {
  return String((env && (env.CSH_ADMIN_SESSION_SECRET || env.CSH_LICENSE_SECRET)) || '')
}

function admReady(env) {
  return !!admSecret(env) && !!(env.CSH_ADMIN_PASS || env.CSH_ADMIN_PASS_SHA256)
}

/** 后台响应：不带任何 CORS 头，禁止缓存，避免会话数据被中间层留存。 */
function admJson(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...(headers || {}),
    },
  })
}

function admCookieGet(request, name) {
  const raw = request.headers.get('cookie') || ''
  for (const part of raw.split(';')) {
    const at = part.indexOf('=')
    if (at < 0) continue
    if (part.slice(0, at).trim() !== name) continue
    try {
      return decodeURIComponent(part.slice(at + 1).trim())
    } catch {
      return ''
    }
  }
  return ''
}

function admCookieSet(token, maxAge) {
  const parts = [
    `${ADM_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    `Max-Age=${maxAge}`,
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
  ]
  return parts.join('; ')
}

/** 请求来源校验：Cookie 已是 SameSite=Strict，这里再挡一层被嵌入/跨站提交的场景。 */
function admSameOrigin(request) {
  const site = String(request.headers.get('sec-fetch-site') || '').toLowerCase()
  if (site && site !== 'same-origin' && site !== 'none') return false

  const raw = request.headers.get('origin') || request.headers.get('referer') || ''
  if (!raw) return true
  try {
    const host = new URL(request.url).host
    return new URL(raw).host === host
  } catch {
    return false
  }
}

/**
 * 真实客户端 IP：只信任边缘会覆盖写入的头（EdgeOne: EO-Connecting-IP，
 * Cloudflare: CF-Connecting-IP）；退化到 XFF 时取**最后一段**——首段由客户端
 * 自行填写，用它做限流会被伪造头直接绕过。eagleeye-real-ip 是阿里云头，
 * EdgeOne 不会覆盖，客户端可以随便填，因此不参与判定。
 */
function clientIpOf(request) {
  const h = request.headers
  for (const name of ['eo-connecting-ip', 'cf-connecting-ip', 'true-client-ip', 'x-real-ip']) {
    const value = String(h.get(name) || '').split(',')[0].trim()
    if (value) return value.slice(0, 64) || 'unknown'
  }
  const chain = String(h.get('x-forwarded-for') || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  const last = chain.length ? chain[chain.length - 1] : ''
  return last.slice(0, 64) || 'unknown'
}

function reqIp(request) {
  return clientIpOf(request)
}

/** 客户端设备码：与 deviceIdOk 同一形态，避免把任意头写进存储键。 */
function deviceIdOf(request) {
  const raw = String(request.headers.get('x-csh-did') || request.headers.get('x-csh-device') || '').trim()
  return deviceIdOk(raw) ? raw : ''
}

/** 定长比较，避免按字符提前返回泄漏密码前缀。 */
/**
 * 服务间调用令牌：观测台等受信后端用它调用 /api/admin/*，无需浏览器会话。
 * 只接受 Authorization: Bearer 或 X-CSH-Admin-Token，且令牌必须足够长。
 */
function admServiceOk(request, env) {
  const expect = String(env.CSH_ADMIN_API_TOKEN || '').trim()
  if (expect.length < 16) return false
  const auth = String(request.headers.get('authorization') || '').trim()
  const bearer = /^bearer\s+/i.test(auth) ? auth.replace(/^bearer\s+/i, '').trim() : ''
  const direct = String(request.headers.get('x-csh-admin-token') || '').trim()
  return ctEqual(bearer || direct, expect)
}

function ctEqual(a, b) {
  const x = String(a)
  const y = String(b)
  let diff = x.length ^ y.length
  const n = Math.max(x.length, y.length)
  for (let i = 0; i < n; i++) diff |= (x.charCodeAt(i) || 0) ^ (y.charCodeAt(i) || 0)
  return diff === 0
}

async function admPasswordOk(env, pass) {
  const hashed = String(env.CSH_ADMIN_PASS_SHA256 || '').trim().toLowerCase()
  if (hashed) return ctEqual(await sha256Hex(String(pass)), hashed)
  const plain = String(env.CSH_ADMIN_PASS || '')
  return plain.length > 0 && ctEqual(pass, plain)
}

async function admIssueSession(env, hours) {
  const span = Number(hours) > 0 ? Number(hours) : ADM_SESSION_TTL_HOURS
  const exp = Math.floor(Date.now() / 1000) + Math.round(span * 3600)
  const mac = new Uint8Array(
    await hmacSha256(textEncoder.encode(admSecret(env)), `admin|v1|${admUser(env)}|${exp}`)
  )
  return { token: `v1.${exp}.${licHex(mac.slice(0, 16))}`, exp }
}

async function admSession(request, env) {
  if (!admReady(env)) return null
  const parts = admCookieGet(request, ADM_COOKIE).split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') return null

  const exp = Number(parts[1])
  if (!Number.isFinite(exp) || exp * 1000 <= Date.now()) return null

  const mac = new Uint8Array(
    await hmacSha256(textEncoder.encode(admSecret(env)), `admin|v1|${admUser(env)}|${exp}`)
  )
  if (!ctEqual(parts[2].toLowerCase(), licHex(mac.slice(0, 16)))) return null
  return { user: admUser(env), exp }
}

async function admIndex(kv, key) {
  const list = await kvJson(kv, key)
  return Array.isArray(list) ? list : []
}

async function admIndexSave(kv, key, list) {
  await kvSave(kv, key, list.slice(0, ADM_INDEX_CAP))
}

/** 激活码本体：16 位 Crockford base32，展示时按 4 位分组并加 CSH- 前缀。 */
async function licMakeCode(env, serial) {
  const dayNumber = Math.floor((Date.now() - LIC_CODE_EPOCH_MS) / 86400000) & 0xffff
  const payload = Uint8Array.from([
    (dayNumber >> 8) & 0xff,
    dayNumber & 0xff,
    (serial >> 16) & 0xff,
    (serial >> 8) & 0xff,
    serial & 0xff,
  ])
  const mac = new Uint8Array(
    await hmacSha256(textEncoder.encode(String(env.CSH_LICENSE_SECRET)), `code|${licHex(payload)}`)
  )
  const raw = new Uint8Array(10)
  raw.set(payload, 0)
  raw.set(mac.slice(0, 5), 5)
  const body = licBase32Encode(raw)
  return { code: 'CSH-' + body.match(/.{4}/g).join('-'), serial }
}

/** 设备封禁记录。until = 0 表示永久。 */
async function licBanInfo(kv, device) {
  if (!kv || !device) return null
  const rec = await kvJson(kv, ADM_BAN_KEY + device)
  if (!rec) return null
  const until = Number(rec.until) || 0
  if (until > 0 && until <= Date.now()) return null
  return rec
}

function licBanMessage(ban) {
  const until = Number(ban && ban.until) || 0
  const reason = String((ban && ban.reason) || '').trim()
  const tail = until > 0 ? `解封时间 ${new Date(until).toLocaleString('zh-CN')}` : '永久停用'
  return `该设备已被停用${reason ? `（${reason}）` : ''}，${tail}。如有疑问请联系开发者。`
}

/** 激活成功后回写对账索引：哪个码被哪台设备、什么时候用掉。 */
async function licRecordActivation(kv, info) {
  if (!kv) return
  const now = Date.now()
  try {
    const codes = await admIndex(kv, ADM_CODE_INDEX_KEY)
    const serial = Number(info.serial) || 0
    const hit = codes.find((c) => c && Number(c.s) === serial)
    if (hit) {
      hit.u = info.device
      hit.ua = now
      hit.n = Number(hit.n || 0) + 1
      await admIndexSave(kv, ADM_CODE_INDEX_KEY, codes)
    } else if (serial > 0) {
      // 由外部签发工具生成、后台没有记录的码：补一条便于对账
      codes.unshift({ s: serial, c: '', at: 0, note: '外部签发', ext: 1, u: info.device, ua: now, n: 1 })
      await admIndexSave(kv, ADM_CODE_INDEX_KEY, codes)
    }
  } catch {}

  try {
    const devices = await admIndex(kv, ADM_DEV_INDEX_KEY)
    const prev = devices.find((d) => d && d.d === info.device)
    const entry = {
      d: info.device,
      at: now,
      first: (prev && Number(prev.first)) || now,
      tail: String(info.tail || '').slice(0, 8),
      s: Number(info.serial) || 0,
      build: String(info.build || '').slice(0, 96),
      ver: String(info.version || '').slice(0, 32),
    }
    const rest = devices.filter((d) => d && d.d !== info.device)
    await admIndexSave(kv, ADM_DEV_INDEX_KEY, [entry].concat(rest))
  } catch {}
}

/**
 * 设备触点：凡带设备码的客户端请求都记入 lic:d:<device> 与后台设备索引，
 * 不论是否激活过——封禁、对账都以这里见过的设备为准。
 * 同一设备至多每 6 小时刷新一次时间戳，避免每个请求都写存储。
 */
const LIC_TOUCH_TTL_MS = 6 * 3600 * 1000

/** 每来源每天最多登记多少台“首次出现”的设备，挡住随机设备码刷存储。 */
const LIC_DEV_REG_PER_IP_DAY = 500

const LIC_DEV_REG_KEY = 'lic:reg:'

/** 设备码合法形态：16–64 位十六进制（与客户端 DeviceIdentity 输出一致）。 */
function deviceIdOk(device) {
  return /^[0-9a-f]{16,64}$/i.test(String(device || ''))
}

async function licTouchDevice(env, request) {
  const device = String(
    request.headers.get('x-csh-did') || request.headers.get('x-csh-device') || ''
  ).slice(0, 64)
  if (!deviceIdOk(device)) return

  const kv = await gateKv()
  if (!kv) return

  const now = Date.now()
  const build = String(request.headers.get('x-csh-build') || '').slice(0, 96)
  const ver = String(request.headers.get('x-csh-ver') || '').slice(0, 32)

  const S = await settingsOf(env)
  const touchTtlMs = Math.max(1, Number(S.licTouchHours) || 6) * 3600 * 1000
  const regMax = Math.max(1, Number(S.licDeviceRegPerIpDay) || LIC_DEV_REG_PER_IP_DAY)

  const prev = await kvJson(kv, LIC_DEVICE_KEY + device)
  if (prev && now - (Number(prev.at) || 0) < touchTtlMs) return

  // 只有“首次出现”的设备才消耗配额；老设备刷新不计数
  if (!prev) {
    const ipHash = (await sha256Hex(reqIp(request))).slice(0, 24)
    const day = new Date(now).toISOString().slice(0, 10)
    const regKey = `${LIC_DEV_REG_KEY}${ipHash}:${day}`
    const used = Number((await kvJson(kv, regKey))?.n) || 0
    if (used >= regMax) return
    try {
      await kvSave(kv, regKey, { n: used + 1, _exp: now + 2 * 86400 * 1000 })
    } catch {}
  }

  const rec = prev || { tail: '', serial: 0 }
  if (!Number(rec.first) || Number(rec.first) > now) rec.first = now
  rec.at = now
  rec._exp = now + 400 * 24 * 3600 * 1000
  if (build && !rec.build) rec.build = build
  if (ver && !rec.ver) rec.ver = ver
  try {
    await kvSave(kv, LIC_DEVICE_KEY + device, rec)
  } catch {}

  // 索引只用于后台展示：新设备插入，老设备仅刷新时间戳（同样受节流约束）
  try {
    const devices = await admIndex(kv, ADM_DEV_INDEX_KEY)
    const hit = devices.find((d) => d && d.d === device)
    if (hit) {
      if (now - (Number(hit.at) || 0) < touchTtlMs) return
      hit.at = now
      if (build && !hit.build) hit.build = build
      if (ver && !hit.ver) hit.ver = ver
      await admIndexSave(kv, ADM_DEV_INDEX_KEY, devices)
    } else {
      devices.unshift({ d: device, at: now, first: rec.first, tail: '', s: 0, build, ver })
      await admIndexSave(kv, ADM_DEV_INDEX_KEY, devices)
    }
  } catch {}
}

// ══════════════════════════════════════════════════════════════════════
// 设备信誉
//
// 设备码由客户端上报（SystemIdentification.GetSystemIdForPublisher 等），
// 服务端据此做两件事：
//   1. 封禁优先：命中直接 429，换网/换 IP 也甩不掉；
//   2. 敏感接口按设备限速：超每分钟/每日上限即 429，并记一条违规事件。
// 通过时把最近活动写入 lic:ev:<device>（每 10 分钟最多一条），便于事后回溯。
// ══════════════════════════════════════════════════════════════════════

const REP_EVENT_PREFIX = 'lic:ev:'
const REP_EVENT_CAP = 80
const REP_EVENT_THROTTLE_MS = 10 * 60 * 1000

// 路径 → [每分钟参数键, 每日参数键, 出厂每分钟, 出厂每日]。未列出的 /api/* 只做封禁检查。
const REP_TIER_BASE = [
  ['/api/dl-ticket', 'repDlTicketMin', 'repDlTicketDay', 60, 1200],
  ['/api/oss-sign', 'repOssSignMin', 'repOssSignDay', 40, 800],
  ['/api/mirror-sign', 'repMirrorSignMin', 'repMirrorSignDay', 40, 800],
  ['/api/submit', 'repSubmitMin', 'repSubmitDay', 6, 30],
  ['/api/echocave', 'repEchoMin', 'repEchoDay', 20, 200],
  ['/api/feedback', 'repFeedbackMin', 'repFeedbackDay', 10, 100],
  ['/api/license/activate', 'repActivateMin', 'repActivateDay', 10, 60],
]

/** 先按路径找到这一档（不读设置），命中后再算生效值。 */
function repTierBase(pathname) {
  for (const row of REP_TIER_BASE) {
    if (pathname === row[0] || pathname.startsWith(row[0] + '/')) return row
  }
  return null
}

/** 生效上限：后台设置 → 出厂值。 */
function repTierOf(pathname, S) {
  const row = repTierBase(pathname)
  if (!row) return null
  const [, minKey, dayKey, defMin, defDay] = row
  const perMin = Number(S && S[minKey]) > 0 ? Number(S[minKey]) : defMin
  const perDay = Number(S && S[dayKey]) > 0 ? Number(S[dayKey]) : defDay
  return { perMin, perDay }
}

/** 设备事件环形日志。默认 10 分钟节流，避免每个请求都写存储。 */
async function repLogEvent(kv, device, ev) {
  if (!kv || !device) return
  const key = REP_EVENT_PREFIX + device
  try {
    const prev = (await kvJson(kv, key)) || null
    // 同类事件 10 分钟只记一条；换类型（request → rate_limited）立即补记，便于回溯。
    if (prev && Number.isFinite(prev.at) && Date.now() - prev.at < REP_EVENT_THROTTLE_MS && prev.k === ev.kind) return
    const events = Array.isArray(prev && prev.events) ? prev.events : []
    events.unshift({ ts: Date.now(), ...ev })
    await kvSave(kv, key, { at: Date.now(), k: ev.kind, events: events.slice(0, REP_EVENT_CAP) })
  } catch {}
}

/** 每设备每分钟/每日计数。返回 { ok:false } 由调用方转 429。 */
async function repCheck(kv, device, tier, pathname) {
  const day = gateDay()
  const key = 'lic:rep:' + device + ':' + day
  const now = Date.now()
  const minute = Math.floor(now / 60000)
  let rec = (await kvJson(kv, key)) || null
  if (!rec || rec.day !== day) rec = { day, m: minute, mn: 0, n: 0, _exp: now + 2 * 86400000 }
  if (rec.m !== minute) {
    rec.m = minute
    rec.mn = 0
  }
  rec._exp = now + 2 * 86400000
  if (rec.n >= tier.perDay) return { ok: false, scope: 'day', limit: tier.perDay, used: rec.n }
  if (rec.mn >= tier.perMin) return { ok: false, scope: 'minute', limit: tier.perMin, used: rec.mn }
  rec.n += 1
  rec.mn += 1
  await kvSave(kv, key, rec)
  await repLogEvent(kv, device, { kind: 'request', path: pathname })
  // 还没超限、但已逼近分钟上限：交给风险引擎作为“短时突发”的一个信号，
  // 不在这里直接拒绝——单看瞬时频率容易误伤正常批量操作。
  const burst = rec.mn >= Math.max(3, Math.ceil(tier.perMin * 0.75))
  return { ok: true, used: rec.n, limit: tier.perDay, burst }
}

// ══════════════════════════════════════════════════════════════════════
// 恶意请求初步识别（多因子累计风险分）
//
// 原则：
//   1. 只识别、不自动封禁；最终动作由运维在观测台确认；
//   2. 没有单一信号能把分数推到“高风险”——单项权重上限 35，高风险阈值 60，
//      必须多个维度同时命中（例如探测路径 + 扫描器 UA）才会升高；
//   3. 分数按 30 分钟半衰期衰减，短时扫描会累积，正常使用会自然回落；
//   4. 只在命中信号时写存储，并按 30 秒/键节流；正常请求不产生额外 KV 开销。
// ══════════════════════════════════════════════════════════════════════

const RISK_DEVICE_PREFIX = 'lic:risk:d:'
const RISK_IP_PREFIX = 'lic:risk:i:'
const RISK_INDEX_KEY = 'lic:risk:index'
const RISK_INDEX_CAP = 300
const RISK_TTL_MS = 7 * 86400000
const RISK_HALF_MS = 30 * 60 * 1000
const RISK_WRITE_GAP_MS = 30 * 1000
const RISK_HIGH = 60
const RISK_MEDIUM = 35
const RISK_LOW = 15

// 历史证据：回溯扫描只处理“风险引擎上线前”的存量记录，用更长的半衰期（3 天）
// 让旧证据逐步淡出，而不是一上来就按 30 分钟衰减归零。
const RISK_HIST_HALF_MS = 3 * 86400000
const RISK_EVIDENCE_CAP = 400
const RISK_PATH_WINDOW_MS = 15 * 60 * 1000
const RISK_PATH_CAP = 60
const RISK_COMBO_GAP_MS = 15 * 60 * 1000
const RISK_BACKFILL_KEY = 'lic:risk:backfill'

// 单信号权重刻意都低于 RISK_HIGH，避免“一个指标就判死刑”。
const RISK_WEIGHTS = {
  probe_path: 35,
  banned_hit: 30,
  scanner_ua: 25,
  rate_limited: 25,
  auth_brute: 25,
  sensitive_query: 22,
  bad_device_id: 20,
  bad_method: 20,
  path_sweep: 20,
  crawl_sweep: 15,
  header_abuse: 15,
  burst: 12,
  multi_probe: 12,
  headless_ua: 12,
  combo: 10,
  repeat_offender: 10,
  empty_ua: 10,
  script_ua: 10,
  missing_device: 8,
  bot_ua: 8,
  err4xx: 8,
}

const RISK_LABELS = {
  probe_path: '探测敏感路径',
  banned_hit: '封禁后继续请求',
  scanner_ua: '扫描器特征 UA',
  rate_limited: '触发设备限流',
  sensitive_query: '注入/越权参数',
  bad_device_id: '伪造/非法设备码',
  bad_method: '异常请求方法',
  path_sweep: '多路径扫描',
  crawl_sweep: '多路径爬取',
  header_abuse: '请求头异常',
  burst: '短时高频突发',
  multi_probe: '多路径探测',
  headless_ua: '无头浏览器 UA',
  combo: '多类信号组合',
  repeat_offender: '历史风险重现',
  empty_ua: '缺少 User-Agent',
  script_ua: '脚本/命令行 UA',
  missing_device: '敏感接口缺少设备码',
  bot_ua: '爬虫/采集 UA',
  err4xx: '连续 4xx 错误',
  auth_brute: '后台登录爆破',
}

// 由引擎根据上下文推导，不接受请求特征直接注入。
const RISK_DERIVED = new Set(['multi_probe', 'path_sweep', 'combo', 'repeat_offender'])

const RISK_PROBE_RE = /(?:^|\/)(?:\.env|\.git|\.svn|\.hg|\.aws|\.ssh|wp-admin|wp-login|wp-content|phpmyadmin|xmlrpc\.php|cgi-bin|actuator|solr|console|boaform|hnap1|vendor\/phpunit|server-status|docker\.sock)(?:\/|$|\.)|(?:^|\/)\.\.(?:\/|$)|%2e%2e|etc\/passwd|proc\/self\/environ/i
const RISK_INJECT_RE = /(?:union(?:\s|\+|%20)+(?:all(?:\s|\+|%20)+)?select\b|information_schema|sleep\s*\(|benchmark\s*\(|<script|onerror\s*=|javascript:|\bselect\b.+\bfrom\b|\bdrop\s+table\b|\bor\s+1\s*=\s*1\b)/i
const RISK_SCANNER_UA_RE = /(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|nessus|dirbuster|gobuster|wfuzz|ffuf|hydra|wpscan|joomscan|whatweb|pocsuite|xray|goby)/i
const RISK_HEADLESS_UA_RE = /(headlesschrome|phantomjs|puppeteer|playwright|selenium|scrapy)/i
const RISK_SCRIPT_UA_RE = /(curl\/|wget\/|python-requests|python-urllib|go-http-client|java\/|okhttp|libwww|httpclient|axios\/|node-fetch)/i
const RISK_BOT_UA_RE = /(semrushbot|ahrefsbot|mj12bot|petalbot|bytespider|dotbot|blexbot|serpstatbot)/i
const RISK_DEVICE_REQUIRED = new Set(['/api/dl-ticket', '/api/oss-sign', '/api/mirror-sign', '/api/license/activate'])

function riskLevelOf(score) {
  const s = Number(score) || 0
  if (s >= RISK_HIGH) return 'high'
  if (s >= RISK_MEDIUM) return 'medium'
  if (s >= RISK_LOW) return 'low'
  return ''
}

function riskFreshScore(rec, now = Date.now()) {
  const at = Number(rec && rec.at) || now
  const score = Number(rec && rec.s) || 0
  return Math.max(0, Math.round(score * Math.pow(0.5, Math.max(0, now - at) / RISK_HALF_MS)))
}

function riskReasons(rec, compact) {
  const out = []
  for (const [name, r] of Object.entries((rec && rec.r) || {})) {
    if (!RISK_WEIGHTS[name]) continue
    const item = { key: name, label: RISK_LABELS[name] || name, n: Math.max(1, Number(r && r.n) || 1), w: Number(RISK_WEIGHTS[name]) || 0 }
    if (!compact && r && r.last) item.last = Number(r.last) || 0
    if (!compact && r && r.ex) item.ex = String(r.ex).slice(0, 80)
    out.push(item)
  }
  out.sort((a, b) => b.w - a.w || b.n - a.n)
  return compact ? out.map((x) => [x.key, x.n]) : out
}

/** 索引里只存 {信号: 次数}，展示时按权重表还原成带标签的列表。 */
function riskReasonsFromCompact(map) {
  const out = []
  for (const [name, n] of Object.entries(map || {})) {
    const w = Number(RISK_WEIGHTS[name]) || 0
    if (!w) continue
    out.push({ key: name, label: RISK_LABELS[name] || name, n: Math.max(1, Number(n) || 1), w })
  }
  out.sort((a, b) => b.w - a.w || b.n - a.n)
  return out
}

/** 路径/查询参数特征：探测路径与注入风格参数是两类独立证据。 */
function riskPathSignals(path, search) {
  const out = {}
  let decoded = String(path || '')
  try { decoded = decodeURIComponent(decoded) } catch {}
  decoded = decoded.slice(0, 200)
  if (RISK_PROBE_RE.test(decoded)) out.probe_path = decoded.slice(0, 80)
  let query = String(search || '').slice(0, 300)
  try { query = decodeURIComponent(query) } catch {}
  if (RISK_INJECT_RE.test(decoded + '?' + query)) out.sensitive_query = `${decoded}?${query}`.slice(0, 80)
  return out
}

/** UA 分类：扫描器 > 无头浏览器 > 脚本客户端 > 采集爬虫 > 空 UA。 */
function riskUaSignal(ua) {
  const text = String(ua || '')
  if (!text) return { empty_ua: 1 }
  if (RISK_SCANNER_UA_RE.test(text)) return { scanner_ua: text.slice(0, 60) }
  if (RISK_HEADLESS_UA_RE.test(text)) return { headless_ua: text.slice(0, 60) }
  if (RISK_SCRIPT_UA_RE.test(text)) return { script_ua: text.slice(0, 60) }
  if (RISK_BOT_UA_RE.test(text)) return { bot_ua: text.slice(0, 60) }
  return {}
}

function riskMethodSignal(method) {
  const m = String(method || 'GET').toUpperCase()
  return ['GET', 'HEAD', 'POST', 'OPTIONS'].includes(m) ? {} : { bad_method: m }
}

/** 只读取请求本身的特征，不产生存储写入。 */
function riskSignalsOf(request, url) {
  const out = { ...riskPathSignals(url.pathname, url.search), ...riskUaSignal(request.headers.get('user-agent')) }
  Object.assign(out, riskMethodSignal(request.method))

  let headerCount = 0
  let huge = 0
  try {
    for (const [, value] of request.headers) {
      headerCount++
      if (String(value).length > 4096) huge++
    }
  } catch {}
  if (headerCount > 64 || huge) out.header_abuse = `h${headerCount}/v${huge}`

  const rawDid = String(request.headers.get('x-csh-did') || request.headers.get('x-csh-device') || '').trim()
  if (rawDid && !deviceIdOk(rawDid)) out.bad_device_id = rawDid.slice(0, 40)
  if (!deviceIdOk(rawDid) && RISK_DEVICE_REQUIRED.has(url.pathname)) out.missing_device = 1
  return out
}

/** 历史日志只有字段没有 Request 对象，用同一套规则还原信号。 */
function riskHistSignalsOfEvent(ev) {
  const out = { ...riskPathSignals(ev.path, ev.query), ...riskUaSignal(ev.ua) }
  Object.assign(out, riskMethodSignal(ev.method))
  const status = Number(ev.status) || 0
  if ([401, 403, 404, 405].includes(status)) out.err4xx = status
  return out
}

// 同一键、同一组信号在 30 秒内只写一次；出现新信号（例如先探测、后扫描器）立即补写。
// 另外在内存里跟踪 15 分钟内的不同路径：扫描器会在几秒内扫过大量路径，
// 达到 3 / 8 个时强制补写一次，让“多路径探测 / 多路径扫描”能及时体现，
// 同时其余重复请求仍被节流，不会把 404 洪水放大成写风暴。
const riskSeen = new Map()
function riskAllowWrite(key, signals, now, path) {
  const names = Object.keys(signals).sort().join(',')
  let entry = riskSeen.get(key)
  if (!entry || now - entry.at > 10 * 60 * 1000) {
    entry = { at: 0, names: '', paths: new Map() }
    riskSeen.set(key, entry)
  }
  const track = path && (signals.probe_path || signals.sensitive_query || signals.err4xx)
  let sweep = 0
  if (track) {
    for (const [h, ts] of entry.paths) if (now - ts > RISK_PATH_WINDOW_MS) entry.paths.delete(h)
    entry.paths.set(riskFnv(path), now)
    const n = entry.paths.size
    if (n === 3 || n === 8) sweep = n
  }
  const allow = !!sweep || !entry.at || now - entry.at >= RISK_WRITE_GAP_MS || entry.names !== names
  if (allow) {
    entry.at = now
    entry.names = names
  }
  if (riskSeen.size > 2000) {
    for (const [k, v] of riskSeen) if (now - v.at > 10 * 60 * 1000) riskSeen.delete(k)
  }
  return { allow, sweep }
}

async function riskIndexGet(kv) {
  const rec = await kvJson(kv, RISK_INDEX_KEY)
  return Array.isArray(rec && rec.items) ? rec.items : []
}

/** 稳定的 32 位散列，只用于内部键（路径/证据去重），不参与安全判定。 */
function riskFnv(text) {
  let h = 0x811c9dc5
  const s = String(text || '')
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(36)
}

function riskEvidenceHash(ev) {
  return riskFnv(`${ev.id || ''}|${ev.ts || ''}|${ev.ip || ''}|${ev.path || ''}|${ev.ua || ''}|${ev.status || ''}`)
}

/** 历史分：单个信号随重复次数缓慢加成（最多 1.5 倍），多类信号自然叠加，封顶 100。 */
function riskHistScore(hb) {
  let sum = 0
  for (const [name, r] of Object.entries(hb || {})) {
    const w = Number(RISK_WEIGHTS[name]) || 0
    if (!w) continue
    const n = Math.max(1, Number(r && r.n) || 1)
    sum += Math.round(w * Math.min(1.5, 1 + 0.05 * Math.log2(n)))
  }
  return Math.min(100, sum)
}

/** 历史分按“最新证据时间”锚定、3 天半衰期折算，旧证据逐步淡出。 */
function riskHistFresh(rec, now = Date.now()) {
  const at = Number(rec && rec.hat) || 0
  if (!at) return 0
  const score = Number(rec && rec.hs) || 0
  return Math.max(0, Math.round(score * Math.pow(0.5, Math.max(0, now - at) / RISK_HIST_HALF_MS)))
}

/** 实时分与历史分取较大值：两者都是“同一对象可疑程度”的估计，取 max 避免重复计分。 */
function riskCombinedFresh(rec, now = Date.now()) {
  return Math.max(riskFreshScore(rec, now), riskHistFresh(rec, now))
}

function riskHistReasons(rec, compact) {
  const out = []
  for (const [name, r] of Object.entries((rec && rec.hb) || {})) {
    if (!RISK_WEIGHTS[name]) continue
    const item = { key: name, label: RISK_LABELS[name] || name, n: Math.max(1, Number(r && r.n) || 1), w: Number(RISK_WEIGHTS[name]) || 0 }
    if (!compact && r && r.last) item.last = Number(r.last) || 0
    if (!compact && r && r.ex) item.ex = String(r.ex).slice(0, 80)
    out.push(item)
  }
  out.sort((a, b) => b.w - a.w || b.n - a.n)
  return compact ? out.map((x) => [x.key, x.n]) : out
}

/**
 * 上下文推导信号：单看一条请求看不出来的“扫描面”。
 *   multi_probe   15 分钟内命中 ≥3 个不同路径
 *   path_sweep    15 分钟内命中 ≥8 个不同路径
 *   combo         同一窗口内 ≥4 类信号（每 15 分钟最多记一次）
 *   repeat_offender 历史证据仍有效时再次命中
 */
function riskDerive(rec, signals, meta) {
  const out = {}
  const now = meta.now
  const path = String(meta.path || '')
  if (path && (signals.probe_path || signals.sensitive_query || signals.err4xx)) {
    const map = rec.p && typeof rec.p === 'object' ? rec.p : {}
    for (const [k, v] of Object.entries(map)) if (now - Number(v) > RISK_PATH_WINDOW_MS) delete map[k]
    map[riskFnv(path)] = now
    const keys = Object.keys(map)
    if (keys.length > RISK_PATH_CAP) {
      keys.sort((a, b) => Number(map[a]) - Number(map[b]))
      for (const k of keys.slice(0, keys.length - RISK_PATH_CAP)) delete map[k]
    }
    rec.p = map
    const n = Math.max(Math.min(keys.length, RISK_PATH_CAP), Number(meta.sweep) || 0)
    if (n >= 3) out.multi_probe = `${n} 个不同路径`
    if (n >= 8) out.path_sweep = `${n} 个不同路径`
  }

  const recent = new Set(Object.keys(signals))
  for (const [name, r] of Object.entries(rec.r || {})) {
    if (RISK_DERIVED.has(name)) continue
    if (now - Number(r && r.last) <= RISK_COMBO_GAP_MS) recent.add(name)
  }
  if (recent.size >= 4 && now - (Number(rec.cbt) || 0) > RISK_COMBO_GAP_MS) {
    out.combo = `${recent.size} 类信号`
    rec.cbt = now
  }

  if (riskHistFresh(rec, now) >= RISK_LOW && now - (Number(rec.rpt) || 0) > RISK_COMBO_GAP_MS) {
    out.repeat_offender = `历史 ${riskHistFresh(rec, now)} 分`
    rec.rpt = now
  }
  return out
}

async function riskIndexPut(kv, kind, id, rec, now) {
  try {
    const items = await riskIndexGet(kv)
    const compact = {}
    for (const [name, n] of riskReasons(rec, true)) compact[name] = n
    const hcompact = {}
    for (const [name, n] of riskHistReasons(rec, true)) hcompact[name] = n
    const item = {
      k: kind,
      id: String(id).slice(0, 64),
      s: Number(rec.s) || 0,
      at: Number(rec.at) || now,
      h: Number(rec.hits) || 0,
      r: compact,
      hs: Number(rec.hs) || 0,
      hat: Number(rec.hat) || 0,
      hr: hcompact,
    }
    if (kind === 'i') item.ip = String(rec.ip || id).slice(0, 64)
    const total = riskCombinedFresh(item, now)
    const at = items.findIndex((x) => x && x.k === kind && x.id === item.id)
    if (at >= 0) items[at] = item
    else if (total >= RISK_LOW) items.push(item)
    else return
    items.sort((a, b) => riskCombinedFresh(b, now) - riskCombinedFresh(a, now) || (Number(b.at) || 0) - (Number(a.at) || 0))
    await kvSave(kv, RISK_INDEX_KEY, { at: now, items: items.slice(0, RISK_INDEX_CAP) })
  } catch {}
}

async function riskApply(kv, kind, key, id, signals, meta) {
  const gate = riskAllowWrite(kind + ':' + key, signals, meta.now, meta.path)
  if (!gate.allow) return null
  if (gate.sweep) meta.sweep = gate.sweep
  const storageKey = (kind === 'd' ? RISK_DEVICE_PREFIX : RISK_IP_PREFIX) + key
  let rec = await kvJson(kv, storageKey)
  if (!rec || !alive(rec)) rec = { s: 0, at: meta.now, r: {}, hits: 0 }
  rec.s = riskFreshScore(rec, meta.now)
  const derived = riskDerive(rec, signals, meta)
  let add = 0
  for (const [name, info] of Object.entries({ ...signals, ...derived })) {
    if (RISK_DERIVED.has(name) && !(name in derived)) continue
    const w = Number(RISK_WEIGHTS[name]) || 0
    if (!w) continue
    add += w
    const r = rec.r[name] || { n: 0 }
    r.n = Math.min(999, (Number(r.n) || 0) + 1)
    r.w = w
    r.last = meta.now
    if (typeof info === 'string' && info) r.ex = String(info).slice(0, 80)
    rec.r[name] = r
  }
  if (!add && !rec.s) return rec
  rec.s = Math.min(100, Math.round((Number(rec.s) || 0) + add))
  rec.at = meta.now
  rec.hits = Math.min(99999, (Number(rec.hits) || 0) + 1)
  if (meta.ip) rec.ip = String(meta.ip).slice(0, 64)
  rec._exp = meta.now + RISK_TTL_MS
  try {
    await kvSave(kv, storageKey, rec)
    await riskIndexPut(kv, kind, id, rec, meta.now)
  } catch {}
  return rec
}

/**
 * 历史证据批量入账：同一批事件读一次、写一次；证据哈希去重，重复执行不会叠加。
 * 历史分每次都由 hb 计数重算（而不是在原分上累加），因此天然幂等。
 */
async function riskHistApplyMany(kv, kind, key, id, events, meta) {
  if (!Array.isArray(events) || !events.length) return { added: 0, skipped: 0 }
  const storageKey = (kind === 'd' ? RISK_DEVICE_PREFIX : RISK_IP_PREFIX) + key
  let rec = await kvJson(kv, storageKey)
  if (!rec || !alive(rec)) rec = { s: 0, at: meta.now, r: {}, hits: 0 }
  const hid = rec.hid && typeof rec.hid === 'object' ? rec.hid : {}
  const hb = rec.hb && typeof rec.hb === 'object' ? rec.hb : {}
  let added = 0
  let skipped = 0
  let newest = Number(rec.hat) || 0
  for (const ev of events) {
    const ts = Number(ev.ts) || meta.now
    const eh = riskEvidenceHash(ev)
    if (hid[eh]) { skipped++; continue }
    hid[eh] = ts
    const sigs = ev._signals || riskHistSignalsOfEvent(ev)
    for (const [name, info] of Object.entries(sigs)) {
      if (!RISK_WEIGHTS[name]) continue
      const e = hb[name] || { n: 0, first: ts, last: ts }
      e.n = Math.min(999, (Number(e.n) || 0) + 1)
      e.first = Math.min(Number(e.first) || ts, ts)
      e.last = Math.max(Number(e.last) || 0, ts)
      if (typeof info === 'string' && info) e.ex = String(info).slice(0, 80)
      hb[name] = e
      newest = Math.max(newest, ts)
    }
    added++
  }
  if (!added) return { added: 0, skipped, rec }
  const entries = Object.entries(hid).sort((a, b) => Number(a[1]) - Number(b[1]))
  if (entries.length > RISK_EVIDENCE_CAP) {
    for (const [k] of entries.slice(0, entries.length - RISK_EVIDENCE_CAP)) delete hid[k]
  }
  // 路径覆盖度：探测/注入/扫描器/4xx 达到一定条数才算“扫描面”，
  // 普通爬取则要求更多不同记录，避免把少量 404 误判成扫描。
  const distinct = Object.keys(hid).length
  const strong =
    (Number(hb.probe_path && hb.probe_path.n) || 0) > 0 ||
    (Number(hb.sensitive_query && hb.sensitive_query.n) || 0) > 0 ||
    (Number(hb.scanner_ua && hb.scanner_ua.n) || 0) > 0
  const firstProbe = Math.min(
    Number(hb.probe_path && hb.probe_path.first) || newest,
    Number(hb.sensitive_query && hb.sensitive_query.first) || newest,
    Number(hb.err4xx && hb.err4xx.first) || newest,
  )
  if (strong && distinct >= 3) hb.multi_probe = { n: distinct, first: firstProbe, last: newest, ex: `${distinct} 条可疑记录` }
  else delete hb.multi_probe
  if (strong && distinct >= 8) hb.path_sweep = { n: distinct, first: firstProbe, last: newest, ex: `${distinct} 条可疑记录` }
  else delete hb.path_sweep
  if (!strong && distinct >= 20) hb.crawl_sweep = { n: distinct, first: firstProbe, last: newest, ex: `${distinct} 条记录` }
  else delete hb.crawl_sweep
  rec.hid = hid
  rec.hb = hb
  rec.hs = riskHistScore(hb)
  rec.hat = newest
  if (!meta.dryRun) {
    rec._exp = Math.max(Number(rec._exp) || 0, meta.now + RISK_TTL_MS)
    if (meta.ip) rec.ip = String(meta.ip).slice(0, 64)
    try {
      await kvSave(kv, storageKey, rec)
      await riskIndexPut(kv, kind, id, rec, meta.now)
    } catch {}
  }
  return { added, skipped, rec }
}

/** 后台展示用摘要：分数按半衰期折算到此刻，等级随分数实时变化，不额外写存储。 */
function riskSummary(rec, now = Date.now()) {
  if (!rec || typeof rec !== 'object') return null
  const live = riskFreshScore(rec, now)
  const hist = riskHistFresh(rec, now)
  const s = Math.max(live, hist)
  return {
    s,
    level: riskLevelOf(s),
    ls: live,
    at: Number(rec.at) || 0,
    hits: Number(rec.hits) || 0,
    ip: String(rec.ip || ''),
    hs: hist,
    hat: Number(rec.hat) || 0,
    reasons: riskReasons(rec, false),
    histReasons: riskHistReasons(rec, false),
  }
}

/**
 * 记录一次风险信号。signals 传 null 表示现场计算请求特征；传 {} 表示只记 extra。
 * 未登记的设备码不建风险记录（否则随机 16 进制 ID 可以无限撑大存储），只记 IP 维度。
 * force=true 时允许记录后台路径（仅用于登录爆破这类必须观测的异常）。
 */
async function riskObserve(request, env, signals, extra, force) {
  try {
    const url = new URL(request.url)
    if (!force && url.pathname.startsWith('/api/admin/')) return
    const base = signals === null || signals === undefined ? riskSignalsOf(request, url) : signals
    const all = { ...base, ...(extra || {}) }
    if (!Object.keys(all).length) return
    const kv = await gateKv()
    if (!kv) return
    const now = Date.now()
    const ip = reqIp(request)
    const meta = { now, ip, path: url.pathname.slice(0, 200) }
    const device = deviceIdOf(request)
    if (device) {
      const known = await kvJson(kv, LIC_DEVICE_KEY + device)
      if (known && alive(known)) await riskApply(kv, 'd', device, device, all, meta)
    }
    if (ip && ip !== 'unknown') {
      const key = (await sha256Hex(ip)).slice(0, 24)
      await riskApply(kv, 'i', key, ip, all, meta)
    }
  } catch {}
}

/**
 * 设备信誉闸门：返回 null = 放行；返回 Response = 直接回绝（封禁与超限都是 429）。
 * 无设备码的请求不在这里处理，仍由各接口自己的 IP/配额逻辑兜底。
 */
async function deviceGuard(request, env, info) {
  const url = new URL(request.url)
  if (!url.pathname.startsWith('/api/') || url.pathname.startsWith('/api/admin/')) return null
  const device = deviceIdOf(request)
  if (!device) return null

  const kv = await gateKv()
  if (!kv) return null

  const ban = await licBanInfo(kv, device)
  if (ban) {
    await repLogEvent(kv, device, { kind: 'banned', path: url.pathname })
    if (info) info.banned_hit = 1
    return json(
      { error: licBanMessage(ban), code: 'csh_device_banned', until: Number(ban.until) || 0 },
      429,
      request,
      env
    )
  }

  if (!repTierBase(url.pathname)) return null
  const tier = repTierOf(url.pathname, await settingsOf(env))
  if (!tier) return null

  const r = await repCheck(kv, device, tier, url.pathname)
  if (r.ok) {
    // 逼近分钟上限只是“观测信号”，不在这里拒绝——单一频率指标不足以定性。
    if (r.burst && info) info.burst = `${url.pathname}:${r.used}/${r.limit}`
    return null
  }

  await repLogEvent(kv, device, {
    kind: 'rate_limited',
    path: url.pathname,
    scope: r.scope,
    used: r.used,
    limit: r.limit,
  })
  if (info) info.rate_limited = `${url.pathname}:${r.scope}:${r.used}/${r.limit}`
  return json(
    {
      error:
        r.scope === 'minute'
          ? `请求过于频繁（每分钟最多 ${r.limit} 次），请稍后再试。`
          : `今天的请求次数已达上限（${r.limit} 次），请明天再试。`,
      code: 'csh_device_rate_limited',
      scope: r.scope,
      limit: r.limit,
      used: r.used,
    },
    429,
    request,
    env
  )
}

function licEnforce(env, S) {
  // 后台显式设置过就以设置为准，否则回落到环境变量的旧语义
  if (S && typeof S.licEnforce === 'boolean') {
    if (S.licEnforce) return true
    const at = Date.parse(String(S.licEnforceAt || ''))
    return Number.isFinite(at) && Date.now() >= at
  }
  if (String((env && env.CSH_LIC_ENFORCE) ?? '').toLowerCase() === 'true') return true
  // 定时开闸：到点自动生效，避免「到日子还得有人记得去控制台改一下再重新部署」。
  const at = Date.parse(String((env && env.CSH_LIC_ENFORCE_AT) || ''))
  return Number.isFinite(at) && Date.now() >= at
}

function licBytesFromHex(hex) {
  const text = String(hex || '').trim().toLowerCase()
  if (text.length === 0 || text.length % 2 !== 0 || !/^[0-9a-f]+$/.test(text)) return null
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

function licHex(bytes) {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

function licSameBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

function licBase32Encode(bytes) {
  let bits = 0
  let value = 0
  let out = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      out += LIC_CODE_ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += LIC_CODE_ALPHABET[(value << (5 - bits)) & 31]
  return out
}

function licBase32Decode(text) {
  const out = []
  let bits = 0
  let value = 0
  for (const ch of String(text || '').toUpperCase()) {
    const index = LIC_CODE_ALPHABET.indexOf(ch)
    if (index < 0) continue
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255)
      bits -= 8
    }
  }
  return Uint8Array.from(out)
}

function licB64Url(bytes) {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function licB64UrlDecode(text) {
  const padded = String(text || '').replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

/** 构建签名 = HMAC-SHA256(CSH_BUILD_SECRET, "v1|<buildId>")，与打包脚本同一算法。 */
async function licVerifyBuild(buildId, signature, env) {
  if (!buildId || !signature) return false
  if (buildId.length > 96 || buildId.indexOf('|') >= 0) return false

  const provided = licBytesFromHex(signature)
  if (!provided || provided.length !== 32) return false

  const payload = `v1|${buildId}`
  const secrets = [env.CSH_BUILD_SECRET, env.CSH_BUILD_SECRET_OLD]
  for (const secret of secrets) {
    if (!secret) continue
    const mac = new Uint8Array(await hmacSha256(textEncoder.encode(String(secret)), payload))
    if (licSameBytes(mac, provided)) return true
  }
  return false
}

/**
 * 归一化用户提交的激活码：去分隔符、转大写，并剥掉签发工具加的可读前缀。
 * 签发端输出 `CSH-XXXX-XXXX-XXXX-XXXX`，本体只有 16 位；用户从聊天窗口复制时
 * 还会夹带空格、全角连字符，所以两端都按同一规则处理。
 */
function licNormalizeCode(input) {
  const text = String(input || '').replace(/[^0-9A-Za-z]/g, '').toUpperCase()
  return text.length === LIC_CODE_LEN + 3 && text.startsWith('CSH') ? text.slice(3) : text
}

/**
 * 激活码：16 个字符（Crockford base32 去掉 I/L/O/U）。
 * payload 5 字节 = 签发起始日（自 2020-01-01 的天数, uint16 BE）+ 序列号（uint24 BE）
 * mac     5 字节 = HMAC-SHA256(CSH_LICENSE_SECRET, "code|<payload hex>")[0..5]
 * 纯离线校验，不建表；作废靠换密钥或维护黑名单。
 */
async function licVerifyCode(code, env) {
  const raw = licBase32Decode(code)
  if (raw.length !== 10) return { ok: false, reason: 'format' }

  const payload = raw.slice(0, 5)
  const mac = raw.slice(5)
  const expected = new Uint8Array(
    await hmacSha256(textEncoder.encode(String(env.CSH_LICENSE_SECRET)), `code|${licHex(payload)}`)
  )
  if (!licSameBytes(expected.slice(0, 5), mac)) return { ok: false, reason: 'signature' }

  const days = (payload[0] << 8) | payload[1]
  const serial = (payload[2] << 16) | (payload[3] << 8) | payload[4]
  return { ok: true, issuedAt: LIC_CODE_EPOCH_MS + days * 86400000, serial }
}

/** 令牌 = base64url(payloadJSON) + "." + base64url(HMAC-SHA256(secret, payloadJSON)[0..16]) */
async function licIssueToken(device, hint, days, env) {
  const lifespan = Number(days > 0 ? days : (env.CSH_LICENSE_DAYS || 365))
  const payload = {
    v: 1,
    d: String(device || '').slice(0, 64),
    e: lifespan > 0 ? Math.floor(Date.now() / 1000) + lifespan * 86400 : 0,
    n: String(hint || '').slice(0, 16),
  }
  const body = textEncoder.encode(JSON.stringify(payload))
  const mac = new Uint8Array(await hmacSha256(textEncoder.encode(String(env.CSH_LICENSE_SECRET)), body))
  return { token: `${licB64Url(body)}.${licB64Url(mac.slice(0, 16))}`, payload }
}

async function licVerifyToken(token, device, env) {
  if (!token || token.indexOf('.') < 0) return null

  const parts = String(token).split('.')
  if (parts.length !== 2) return null

  let body
  let mac
  try {
    body = licB64UrlDecode(parts[0])
    mac = licB64UrlDecode(parts[1])
  } catch {
    return null
  }
  if (body.length === 0 || mac.length !== 16) return null

  const expected = new Uint8Array(await hmacSha256(textEncoder.encode(String(env.CSH_LICENSE_SECRET)), body))
  if (!licSameBytes(expected.slice(0, 16), mac)) return null

  let payload
  try {
    payload = JSON.parse(new TextDecoder().decode(body))
  } catch {
    return null
  }
  if (!payload || payload.v !== 1) return null
  if (payload.d && payload.d !== device) return null
  if (payload.e && payload.e * 1000 <= Date.now()) return null
  return payload
}

/**
 * 网页端豁免：浏览器发起的请求没有构建签名，靠来源与 fetch 元数据识别。
 * ⚠️ sec-fetch-mode 是浏览器的禁止修改头，普通 HTTP 客户端不会带 —— 提高伪造门槛，不是安全边界。
 */
function licBrowserAllowed(request, env) {
  if (!request.headers.get('sec-fetch-mode')) return false

  const raw = request.headers.get('origin') || request.headers.get('referer') || ''
  let host
  try {
    host = new URL(raw).hostname.toLowerCase()
  } catch {
    return false
  }

  const list = String(env.CSH_LIC_BROWSER_ORIGINS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
  return list.some((allowed) => host === allowed || host.endsWith('.' + allowed))
}

/** 旧客户端豁免窗口：完全不带构建标识的版本在截止日前照常放行。 */
function licLegacyOpen(env, S) {
  const until = String((S && S.licLegacyUntil) || env.CSH_LIC_LEGACY_UNTIL || '').trim()
  if (!until) return false
  const at = Date.parse(until)
  return Number.isFinite(at) && Date.now() < at
}

/**
 * 闸门。返回 null = 放行；{ deny } = 直接回绝；{ headers } = 放行并把响应头合并进真实响应
 * （官方构建首次访问时下发短期令牌，客户端存下后就不再重复验签）。
 */
async function licenseGuard(request, env) {
  const url = new URL(request.url)
  if (!LIC_GATED_PREFIXES.some((prefix) => url.pathname === prefix || url.pathname.startsWith(prefix))) {
    return null
  }

  const device = String(
    request.headers.get('x-csh-device') || request.headers.get('x-csh-did') || ''
  ).slice(0, 64)
  const build = String(request.headers.get('x-csh-build') || '').trim()
  const signature = String(request.headers.get('x-csh-sig') || '').trim()

  // 封禁先于授权判定：被停用的设备即使令牌仍在有效期内也挡下来
  if (device) {
    const kv = await gateKv()
    const ban = await licBanInfo(kv, device)
    if (ban) {
      return {
        deny: json(
          { error: licBanMessage(ban), code: 'csh_device_banned', until: Number(ban.until) || 0 },
          403,
          request,
          env
        ),
      }
    }
  }

  if (env.CSH_LICENSE_SECRET) {
    const payload = await licVerifyToken(request.headers.get('x-csh-lic'), device, env)
    if (payload) return null
  }

  let headers = null
  if (build && await licVerifyBuild(build, signature, env)) {
    if (env.CSH_LICENSE_SECRET) {
      // 官方构建只发短期令牌：密钥轮换或构建号作废后，最多一个周期自然失效
      const S = await settingsOf(env)
      const officialDays = Math.max(1, Number(S.licOfficialDays) || 30)
      const issued = await licIssueToken(device, 'official', officialDays, env)
      headers = { 'X-CSH-Lic': issued.token, 'X-CSH-Lic-Exp': String(issued.payload.e) }
    } else {
      headers = null
    }
    return headers ? { headers } : null
  }

  const settings = await settingsOf(env)
  const exempt = (!build && licLegacyOpen(env, settings)) || licBrowserAllowed(request, env)
  if (exempt) return null

  if (!licEnforce(env, settings)) {
    console.warn(`license: would deny ${url.pathname} build=${build || '(none)'}`)
    return null
  }

  return { deny: json(LIC_DENY_BODY, 403, request, env) }
}

/** POST /api/license/activate —— 激活码换令牌。兑换本身不能要求授权，否则死循环。 */
async function handleLicenseActivate(request, env) {
  if (request.method !== 'POST') return json({ error: '只接受 POST' }, 405, request, env)
  if (!env.CSH_LICENSE_SECRET) return json({ error: '激活服务未配置' }, 503, request, env)

  let body
  try {
    body = await request.json()
  } catch {
    return json({ error: '请求格式错误' }, 400, request, env)
  }

  const code = licNormalizeCode(body?.code)
  const device = String(body?.device || '').slice(0, 64)
  if (code.length !== LIC_CODE_LEN) {
    return json({ error: `激活码长度不对（应为 ${LIC_CODE_LEN} 个字符）。` }, 400, request, env)
  }
  if (!device) return json({ error: '缺少设备码。' }, 400, request, env)
  if (!deviceIdOk(device)) return json({ error: '设备码格式不对。' }, 400, request, env)

  const kv = await gateKv()

  // 被封禁的设备连换码的机会都没有，避免「换个码继续用」
  if (kv) {
    const ban = await licBanInfo(kv, device)
    if (ban) {
      return json({ error: licBanMessage(ban), code: 'csh_device_banned', until: Number(ban.until) || 0 }, 429, request, env)
    }
    const rep = await repCheck(kv, device, { perMin: 10, perDay: 60 }, LIC_ACTIVATE_PATH)
    if (!rep.ok) {
      await repLogEvent(kv, device, { kind: 'rate_limited', path: LIC_ACTIVATE_PATH, scope: rep.scope })
      return json(
        {
          error: rep.scope === 'minute' ? '激活尝试过于频繁，请稍后再试。' : '今日激活尝试次数过多，请明天再试。',
          code: 'csh_device_rate_limited',
          scope: rep.scope,
          limit: rep.limit,
          used: rep.used,
        },
        429,
        request,
        env
      )
    }
  }

  // 防爆破：同一来源每日尝试次数上限（来源 IP 以边缘写入的可信头为准）
  const src = (await sha256Hex(reqIp(request))).slice(0, 24)
  const tryLimit = Math.max(1, Number((await settingsOf(env)).licTryPerDay) || 30)
  const day = gateDay()
  const tryKey = LIC_TRY_KEY + day + ':' + src
  if (kv) {
    let rec = (await kvJson(kv, tryKey)) || null
    if (!alive(rec) || rec.day !== day) rec = { day, n: 0, _exp: Date.now() + 36 * 3600 * 1000 }
    const limit = tryLimit
    if (rec.n >= limit) {
      return json({ error: '今日激活尝试次数过多，请明天再试或把设备码发给开发者。' }, 429, request, env)
    }
    rec.n = Number(rec.n) + 1
    try { await kvSave(kv, tryKey, rec) } catch {}
  }

  const check = await licVerifyCode(code, env)
  if (!check.ok) {
    return json({ error: check.reason === 'signature' ? '激活码无效。' : '激活码格式不对。' }, 400, request, env)
  }

  // 吊销只对「尚未激活」的码有效：已发出去的令牌是离线凭证，收不回来，
  // 要连带失效只能封禁设备或轮换 CSH_LICENSE_SECRET。
  if (kv) {
    try {
      const codes = await admIndex(kv, ADM_CODE_INDEX_KEY)
      const hit = codes.find((c) => c && Number(c.s) === Number(check.serial))
      if (hit && hit.r) return json({ error: '激活码已被吊销，请联系开发者重新获取。' }, 403, request, env)
    } catch {}
  }

  const licDays = Math.max(1, Number((await settingsOf(env)).licDays) || 365)
  const issued = await licIssueToken(device, code.slice(-4), licDays, env)

  const deviceRec = {
    at: Date.now(),
    tail: code.slice(-4),
    serial: check.serial,
    build: String(body?.build || '').slice(0, 96),
    ver: String(body?.version || '').slice(0, 32),
    _exp: Date.now() + 400 * 24 * 3600 * 1000,
  }
  if (kv) {
    try { await kvSave(kv, LIC_DEVICE_KEY + device, deviceRec) } catch {}
    try { await repLogEvent(kv, device, { kind: 'activate', serial: check.serial }) } catch {}
    try {
      await licRecordActivation(kv, {
        device,
        serial: check.serial,
        tail: code.slice(-4),
        build: deviceRec.build,
        version: deviceRec.ver,
      })
    } catch {}
  }

  return json({
    success: true,
    message: '激活成功。',
    token: issued.token,
    expiresAt: issued.payload.e,
  }, 200, request, env)
}

// ── 后台接口 ─────────────────────────────────────────────────────────

function admLicenseSnapshot(env, S) {
  const s = S || {}
  return {
    enforce: licEnforce(env, S),
    enforceAt: String(s.licEnforceAt || '') || null,
    legacyUntil: String(s.licLegacyUntil || '') || null,
    days: Number(s.licDays) || 365,
    officialDays: Number(s.licOfficialDays) || 30,
    buildSecret: !!env.CSH_BUILD_SECRET,
    licenseSecret: !!env.CSH_LICENSE_SECRET,
  }
}

/** POST /api/admin/login */
async function handleAdminLogin(request, env) {
  if (!admSameOrigin(request)) return admJson({ error: '来源校验失败，请直接打开后台页面登录。' }, 403)
  if (!admReady(env)) {
    return admJson(
      {
        error: '后台未配置',
        detail: '需在环境变量里设置 CSH_ADMIN_PASS（或 CSH_ADMIN_PASS_SHA256）与 CSH_LICENSE_SECRET。',
      },
      503
    )
  }

  let body
  try {
    body = await request.json()
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }

  const user = String(body?.user || '').trim().slice(0, 64)
  const pass = String(body?.pass || '')
  const kv = await gateKv()
  const failKey = ADM_FAIL_KEY + (await sha256Hex(reqIp(request))).slice(0, 24)
  const S = await settingsOf(env)
  const failLimit = Math.max(1, Number(S.admLoginFailLimit) || ADM_LOGIN_FAIL_LIMIT)
  const failWindowMs = Math.max(60000, (Number(S.admLoginFailWindowMin) || 30) * 60000)

  if (kv) {
    const rec = await kvJson(kv, failKey)
    if (rec && Number(rec.n) >= failLimit && Number(rec._exp) > Date.now()) {
      const mins = Math.max(1, Math.ceil((Number(rec._exp) - Date.now()) / 60000))
      return admJson({ error: `密码错误次数过多，请 ${mins} 分钟后再试。` }, 429)
    }
  }

  const okUser = ctEqual(user, admUser(env))
  const okPass = await admPasswordOk(env, pass)
  if (!okUser || !okPass) {
    if (kv) {
      const rec = (await kvJson(kv, failKey)) || { n: 0 }
      const n = (Number(rec.n) || 0) + 1
      try {
        await kvSave(kv, failKey, { n, _exp: Date.now() + failWindowMs })
      } catch {}
      // 后台登录连续失败是典型的爆破信号；第 3 次起计入风险分（30 秒节流）。
      if (n >= 3) await riskObserve(request, env, {}, { auth_brute: '/api/admin/login' }, true)
    }
    console.warn(`admin: login failed from ${reqIp(request)}`)
    return admJson({ error: '账号或密码不正确。' }, 401)
  }

  if (kv) {
    try {
      await kv.delete(failKey)
    } catch {}
  }

  const sessionHours = Math.max(1, Number(S.admSessionHours) || ADM_SESSION_TTL_HOURS)
  const issued = await admIssueSession(env, sessionHours)
  console.log(`admin: ${admUser(env)} logged in`)
  return admJson({ ok: true, user: admUser(env), exp: issued.exp }, 200, {
    'Set-Cookie': admCookieSet(issued.token, Math.round(sessionHours * 3600)),
  })
}

/** POST /api/admin/logout */
async function handleAdminLogout(request, env) {
  return admJson({ ok: true }, 200, { 'Set-Cookie': admCookieSet('', 0) })
}

/** GET /api/admin/session —— 页面加载时用它决定显示登录框还是控制台。 */
async function handleAdminSession(request, env) {
  const sess = await admSession(request, env)
  if (!sess) return admJson({ ok: false, ready: admReady(env) }, 401)
  const S = await settingsOf(env)
  return admJson({
    ok: true,
    user: sess.user,
    exp: sess.exp,
    license: admLicenseSnapshot(env, S),
    settingsOverrides: Object.keys((await settingsBundle(env)).overrides || {}).length,
  })
}

/** GET /api/admin/codes 列表；POST /api/admin/codes 批量签发。 */
async function handleAdminCodes(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  if (request.method === 'GET') {
    const codes = await admIndex(kv, ADM_CODE_INDEX_KEY)
    return admJson({ ok: true, codes })
  }

  if (!admServiceOk(request, env) && !admSameOrigin(request)) return admJson({ error: '来源校验失败' }, 403)
  if (!env.CSH_LICENSE_SECRET) return admJson({ error: '未配置 CSH_LICENSE_SECRET，无法签发' }, 503)

  let body
  try {
    body = await request.json()
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }

  const want = Math.min(ADM_MAX_BATCH, Math.max(1, Math.floor(Number(body?.count) || 1)))
  const note = cleanText(body?.note, 60)

  const seqRec = await kvJson(kv, ADM_SEQ_KEY)
  const codes = await admIndex(kv, ADM_CODE_INDEX_KEY)
  let seq = Math.max(Number(seqRec && seqRec.n) || 0, 0)
  for (const c of codes) seq = Math.max(seq, Number(c && c.s) || 0)

  const created = []
  const now = Date.now()
  for (let i = 0; i < want; i++) {
    if (seq >= 0xffffff) break
    seq += 1
    const made = await licMakeCode(env, seq)
    created.push({ s: made.serial, c: made.code, at: now, note, by: (sess && sess.user) || 'service', n: 0 })
  }
  if (!created.length) return admJson({ error: '序列号已用尽，需要更换签发规则' }, 507)

  await kvSave(kv, ADM_SEQ_KEY, { n: seq })
  await admIndexSave(kv, ADM_CODE_INDEX_KEY, created.concat(codes))
console.log(`admin: ${(sess && sess.user) || 'service'} issued ${created.length} code(s) note=${note || '-'}`)
  await admAudit(env, 'code-issue', {
    count: created.length,
    note,
    serials: created.map((c) => c.s),
  })


  return admJson({
    ok: true,
    note,
    codes: created.map((c) => ({ code: c.c, serial: c.s })),
  })
}

/** POST /api/admin/code-revoke —— 吊销/恢复。只影响未激活的码。 */
async function handleAdminCodeRevoke(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)
  if (!admServiceOk(request, env) && !admSameOrigin(request)) return admJson({ error: '来源校验失败' }, 403)

  let body
  try {
    body = await request.json()
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }

  const serial = Number(body?.serial) || 0
  if (!serial) return admJson({ error: '缺少序列号' }, 400)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  const codes = await admIndex(kv, ADM_CODE_INDEX_KEY)
  const hit = codes.find((c) => c && Number(c.s) === serial)
  if (!hit) return admJson({ error: '未找到该激活码记录' }, 404)

  const revoked = body?.revoke === false ? 0 : 1
  if (revoked && hit.u) {
    return admJson({ error: '该激活码已被使用，不能吊销；要停止使用请在设备列表里封禁。' }, 409)
  }
  hit.r = revoked
  await admIndexSave(kv, ADM_CODE_INDEX_KEY, codes)
console.log(`admin: ${(sess && sess.user) || 'service'} ${revoked ? 'revoked' : 'restored'} code #${serial}`)
  await admAudit(env, revoked ? 'code-revoke' : 'code-restore', { serial })

  return admJson({ ok: true, serial, revoked: !!revoked })
}

/** GET /api/admin/devices —— 已激活设备（按最近激活排序，最多 200 台）。 */
async function handleAdminDevices(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  // 索引是后台上线后才维护的；老设备只留了 lic:d:<device> 记录，
  // 首次打开设备页时扫一遍前缀补进索引（只跑一次，之后靠激活时增量写入）。
  const backfilled = await licBackfillDevices(kv)

  const devices = await admIndex(kv, ADM_DEV_INDEX_KEY)

  // 风险分只从索引里读一次，避免每台设备一次 KV 读；分数折算到此刻再给前端。
  const now = Date.now()
  const riskByDevice = new Map()
  for (const it of await riskIndexGet(kv)) {
    if (it && it.k === 'd' && it.id) riskByDevice.set(String(it.id), it)
  }
  const rows = devices.map((d) => {
    const item = riskByDevice.get(String((d && d.d) || ''))
    if (!item) return d
    const s = riskCombinedFresh(item, now)
    return {
      ...d,
      risk: {
        s,
        level: riskLevelOf(s),
        ls: riskFreshScore(item, now),
        at: Number(item.at) || 0,
        hits: Number(item.h) || 0,
        hs: riskHistFresh(item, now),
        hat: Number(item.hat) || 0,
        reasons: riskReasonsFromCompact(item.r),
        histReasons: riskReasonsFromCompact(item.hr),
      },
    }
  })
  return admJson({ ok: true, devices: rows, backfilled, riskAt: now })
}

/** GET /api/admin/risk?kind=d|i —— 风险清单（设备 / IP），按当前折算分数排序。 */
async function handleAdminRisk(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  const kind = String(new URL(request.url).searchParams.get('kind') || '').trim()
  const now = Date.now()
  const counts = { high: 0, medium: 0, low: 0 }
  const items = []
  for (const it of await riskIndexGet(kv)) {
    if (!it || !it.id) continue
    if (kind && it.k !== kind) continue
    const hs = riskHistFresh(it, now)
    const s = riskCombinedFresh(it, now)
    const level = riskLevelOf(s)
    if (!level) continue
    counts[level]++
    items.push({
      kind: it.k,
      id: String(it.id),
      ip: String(it.ip || ''),
      s,
      level,
      ls: riskFreshScore(it, now),
      at: Number(it.at) || 0,
      hits: Number(it.h) || 0,
      hs,
      hat: Number(it.hat) || 0,
      reasons: riskReasonsFromCompact(it.r),
      histReasons: riskReasonsFromCompact(it.hr),
    })
  }
  items.sort((a, b) => b.s - a.s || b.at - a.at)
  return admJson({ ok: true, now, counts, items: items.slice(0, RISK_INDEX_CAP) })
}

/** GET /api/admin/device-events?device= —— 单设备信誉详情：事件、封禁、当日报数。 */
async function handleAdminDeviceEvents(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)

  const device = String(new URL(request.url).searchParams.get('device') || '').trim().slice(0, 64)
  if (!device) return admJson({ error: '缺少设备码' }, 400)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  const ev = (await kvJson(kv, REP_EVENT_PREFIX + device)) || null
  const ban = await licBanInfo(kv, device)
  const touch = await kvJson(kv, LIC_DEVICE_KEY + device)
  const usage = (await kvJson(kv, 'lic:rep:' + device + ':' + gateDay())) || null

  // 风险详情：设备维度 + 该设备最近来源 IP 的维度（两者独立累计，便于判断是否单机 vs 整段 IP）。
  const riskRec = await kvJson(kv, RISK_DEVICE_PREFIX + device)
  const risk = riskSummary(riskRec)
  let ipRisk = null
  const recIp = riskRec && String(riskRec.ip || '')
  if (recIp && recIp !== 'unknown') {
    ipRisk = riskSummary(await kvJson(kv, RISK_IP_PREFIX + (await sha256Hex(recIp)).slice(0, 24)))
  }

  return admJson({
    ok: true,
    device,
    ban: ban || null,
    touch: touch || null,
    usage: usage ? { day: usage.day, dayCount: usage.n, minuteCount: usage.mn } : null,
    risk,
    ipRisk,
    events: Array.isArray(ev && ev.events) ? ev.events : [],
  })
}

// ══════════════════════════════════════════════════════════════════════
// 历史回溯：风险引擎上线前没有计分，用存量记录与观测台日志补一次基线。
//
//   1. source=state  扫描 csh-api 自己的设备事件（lic:ev:）与封禁记录（lic:ban:）；
//   2. source=events 接收观测台从 Nginx 日志整理出的可疑请求（ip/ts/path/ua/status）；
//   3. 每条证据只入账一次（哈希去重），历史分由计数重算，重复执行不叠加；
//   4. 结果与实时分分开存放（hs/hat），展示时取两者较大值，避免重复计分。
// ══════════════════════════════════════════════════════════════════════

/** 历史回溯概览：已入账的历史证据与命中情况。 */
async function riskBackfillStatus(kv) {
  const marker = await kvJson(kv, RISK_BACKFILL_KEY)
  const now = Date.now()
  const items = await riskIndexGet(kv)
  let hist = 0
  let histHigh = 0
  let last = 0
  for (const it of items) {
    if (!it) continue
    const hs = riskHistFresh(it, now)
    if (hs > 0) hist++
    if (hs >= RISK_HIGH) histHigh++
    last = Math.max(last, Number(it.hat) || 0)
  }
  return { marker: marker || null, hist, histHigh, lastHistAt: last, now }
}

/** 清空历史分（保留实时分与事件记录），用于纠正一次错误导入后重跑。 */
async function riskBackfillReset(kv) {
  const now = Date.now()
  const items = await riskIndexGet(kv)
  const kept = []
  for (const it of items) {
    if (!it || !it.id) continue
    const storageKey = (it.k === 'd' ? RISK_DEVICE_PREFIX : RISK_IP_PREFIX) + it.id
    const rec = await kvJson(kv, storageKey)
    if (rec) {
      delete rec.hs
      delete rec.hat
      delete rec.hb
      delete rec.hid
      delete rec.rpt
      try { await kvSave(kv, storageKey, rec) } catch {}
    }
    if (riskFreshScore(it, now) >= RISK_LOW) {
      delete it.hs
      delete it.hat
      delete it.hr
      kept.push(it)
    }
  }
  try { await kvSave(kv, RISK_INDEX_KEY, { at: now, items: kept.slice(0, RISK_INDEX_CAP) }) } catch {}
  try { await kvSave(kv, RISK_BACKFILL_KEY, { v: 1, at: now, resetAt: now, state: {}, events: {} }) } catch {}
  return { reset: true, kept: kept.length }
}

/** 把设备事件日志翻译成一条历史证据；只保留能说明问题的类型。 */
function riskHistEventOfDeviceEvent(device, e) {
  if (!e || typeof e !== 'object') return null
  const ts = Number(e.ts) || 0
  if (!ts) return null
  const path = String(e.path || '').slice(0, 200)
  const id = `${device}:${ts}:${e.kind || ''}:${path}`
  if (e.kind === 'rate_limited') return { id, ts, path, ua: '', method: 'POST', status: 429, _signals: { rate_limited: path } }
  if (e.kind === 'banned') return { id, ts, path, ua: '', method: 'GET', status: 429, _signals: { banned_hit: path } }
  if (e.kind === 'request') {
    const sig = riskPathSignals(path, '')
    return Object.keys(sig).length ? { id, ts, path, ua: '', method: 'GET', status: 0, _signals: sig } : null
  }
  return null
}

async function riskBackfillState(kv, body, dryRun) {
  if (!kv || typeof kv.list !== 'function') return { status: 501, data: { error: '当前存储不支持前缀扫描' } }
  const marker = (await kvJson(kv, RISK_BACKFILL_KEY)) || { v: 1, state: {}, events: {} }
  const limit = Math.max(1, Math.min(300, Number(body.limit) || 80))
  const cursor = Math.max(0, Number(body.cursor) || Number(marker.state && marker.state.cursor) || 0)
  let keys = []
  let banKeys = []
  try {
    keys = (await kv.list(REP_EVENT_PREFIX)).map(String).filter((k) => k.startsWith(REP_EVENT_PREFIX))
  } catch {
    return { status: 502, data: { error: '扫描设备事件失败' } }
  }
  try { banKeys = (await kv.list(ADM_BAN_KEY)).map(String).filter((k) => k.startsWith(ADM_BAN_KEY)) } catch {}
  const all = keys.concat(banKeys)
  const end = Math.min(all.length, cursor + limit)
  const now = Date.now()
  let processed = 0
  let added = 0
  let skipped = 0

  for (const key of all.slice(cursor, end)) {
    if (key.startsWith(REP_EVENT_PREFIX)) {
      const device = key.slice(REP_EVENT_PREFIX.length)
      if (!device) continue
      const rec = await kvJson(kv, key)
      const events = Array.isArray(rec && rec.events) ? rec.events : []
      const list = events.map((e) => riskHistEventOfDeviceEvent(device, e)).filter(Boolean)
      if (!list.length) continue
      processed += list.length
      const r = await riskHistApplyMany(kv, 'd', device, device, list, { now, dryRun, ip: (rec && rec.ip) || '' })
      added += r.added
      skipped += r.skipped
    } else {
      const device = key.slice(ADM_BAN_KEY.length)
      const rec = await kvJson(kv, key)
      const ts = Number(rec && rec.at) || 0
      if (!device || !ts) continue
      const ev = {
        id: `ban:${device}:${ts}`,
        ts,
        path: '/api/admin/ban',
        ua: '',
        method: 'POST',
        status: 0,
        _signals: { banned_hit: rec.reason ? String(rec.reason).slice(0, 80) : '封禁记录' },
      }
      processed++
      const r = await riskHistApplyMany(kv, 'd', device, device, [ev], { now, dryRun })
      added += r.added
      skipped += r.skipped
    }
  }

  const done = end >= all.length
  if (!dryRun) {
    marker.v = 1
    marker.at = now
    const prev = marker.state || {}
    marker.state = {
      cursor: done ? 0 : end,
      done,
      total: all.length,
      processed: (Number(prev.processed) || 0) + processed,
      added: (Number(prev.added) || 0) + added,
      skipped: (Number(prev.skipped) || 0) + skipped,
      at: now,
    }
    try { await kvSave(kv, RISK_BACKFILL_KEY, marker) } catch {}
  }
  return {
    status: 200,
    data: {
      ok: true,
      source: 'state',
      dryRun,
      cursor,
      nextCursor: done ? 0 : end,
      total: all.length,
      processed,
      added,
      skipped,
      done,
      summary: await riskBackfillStatus(kv),
    },
  }
}

async function riskBackfillEvents(kv, body, dryRun) {
  const list = Array.isArray(body.events) ? body.events.slice(0, 3000) : []
  if (!list.length) return { status: 400, data: { error: '缺少 events' } }
  const now = Date.now()
  const byIp = new Map()
  let ignored = 0
  for (const raw of list) {
    if (!raw || typeof raw !== 'object') { ignored++; continue }
    const ip = String(raw.ip || '').trim().slice(0, 64)
    if (!ip || ip === 'unknown') { ignored++; continue }
    const ts = Number(raw.ts) || 0
    if (!ts || ts > now + 60000) { ignored++; continue }
    const ev = {
      id: String(raw.id || '').slice(0, 80),
      ts,
      ip,
      path: String(raw.path || raw.uri || '').slice(0, 500),
      query: String(raw.query || '').slice(0, 200),
      ua: String(raw.ua || '').slice(0, 300),
      method: String(raw.method || 'GET').slice(0, 8),
      status: Number(raw.status) || 0,
    }
    if (!byIp.has(ip)) byIp.set(ip, [])
    byIp.get(ip).push(ev)
  }

  let added = 0
  let skipped = 0
  let touched = 0
  let errors = 0
  for (const [ip, events] of byIp) {
    // 单个 IP 写失败不应让整批回溯失败，继续处理其它 IP。
    try {
      const key = (await sha256Hex(ip)).slice(0, 24)
      const r = await riskHistApplyMany(kv, 'i', key, ip, events, { now, dryRun, ip })
      added += r.added
      skipped += r.skipped
      if (r.added) touched++
    } catch {
      errors++
    }
  }

  if (!dryRun) {
    const marker = (await kvJson(kv, RISK_BACKFILL_KEY)) || { v: 1, state: {}, events: {} }
    marker.v = 1
    marker.at = now
    const prev = marker.events || {}
    marker.events = {
      imported: (Number(prev.imported) || 0) + added,
      skipped: (Number(prev.skipped) || 0) + skipped,
      ipsTouched: (Number(prev.ipsTouched) || 0) + touched,
      lastAt: now,
    }
    try { await kvSave(kv, RISK_BACKFILL_KEY, marker) } catch {}
  }
  return {
    status: 200,
    data: {
      ok: true,
      source: 'events',
      dryRun,
      processed: list.length,
      ignored,
      ips: byIp.size,
      added,
      skipped,
      errors,
      summary: await riskBackfillStatus(kv),
    },
  }
}

/** GET /api/admin/risk/backfill 概览；POST 执行一批（state 扫描或 events 导入）。 */
async function handleAdminRiskBackfill(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  if (request.method === 'GET') {
    return admJson({ ok: true, ...(await riskBackfillStatus(kv)) })
  }

  let body = {}
  try {
    body = (await request.json()) || {}
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }
  const dryRun = body.dryRun === true
  const reset = body.reset === true
  const source = body.source === 'events' ? 'events' : 'state'
  let out = {}
  if (reset) {
    if (dryRun) out = { reset: false }
    else {
      const cleared = await riskBackfillReset(kv)
      out = { reset: true, resetKept: cleared.kept }
    }
  }
  // 只重置、不导入时直接返回，不必再要求 events。
  if (reset && source === 'events' && !Array.isArray(body.events)) {
    return admJson({ ok: true, ...out, source, summary: await riskBackfillStatus(kv) })
  }
  const r = source === 'events' ? await riskBackfillEvents(kv, body, dryRun) : await riskBackfillState(kv, body, dryRun)
  return admJson({ ...(r.data || {}), ...out }, r.status)
}

/**
 * 存量设备回填。扫描 lic:d: 前缀（Blob 存储支持 list；KV 绑定若不支持则跳过，
 * 不影响增量路径）。已在新索引里的设备以索引为准，不覆盖。
 */
async function licBackfillDevices(kv) {
  if (!kv || typeof kv.list !== 'function') return false
  try {
    const marker = await kvJson(kv, ADM_DEV_BACKFILL_KEY)
    if (alive(marker)) return true

    const keys = await kv.list(LIC_DEVICE_KEY)
    const devices = await admIndex(kv, ADM_DEV_INDEX_KEY)
    const byDevice = new Map(devices.filter((d) => d && d.d).map((d) => [d.d, d]))

    for (const key of keys) {
      const device = String(key).slice(LIC_DEVICE_KEY.length)
      if (!device || byDevice.has(device)) continue
      const rec = await kvJson(kv, key)
      if (!alive(rec)) continue
      byDevice.set(device, {
        d: device,
        at: Number(rec.at) || 0,
        first: Number(rec.at) || 0,
        tail: String(rec.tail || '').slice(0, 8),
        s: Number(rec.serial) || 0,
        build: String(rec.build || '').slice(0, 96),
        ver: String(rec.ver || '').slice(0, 32),
      })
    }

    const merged = [...byDevice.values()].sort((a, b) => (Number(b.at) || 0) - (Number(a.at) || 0))
    await admIndexSave(kv, ADM_DEV_INDEX_KEY, merged)
    await kvSave(kv, ADM_DEV_BACKFILL_KEY, { at: Date.now(), n: merged.length })
    console.log(`admin: device index backfilled, ${merged.length} device(s)`)
    return true
  } catch (err) {
    console.warn('admin: device backfill failed:', String((err && err.message) || err).slice(0, 120))
    return false
  }
}

/** POST /api/admin/ban { device, hours, reason } —— hours=0 表示永久。 */
async function handleAdminBan(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)
  if (!admServiceOk(request, env) && !admSameOrigin(request)) return admJson({ error: '来源校验失败' }, 403)

  let body
  try {
    body = await request.json()
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }

  const device = String(body?.device || '').trim().slice(0, 64)
  if (!device) return admJson({ error: '缺少设备码' }, 400)
  if (!deviceIdOk(device)) return admJson({ error: '设备码格式不对' }, 400)

  const hours = Math.max(0, Math.min(24 * 3650, Number(body?.hours) || 0))
  const until = hours > 0 ? Date.now() + hours * 3600 * 1000 : 0
  const reason = cleanText(body?.reason, 80)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  await kvSave(kv, ADM_BAN_KEY + device, { at: Date.now(), until, reason, by: (sess && sess.user) || 'service' })

  const devices = await admIndex(kv, ADM_DEV_INDEX_KEY)
  const hit = devices.find((d) => d && d.d === device)
  if (hit) {
    hit.b = until
    await admIndexSave(kv, ADM_DEV_INDEX_KEY, devices)
  }

console.log(`admin: ${(sess && sess.user) || 'service'} banned ${device} until=${until || 'forever'} reason=${reason || '-'}`)
  await admAudit(env, 'ban', { device, hours, reason, until })

  return admJson({ ok: true, device, until })
}

/** POST /api/admin/unban { device } */
async function handleAdminUnban(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)
  if (!admServiceOk(request, env) && !admSameOrigin(request)) return admJson({ error: '来源校验失败' }, 403)

  let body
  try {
    body = await request.json()
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }

  const device = String(body?.device || '').trim().slice(0, 64)
  if (!device) return admJson({ error: '缺少设备码' }, 400)
  if (!deviceIdOk(device)) return admJson({ error: '设备码格式不对' }, 400)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  try {
    await kv.delete(ADM_BAN_KEY + device)
  } catch {}
  await admAudit(env, 'unban', { device })

  const devices = await admIndex(kv, ADM_DEV_INDEX_KEY)
  const hit = devices.find((d) => d && d.d === device)
  if (hit && 'b' in hit) {
    delete hit.b
    await admIndexSave(kv, ADM_DEV_INDEX_KEY, devices)
  }

  console.log(`admin: ${(sess && sess.user) || 'service'} unbanned ${device}`)
  return admJson({ ok: true, device })
}

/** 每来源每日配额（KV 计数，两天过期）。超限返回 false；存储不可用时放行，不因限流挂掉主流程。 */
async function ipDailyAllow(kv, scope, limit, request) {
  if (!kv) return true
  try {
    const ipHash = (await sha256Hex(reqIp(request))).slice(0, 24)
    const day = new Date().toISOString().slice(0, 10)
    const key = `quota:${scope}:${ipHash}:${day}`
    const used = Number((await kvJson(kv, key))?.n) || 0
    if (used >= limit) return false
    await kvSave(kv, key, { n: used + 1, _exp: Date.now() + 2 * 86400 * 1000 })
  } catch {}
  return true
}

/** 通用键前缀枚举：兼容本仓 Blob 适配层（收字符串）与 Cloudflare KV 绑定（收 { prefix }）。 */
async function kvListKeys(kv, prefix) {
  if (!kv || typeof kv.list !== 'function') return []
  try {
    const res = await kv.list(prefix)
    if (Array.isArray(res)) return res.map((k) => String(k))
    if (res && Array.isArray(res.keys)) return res.keys.map((k) => String((k && k.name) || ''))
  } catch {}
  try {
    const res = await kv.list({ prefix })
    if (Array.isArray(res)) return res.map((k) => String(k))
    if (res && Array.isArray(res.keys)) return res.keys.map((k) => String((k && k.name) || ''))
  } catch {}
  return []
}

/** 在线窗口：客户端轮询间隔最慢 120 秒，留一个周期余量。 */
const ADM_ONLINE_WINDOW_MS = 180 * 1000

/** 在线设备 = 教室喊话轮询（ann-poll）心跳仍在窗口内的设备，按配对码分组。 */
async function admOnlineDevices(kv) {
  const keys = await kvListKeys(kv, 'gate:ann:d:')
  const now = Date.now()
  const out = []
  for (const key of keys) {
    const pair = key.slice('gate:ann:d:'.length)
    if (!/^\d{6}$/.test(pair)) continue
    const reg = await kvJson(kv, key)
    if (!reg || typeof reg !== 'object') continue
    for (const [dev, v] of Object.entries(reg)) {
      const ts = Number(v && typeof v === 'object' ? v.t : v)
      if (!Number.isFinite(ts) || now - ts > ADM_ONLINE_WINDOW_MS) continue
      out.push({
        d: dev,
        pair,
        name: String((v && typeof v === 'object' && v.n) || '').slice(0, 32),
        ts,
      })
    }
  }
  out.sort((a, b) => b.ts - a.ts)
  return out
}

/** GET /api/admin/online —— 当前可喊话的在线设备。 */
async function handleAdminOnline(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  const online = await admOnlineDevices(kv)
  return admJson({ ok: true, online, window: Math.round(ADM_ONLINE_WINDOW_MS / 1000) })
}

/** POST /api/admin/shout { text, duration, from, targets } —— 向在线设备喊话。 */
async function handleAdminShout(request, env) {
  const sess = await admSession(request, env)
  if (!sess && !admServiceOk(request, env)) return admJson({ error: '未登录' }, 401)
  if (!admServiceOk(request, env) && !admSameOrigin(request)) return admJson({ error: '来源校验失败' }, 403)

  let body
  try {
    body = await request.json()
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }

  const text = String(body?.text || '').trim()
  if (!text) return admJson({ error: '喊话内容不能为空' }, 400)
  const shoutMax = Math.max(10, Number((await settingsOf(env)).annTextMax) || ANN_TEXT_MAX)
  if (text.length > shoutMax) return admJson({ error: `喊话内容最多 ${shoutMax} 字` }, 400)

  const duration = Math.min(
    ANN_DURATION_MAX,
    Math.max(ANN_DURATION_MIN, Number(body?.duration) || ANN_DURATION_DEFAULT)
  )
  const from = String(body?.from || '').trim().slice(0, ANN_FROM_MAX) || '管理员'

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  const online = await admOnlineDevices(kv)
  if (online.length === 0) return admJson({ error: '当前没有在线设备', online: 0 }, 409)

  const wanted = Array.isArray(body?.targets)
    ? new Set(body.targets.map((t) => String(t).trim()).filter(Boolean))
    : null
  const picked = wanted ? online.filter((d) => wanted.has(d.d)) : online
  if (picked.length === 0) return admJson({ error: '选中的设备已离线', online: online.length }, 409)

  // 同一配对码下的一条消息可带多个目标；按配对码分组合并投递
  const groups = new Map()
  for (const dev of picked) {
    if (!groups.has(dev.pair)) groups.set(dev.pair, [])
    groups.get(dev.pair).push(dev.d)
  }

  const id = `adm-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
  let delivered = 0
  const failed = []
  for (const [pair, targets] of groups) {
    const out = await announceOp(env, {
      op: 'ann-send',
      pairCode: pair,
      text,
      from,
      duration,
      id,
      targets,
      rate: false,
    })
    if (out && out.ok) delivered += Number(out.devices) || targets.length
    else failed.push({ pair, error: (out && out.error) || 'internal' })
  }

console.log(`admin: ${(sess && sess.user) || 'service'} shout ${id} delivered=${delivered} pairs=${groups.size} text=${text.slice(0, 40)}`)
  await admAudit(env, 'shout', { delivered, pairs: groups.size, text: text.slice(0, 120), duration })

  return admJson({ ok: true, id, delivered, pairs: groups.size, failed })
}

// ── 参数设置与操作日志 ──────────────────────────────────────────────

const ADM_AUDIT_KEY = 'cfg:audit'
const ADM_AUDIT_MAX = 300

/** 记一条后台操作。只保留最近 300 条，读改写一次，够回溯就行。 */
async function admAudit(env, action, detail) {
  try {
    const kv = await gateKv()
    if (!kv) return
    const list = (await kvJson(kv, ADM_AUDIT_KEY)) || []
    const entry = {
      at: Date.now(),
      by: admUser(env),
      act: String(action || '').slice(0, 40),
      detail: detail && typeof detail === 'object' ? detail : { text: String(detail || '').slice(0, 240) },
    }
    const next = [entry].concat(Array.isArray(list) ? list : []).slice(0, ADM_AUDIT_MAX)
    await kvSave(kv, ADM_AUDIT_KEY, next)
  } catch {}
}

function admSameOriginOrFail(request) {
  return admSameOrigin(request) ? null : admJson({ error: '来源校验失败' }, 403)
}

/** GET /api/admin/settings —— 分组后的参数、生效值、出厂值、是否被改过。 */
async function handleAdminSettingsGet(request, env) {
  const sess = await admSession(request, env)
  if (!sess) return admJson({ error: '未登录' }, 401)

  const bundle = await settingsBundle(env)
  const groups = SETTING_GROUPS.map((g) => ({
    id: g.id,
    title: g.title,
    hint: g.hint || '',
    fields: SETTING_FIELDS.filter((f) => f.group === g.id).map((f) => ({
      key: f.key,
      label: f.label,
      type: f.type,
      unit: f.unit || '',
      min: f.min,
      max: f.max,
      options: f.options || null,
      hint: f.hint || '',
      value: bundle.values[f.key],
      def: bundle.defaults[f.key],
      overridden: settingOverridden(bundle, f.key),
    })),
  }))

  let audit = []
  try {
    const kv = await gateKv()
    if (kv) audit = ((await kvJson(kv, ADM_AUDIT_KEY)) || []).slice(0, 60)
  } catch {}

  return admJson({
    ok: true,
    groups,
    audit,
    updatedAt: bundle.meta ? bundle.meta.at : 0,
    updatedBy: bundle.meta ? bundle.meta.by : '',
    overrides: Object.keys(bundle.overrides || {}).length,
  })
}

/** POST /api/admin/settings { patch: {key: value}, reset: [key] | true } */
async function handleAdminSettingsSave(request, env) {
  const sess = await admSession(request, env)
  if (!sess) return admJson({ error: '未登录' }, 401)
  const originFail = admSameOriginOrFail(request)
  if (originFail) return originFail

  let body
  try {
    body = await request.json()
  } catch {
    return admJson({ error: '请求格式错误' }, 400)
  }

  const kv = await gateKv()
  if (!kv) return admJson({ error: '状态存储不可用' }, 503)

  const bundle = await settingsBundle(env)
  const stored = (await kvJson(kv, SETTINGS_KEY)) || {}
  const next = Object.assign({}, stored.v && typeof stored.v === 'object' ? stored.v : {})
  const errors = {}
  const changes = []

  const patch = body && body.patch && typeof body.patch === 'object' ? body.patch : {}
  for (const key of Object.keys(patch)) {
    const field = settingField(key)
    if (!field) {
      errors[key] = '未知参数'
      continue
    }
    const out = settingCoerce(field, patch[key])
    if (!out.ok) {
      errors[key] = out.error
      continue
    }
    const before = bundle.values[key]
    if (before === out.value) continue
    changes.push({ key, label: field.label, from: before, to: out.value })
    next[key] = out.value
  }

  const reset = body && body.reset
  const resetKeys =
    reset === true ? Object.keys(next) : Array.isArray(reset) ? reset.map((k) => String(k)) : []
  for (const key of resetKeys) {
    if (!Object.prototype.hasOwnProperty.call(next, key)) continue
    const field = settingField(key)
    if (!field) continue
    const before = bundle.values[key]
    delete next[key]
    if (before !== bundle.defaults[key]) {
      changes.push({ key, label: field.label, from: before, to: bundle.defaults[key], reset: true })
    }
  }

  if (Object.keys(errors).length > 0) {
    return admJson({ error: '有参数不合法', errors }, 400)
  }
  if (changes.length === 0) {
    return admJson({ ok: true, changed: 0, message: '没有改动' })
  }

  await kvSave(kv, SETTINGS_KEY, { v: next, at: Date.now(), by: admUser(env) })
  await admAudit(env, 'settings', { changes: changes.slice(0, 24) })
  console.log(`admin: ${sess.user} settings changed=${changes.length}`)
  return admJson({ ok: true, changed: changes.length, changes })
}

/** GET /api/admin/audit —— 最近的后台操作。 */
async function handleAdminAudit(request, env) {
  const sess = await admSession(request, env)
  if (!sess) return admJson({ error: '未登录' }, 401)
  let audit = []
  try {
    const kv = await gateKv()
    if (kv) audit = ((await kvJson(kv, ADM_AUDIT_KEY)) || []).slice(0, ADM_AUDIT_MAX)
  } catch {}
  return admJson({ ok: true, audit })
}

async function workerFetch(request, env, ctx) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(request, env) })
    }

    const url = new URL(request.url)

    if (url.pathname === LIC_ACTIVATE_PATH) return handleLicenseActivate(request, env)

    const isClientApi = url.pathname.startsWith('/api/') && !url.pathname.startsWith('/api/admin/')

    // 凡带设备码的客户端请求都登记一笔（激活接口自己会记，这里跳过）；异步写，不阻塞响应
    if (isClientApi) {
      ctx.waitUntil(licTouchDevice(env, request).catch(() => {}))
    }

    // 请求特征先算一遍（纯内存）；闸门结果和响应状态也并进同一批信号，
    // 每个请求最多写一次风险存储，避免同一键并发读改写互相覆盖。
    const preRisk = isClientApi ? riskSignalsOf(request, url) : {}
    const riskInfo = {}
    const recordRisk = () => {
      if (Object.keys(preRisk).length || Object.keys(riskInfo).length) {
        ctx.waitUntil(riskObserve(request, env, preRisk, riskInfo))
      }
    }

    // 设备信誉先于许可判定：封禁/超限统一回 429（许可闸门对被封禁设备回 403）。
    const rep = await deviceGuard(request, env, riskInfo)
    if (rep) {
      recordRisk()
      return rep
    }
    const gate = await licenseGuard(request, env)
    if (gate && gate.deny) return gate.deny

    const response = await routeRequest(request, env, ctx)

    // 反复撞 4xx（猜路径/猜参数）也算一个低权重信号，必须与其它因子叠加才升级。
    if (isClientApi && response && [401, 403, 404, 405].includes(response.status)) {
      riskInfo.err4xx = response.status
    }
    recordRisk()

    if (!gate || !gate.headers) return response

    try {
      const merged = new Response(response.body, response)
      for (const [name, value] of Object.entries(gate.headers)) merged.headers.set(name, value)
      return merged
    } catch {
      return response
    }
}

async function routeRequest(request, env, ctx) {
    const url = new URL(request.url)

    // 管理后台：登录态走 Cookie，与其它接口的 CORS/许可闸门互不影响
    if (url.pathname.startsWith('/api/admin/')) {
      if (url.pathname === '/api/admin/login' && request.method === 'POST') return handleAdminLogin(request, env)
      if (url.pathname === '/api/admin/logout' && request.method === 'POST') return handleAdminLogout(request, env)
      if (url.pathname === '/api/admin/session' && request.method === 'GET') return handleAdminSession(request, env)
      if (url.pathname === '/api/admin/codes' && (request.method === 'GET' || request.method === 'POST')) {
        return handleAdminCodes(request, env)
      }
      if (url.pathname === '/api/admin/code-revoke' && request.method === 'POST') {
        return handleAdminCodeRevoke(request, env)
      }
      if (url.pathname === '/api/admin/devices' && request.method === 'GET') return handleAdminDevices(request, env)
      if (url.pathname === '/api/admin/device-events' && request.method === 'GET') {
        return handleAdminDeviceEvents(request, env)
      }
      if (url.pathname === '/api/admin/ban' && request.method === 'POST') return handleAdminBan(request, env)
      if (url.pathname === '/api/admin/unban' && request.method === 'POST') return handleAdminUnban(request, env)
      if (url.pathname === '/api/admin/online' && request.method === 'GET') return handleAdminOnline(request, env)
      if (url.pathname === '/api/admin/risk' && request.method === 'GET') return handleAdminRisk(request, env)
      if (url.pathname === '/api/admin/risk/backfill' && (request.method === 'GET' || request.method === 'POST')) {
        return handleAdminRiskBackfill(request, env)
      }
      if (url.pathname === '/api/admin/shout' && request.method === 'POST') return handleAdminShout(request, env)
      if (url.pathname === '/api/admin/settings') {
        if (request.method === 'GET') return handleAdminSettingsGet(request, env)
        if (request.method === 'POST') return handleAdminSettingsSave(request, env)
      }
      if (url.pathname === '/api/admin/audit' && request.method === 'GET') return handleAdminAudit(request, env)
      return admJson({ error: 'Not Found' }, 404)
    }

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
  const ossConfig = !!(env.OSS_ACCESS_KEY_ID && env.OSS_ACCESS_KEY_SECRET && env.OSS_BUCKET)
  const githubConfig = !!(env.GITHUB_TOKEN && env.GITHUB_OWNER && env.GITHUB_REPO)
  const gateOk = out.services.kv
  const missingOss = ossConfig ? [] : ['OSS_ACCESS_KEY_ID/SECRET']
  const missingGithub = githubConfig ? [] : ['GITHUB_TOKEN']
  out.services.ossConfig = ossConfig
  out.services.signConfig = !!env.SIGN_API_KEY
  out.services.githubConfig = githubConfig
  out.services.licenseConfig = !!(env.CSH_BUILD_SECRET && env.CSH_LICENSE_SECRET)
  out.services.adminConfig = admReady(env)
  out.admin = { user: admUser(env), ready: admReady(env) }
  const statusSettings = await settingsOf(env)
  out.license = {
    enforce: licEnforce(env, statusSettings),
    enforceAt: String(statusSettings.licEnforceAt || '') || null,
    buildSecret: !!env.CSH_BUILD_SECRET,
    licenseSecret: !!env.CSH_LICENSE_SECRET,
    legacyUntil: String(statusSettings.licLegacyUntil || '') || null,
  }
  out.features = [
    {
      key: 'announce', name: '教室喊话',
      ok: gateOk,
      need: gateOk ? [] : ['状态存储（Blob/KV）'],
    },
    {
      key: 'submit', name: '软件投稿',
      ok: ossConfig && gateOk,
      need: [].concat(missingOss, gateOk ? [] : ['状态存储']),
    },
    {
      key: 'ossSign', name: '投稿直传签名',
      ok: ossConfig,
      need: missingOss,
    },
    {
      key: 'echoCave', name: '回声洞提交',
      ok: githubConfig,
      need: missingGithub,
    },
    {
      key: 'feedback', name: '问题反馈',
      ok: githubConfig,
      need: missingGithub,
    },
    {
      key: 'dl', name: '下载闸门/加速',
      ok: ossConfig && !!env.SIGN_API_KEY && gateOk,
      need: [].concat(missingOss, env.SIGN_API_KEY ? [] : ['SIGN_API_KEY'], gateOk ? [] : ['状态存储']),
    },
  ]
  try {
    const t0 = Date.now()
    const l = await relayListDetailed(env, '')
    out.services.oss = l !== null
    out.ossProbeMs = Date.now() - t0
    out.ossObjectsProbed = l ? l.objects.length : 0
    out.ossFiles = l ? l.objects.length : null
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
  const relayStatus = await relayProbeStatus(env)
  out.dl = {
    mode: await dlModeWanted(env),
    relayConfigured: relayStatus !== null,
    relayStatus,
    backendReady: !!(env.OSS_BUCKET && env.OSS_ACCESS_KEY_ID && env.OSS_ACCESS_KEY_SECRET),
  }
  const checks = [out.services.kv, out.services.oss, out.services.githubApi]
  out.ok = checks.every(Boolean)
  out.ms = Date.now() - started
  return json(out, out.ok ? 200 : 503, request, env)
}

const ENV_DEFAULTS = {
  ALLOWED_ORIGIN: '*',
  GITHUB_OWNER: 'c1201y',
  GITHUB_REPO: 'classsoftwarehub',
  GITHUB_BRANCH: 'main',
  OSS_BUCKET: 'classsoftwarehub',
  OSS_REGION: 'cn-shanghai',
  OSS_ENDPOINT: 'oss-cn-shanghai.aliyuncs.com',
  OSS_PUBLIC_BASE: 'https://classsoftwarehub.oss-cn-shanghai.aliyuncs.com',
  OSS_PREFIX: 'upload',
  DL_MODE: 'auto',
  DL_DAILY_LIMIT: '25',
  DL_DIRECT_MONTHLY_GB: '0',
  DL_RELAY_MONTHLY_GB: '0',
  GC_ORPHAN_MINUTES: '15',
  GC_STALE_RECORD_HOURS: '24',
  SUBMIT_REQUIRE_SOURCE: 'true',
  SUBMIT_MAX_PER_DAY: '6',
  SUBMIT_MAX_PENDING: '3',
  // 正版校验：默认处于观察期（只记日志不拦），确认官方客户端都带构建签名后再改 true
  CSH_LIC_ENFORCE: 'false',
  // 定时开闸：首批带签名的桌面版发布于 2026-11-02，给 30 天缓冲，到点自动开始拦截。
  // 要提前或延后，在控制台覆盖这个变量即可；想彻底关掉就把它设成空字符串。
  CSH_LIC_ENFORCE_AT: '2026-12-02T00:00:00Z',
  CSH_LICENSE_DAYS: '365',
  CSH_OFFICIAL_TOKEN_DAYS: '30',
  CSH_LIC_LEGACY_UNTIL: '',
  CSH_LIC_BROWSER_ORIGINS: 'classsoftwarehub.cn,www.classsoftwarehub.cn',
  CSH_LIC_TRY_PER_DAY: '30',
  // 管理后台：密码必须由控制台提供，代码里不留默认值
  CSH_ADMIN_USER: 'admin',
}

export async function onRequest(context) {
  const env = Object.assign({}, ENV_DEFAULTS, context.env || {})
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
