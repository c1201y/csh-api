// 搜索引擎蜘蛛识别：UA 只用来判断“声称是谁”，IP 段/DNS 才决定“是否真的是它”。
// 数据由 tools/fetch-crawler-ranges.mjs 从 Google/Bing/Apple 官方源生成。
import { CRAWLER_RANGES, CRAWLER_UA_PATTERNS, CRAWLER_DNS_SUFFIXES } from './crawler-ranges.js'

const UA_RULES = CRAWLER_UA_PATTERNS.map((x) => ({ engine: x.engine, re: new RegExp(x.pattern, 'i') }))
export const CRAWLER_ENGINE_NAMES = UA_RULES.map((x) => x.engine)

// 官方 IP 段会变，但没有必要时时刻刻改代码重发布：运行时可从 KV 覆盖，
// 内置 crawler-ranges.js 只作兜底。覆盖值只在引擎名已存在时生效，避免被写入任意键。
let LIVE_RANGES = CRAWLER_RANGES
const CIDR_RE = /^[0-9a-fA-F:.]{2,64}\/\d{1,3}$/
const CRAWLER_RANGE_MAX = 8000

function sanitizeRanges(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null
  const known = new Set(CRAWLER_ENGINE_NAMES)
  const out = {}
  let total = 0
  for (const [engine, value] of Object.entries(input)) {
    if (!known.has(engine) || !value || typeof value !== 'object') continue
    const v4 = []
    const v6 = []
    for (const [bucket, list] of [['v4', value.v4], ['v6', value.v6]]) {
      if (!Array.isArray(list)) continue
      for (const raw of list) {
        if (total >= CRAWLER_RANGE_MAX) break
        const cidr = String(raw == null ? '' : raw).trim()
        if (!CIDR_RE.test(cidr)) continue
        if (bucket === 'v4' ? !cidr.includes('.') : !cidr.includes(':')) continue
        const target = bucket === 'v4' ? v4 : v6
        if (target.includes(cidr)) continue
        target.push(cidr)
        total += 1
      }
    }
    if (v4.length || v6.length) out[engine] = { v4, v6 }
  }
  return Object.keys(out).length ? out : null
}

/** 校验并返回可落库的 IP 段；空/非法返回 null。 */
export function crawlerSanitizeRanges(input) {
  return sanitizeRanges(input)
}

/** 用 KV 里的文档覆盖运行时 IP 段；返回是否生效。 */
export function crawlerApplyRanges(doc) {
  const ranges = sanitizeRanges(doc && doc.ranges)
  if (!ranges) return false
  // 按引擎合并：某个官方源拉取失败时继续沿用上一版，不会把该引擎整个丢掉。
  LIVE_RANGES = { ...LIVE_RANGES, ...ranges }
  return true
}

/** 当前生效的 IP 段（用于后台查看/导出）。 */
export function crawlerRangesDoc() {
  return LIVE_RANGES
}

/** 按 UA 判断声称的搜索引擎；未知返回空字符串。 */
export function crawlerEngineOfUa(ua) {
  const text = String(ua || '')
  if (!text) return ''
  for (const rule of UA_RULES) if (rule.re.test(text)) return rule.engine
  return ''
}

export function crawlerDnsSuffixes(engine) {
  return Array.isArray(CRAWLER_DNS_SUFFIXES[engine]) ? CRAWLER_DNS_SUFFIXES[engine] : []
}

function ipv4ToInt(ip) {
  const parts = String(ip).split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const part of parts) {
    const n = Number(part)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = ((out << 8) | n) >>> 0
  }
  return out
}

function ipv6ToBigInt(ip) {
  const text = String(ip).trim().toLowerCase()
  if (!text.includes(':')) return null
  const halves = text.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0
  if (fill < 0) return null
  const groups = [...head, ...new Array(fill).fill('0'), ...tail]
  if (groups.length !== 8) return null
  let out = 0n
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null
    out = (out << 16n) | BigInt(parseInt(group, 16))
  }
  return out
}

function cidrMatch(ip, cidr) {
  const text = String(cidr || '')
  const slash = text.lastIndexOf('/')
  if (slash <= 0) return false
  const base = text.slice(0, slash)
  const bits = Number(text.slice(slash + 1))
  if (ip.includes(':')) {
    if (!base.includes(':') || !Number.isInteger(bits) || bits < 0 || bits > 128) return false
    const a = ipv6ToBigInt(ip)
    const b = ipv6ToBigInt(base)
    if (a == null || b == null) return false
    if (bits === 0) return true
    const shift = 128n - BigInt(bits)
    return (a >> shift) === (b >> shift)
  }
  if (!base.includes('.') || !Number.isInteger(bits) || bits < 0 || bits > 32) return false
  const a = ipv4ToInt(ip)
  const b = ipv4ToInt(base)
  if (a == null || b == null) return false
  if (bits === 0) return true
  const mask = bits === 32 ? 0xffffffff : (~((1 << (32 - bits)) - 1)) >>> 0
  return (a & mask) === (b & mask)
}

/** 静态官方 IP 段命中则返回引擎名。 */
export function crawlerStaticEngine(ip, ua) {
  const engine = crawlerEngineOfUa(ua)
  if (!engine) return ''
  const ranges = LIVE_RANGES[engine]
  if (!ranges) return ''
  const list = [...(ranges.v4 || []), ...(ranges.v6 || [])]
  for (const cidr of list) if (cidrMatch(ip, cidr)) return engine
  return ''
}

export function crawlerIsStatic(ip, ua) {
  return !!crawlerStaticEngine(ip, ua)
}

export function crawlerRangeCount() {
  return Object.values(LIVE_RANGES).reduce((n, x) => n + (x.v4 || []).length + (x.v6 || []).length, 0)
}
