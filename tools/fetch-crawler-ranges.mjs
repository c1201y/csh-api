// 拉取并生成搜索引擎官方 IP 段。
//
// 用法：
//   node tools/fetch-crawler-ranges.mjs                     # 从官方 URL 拉取并生成兜底文件
//   node tools/fetch-crawler-ranges.mjs --feeds-dir X       # 用本地已下载的 feed 生成
//   node tools/fetch-crawler-ranges.mjs --out Y
//   node tools/fetch-crawler-ranges.mjs --upload --no-file  # 只写运行时 KV，不产生代码提交
//
// 默认生成 functions/api/crawler-ranges.js 作兜底；--upload 会把同一份数据 POST 到
// csh-api 的 /api/admin/crawler/ranges，运行时热生效，避免每次更新都触发 EdgeOne 重建。
// 环境变量：CSH_API_URL（默认 https://api.classsoftwarehub.cn）、CSH_ADMIN_API_TOKEN。
// 百度/搜狗/360/字节/DuckDuckGo 没有稳定的官方 JSON，运行期交给 gh-dash 做 DNS 正反查。
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const OUT = path.join(ROOT, 'functions/api/crawler-ranges.js')

const FEEDS = {
  googlebot: 'https://developers.google.com/static/search/apis/ipranges/googlebot.json',
  bingbot: 'https://www.bing.com/toolbox/bingbot.json',
  applebot: 'https://search.developer.apple.com/applebot.json',
}

const UA_PATTERNS = [
  ['googlebot', 'Googlebot|Google-InspectionTool|Storebot-Google|GoogleOther'],
  ['bingbot', 'bingbot|BingPreview|adidxbot'],
  ['applebot', 'Applebot'],
  ['baiduspider', 'Baiduspider'],
  ['yandexbot', 'YandexBot|YandexImages|YandexVideo|YandexAccessibilityBot'],
  ['sogou', 'Sogou (web|inst|news) spider|SogouSpider'],
  ['360spider', '360Spider|HaosouSpider'],
  ['bytespider', 'Bytespider'],
  ['duckduckbot', 'DuckDuckBot'],
]

const DNS_SUFFIXES = {
  googlebot: ['.googlebot.com', '.google.com'],
  bingbot: ['.search.msn.com', '.bing.com'],
  applebot: ['.applebot.apple.com', '.apple.com'],
  baiduspider: ['.baidu.com', '.baidu.jp'],
  yandexbot: ['.yandex.com', '.yandex.ru', '.yandex.net'],
  sogou: ['.sogou.com'],
  '360spider': ['.360.cn', '.so.com'],
  bytespider: ['.bytedance.com', '.byteimg.com'],
  duckduckbot: ['.duckduckgo.com'],
}

function args() {
  const out = { feedsDir: '', out: OUT, upload: false, noFile: false }
  const list = process.argv.slice(2)
  for (let i = 0; i < list.length; i++) {
    if (list[i] === '--feeds-dir') out.feedsDir = list[++i]
    else if (list[i] === '--out') out.out = path.resolve(list[++i])
    else if (list[i] === '--upload') out.upload = true
    else if (list[i] === '--no-file') out.noFile = true
  }
  return out
}

async function readFeed(name, url, feedsDir) {
  if (feedsDir) {
    const p = path.join(feedsDir, `${name}.json`)
    try { return JSON.parse(fs.readFileSync(p, 'utf8')) } catch {}
  }
  const res = await fetch(url, { signal: AbortSignal.timeout(30000) })
  if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`)
  return res.json()
}

function prefixesOf(feed) {
  const v4 = []
  const v6 = []
  for (const item of Array.isArray(feed && feed.prefixes) ? feed.prefixes : []) {
    if (item && item.ipv4Prefix) v4.push(String(item.ipv4Prefix))
    else if (item && item.ipv6Prefix) v6.push(String(item.ipv6Prefix))
  }
  return { v4: [...new Set(v4)].sort(), v6: [...new Set(v6)].sort() }
}

const opt = args()
const ranges = {}
const meta = {}
async function oldRanges(name) {
  try {
    const mod = await import(`${pathToFileURL(opt.out).href}?t=${Date.now()}`)
    const prev = mod.CRAWLER_RANGES && mod.CRAWLER_RANGES[name]
    if (!prev) return null
    return {
      v4: Array.isArray(prev.v4) ? prev.v4.map(String) : [],
      v6: Array.isArray(prev.v6) ? prev.v6.map(String) : [],
    }
  } catch {
    return null
  }
}

for (const [name, url] of Object.entries(FEEDS)) {
  try {
    const feed = await readFeed(name, url, opt.feedsDir)
    ranges[name] = prefixesOf(feed)
    meta[name] = { source: url, creationTime: feed.creationTime || '' }
  } catch (err) {
    console.error(`[warn] ${name}: ${err.message}（保留旧数据）`)
    const prev = await oldRanges(name)
    if (prev) ranges[name] = prev
  }
}

const lines = []
lines.push('// 由 tools/fetch-crawler-ranges.mjs 生成，请勿手改。')
lines.push(`// generatedAt: ${new Date().toISOString()}`)
lines.push('export const CRAWLER_RANGES = {')
for (const [name, value] of Object.entries(ranges)) {
  lines.push(`  ${name}: {`)
  lines.push(`    v4: [${value.v4.map((x) => `'${x}'`).join(', ')}],`)
  lines.push(`    v6: [${value.v6.map((x) => `'${x}'`).join(', ')}],`)
  lines.push('  },')
}
lines.push('};')
lines.push('')
lines.push('export const CRAWLER_UA_PATTERNS = [')
for (const [engine, pattern] of UA_PATTERNS) lines.push(`  { engine: '${engine}', pattern: '${pattern.replace(/'/g, "\\'")}' },`)
lines.push('];')
lines.push('')
lines.push('export const CRAWLER_DNS_SUFFIXES = {')
for (const [engine, suffixes] of Object.entries(DNS_SUFFIXES)) lines.push(`  '${engine}': [${suffixes.map((s) => `'${s}'`).join(', ')}],`)
lines.push('};')
lines.push('')
lines.push('export const CRAWLER_META = ' + JSON.stringify(meta) + ';')
lines.push('')

if (opt.upload) {
  const api = String(process.env.CSH_API_URL || 'https://api.classsoftwarehub.cn').replace(/\/+$/, '')
  const token = String(process.env.CSH_ADMIN_API_TOKEN || '').trim()
  if (!token) {
    console.error('CSH_ADMIN_API_TOKEN 未配置，无法写入运行时 KV')
    process.exitCode = 1
  } else {
    const res = await fetch(`${api}/api/admin/crawler/ranges`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ at: Date.now(), ranges }),
      signal: AbortSignal.timeout(20000),
    })
    const text = await res.text()
    if (!res.ok) {
      console.error(`写入运行时 KV 失败: HTTP ${res.status} ${text.slice(0, 200)}`)
      process.exitCode = 1
    } else {
      console.log(JSON.stringify({ ok: true, uploaded: true, api, engines: Object.keys(ranges).length }))
    }
  }
}

if (!opt.noFile) {
  fs.writeFileSync(opt.out, lines.join('\n'))
  console.log(`已写入 ${opt.out}`)
}
for (const [name, value] of Object.entries(ranges)) console.log(`  ${name}: IPv4 ${value.v4.length} / IPv6 ${value.v6.length}`)
