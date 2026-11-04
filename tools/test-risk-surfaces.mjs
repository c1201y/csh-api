// 验证分面统一处置：下载 / OSS / 镜像 / 全站代理都走同一条动作线，
// 正常高频（多线程分段下载）永不封禁，明确的攻击证据才动作，并联动设备码。
// 只使用内存 KV，不接触生产。
import { createHash } from 'node:crypto'
import { onRequest } from '../functions/api/%5B%5Bdefault%5D%5D.js'

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
  CSH_ADMIN_API_TOKEN: 'svc-token-1234567890abcdef',
  PURGE_TOKEN: 'purge-test',
}

let failed = 0
const pending = []
function log(name, ok, extra) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  ' + extra : ''}`)
  if (!ok) failed++
}
async function flush() { await Promise.allSettled(pending.splice(0)) }

function admin(path, { method = 'GET', body } = {}) {
  const init = { method, headers: { authorization: 'Bearer ' + env.CSH_ADMIN_API_TOKEN } }
  if (body !== undefined) init.body = JSON.stringify(body)
  return onRequest({ request: new Request('https://api.test' + path, init), env, waitUntil(p) { pending.push(p) } })
}
async function jsonOf(res) {
  const text = await res.text()
  try { return { status: res.status, data: JSON.parse(text) } } catch { return { status: res.status, data: text } }
}
const ipKey = (ip) => 'lic:banip:' + createHash('sha256').update(ip).digest('hex').slice(0, 24)

function evs(ip, n, extra = {}) {
  const now = Date.now()
  return Array.from({ length: n }, (_, i) => ({
    id: `${ip}-${extra.tag || 'e'}-${i}`,
    ts: now - i * 500,
    ip,
    method: extra.method || 'GET',
    status: extra.status || 200,
    path: extra.path || '/',
    ua: extra.ua || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0',
    op: extra.op || '',
    result: extra.result || '',
    device: extra.device || '',
  }))
}

async function report(source, events) {
  const r = await jsonOf(await admin('/api/admin/risk/report', { method: 'POST', body: { source, events } }))
  await flush()
  return r
}

// ── 1. 未知来源拒绝 ─────────────────────────────────────────────────
const bad = await report('nope', evs('198.18.1.1', 1))
log('未知来源被拒绝', bad.status === 400)

// ── 2. 多线程分段下载：量大但无攻击证据，绝不封禁 ────────────────────
const dlClean = Array.from({ length: 200 }, (_, i) => ({
  id: `dl-clean-${i}`,
  ts: Date.now() - i * 30,
  ip: '198.18.1.2',
  method: 'GET',
  status: 206,
  path: '/owner/repo/releases/download/v1.0/app.exe',
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0',
  op: 'signed',
}))
const clean = await report('download', dlClean)
log('多线程分段下载不被封禁', clean.status === 200 && clean.data.actions.length === 0 && !store.has(ipKey('198.18.1.2')),
  `actions=${JSON.stringify(clean.data.actions)} tiers=${(clean.data.tiers || []).length}`)

// ── 3. 下载签名失败达到阈值才封禁 ───────────────────────────────────
const dlFail = await report('download', evs('198.18.1.3', 8, { status: 403, path: '/owner/repo/releases/download/v1.0/app.exe', ua: '' }))
const dlRec = store.has(ipKey('198.18.1.3')) ? JSON.parse(store.get(ipKey('198.18.1.3'))) : null
log('下载签名失败触发封禁', dlFail.status === 200 && dlFail.data.actions.length === 1 && !!dlRec && dlRec.src === 'download',
  `actions=${JSON.stringify(dlFail.data.actions)}`)

// ── 4. 镜像仓库探测封禁 ────────────────────────────────────────────
const mirror = await report('mirror', evs('198.18.1.4', 6, { status: 404, path: '/owner/repo/.git/config', ua: 'curl/8.4.0' }))
log('镜像仓库探测触发封禁', mirror.status === 200 && mirror.data.actions.length === 1,
  `actions=${JSON.stringify(mirror.data.actions)}`)

// ── 5. OSS 鉴权失败封禁 ────────────────────────────────────────────
const oss = await report('oss', evs('198.18.1.5', 12, { status: 401, path: '/icon/a.webp', ua: '' }))
log('OSS 鉴权失败触发封禁', oss.status === 200 && oss.data.actions.length === 1,
  `actions=${JSON.stringify(oss.data.actions)}`)

// ── 6. 全站代理扫描 + 设备码联动 ───────────────────────────────────
const device = 'a1b2c3d4e5f60718'
store.set('lic:d:' + device, JSON.stringify({ at: Date.now(), first: Date.now() }))
const siteEv = evs('198.18.1.6', 10, {
  status: 444,
  path: '/.env',
  ua: 'sqlmap/1.7.2#stable (https://sqlmap.org)',
  device,
})
const site = await report('site', siteEv)
const devBan = store.has('lic:ban:' + device) ? JSON.parse(store.get('lic:ban:' + device)) : null
const siteRec = store.has(ipKey('198.18.1.6')) ? JSON.parse(store.get(ipKey('198.18.1.6'))) : null
log('全站代理扫描触发封禁', site.status === 200 && site.data.actions.length === 1 && !!siteRec && siteRec.src === 'site',
  `actions=${JSON.stringify(site.data.actions)}`)
log('封禁联动已登记设备码', !!devBan && !!siteRec && devBan.until === siteRec.until,
  devBan && `until=${devBan.until} reason=${devBan.reason}`)

const bans = await jsonOf(await admin('/api/admin/ip-bans'))
const siteRow = (bans.data.rows || []).find((r) => r.ip === '198.18.1.6')
const surfaceCfg = bans.data.cfg || {}
log('封禁清单暴露动作线与设备码', bans.status === 200 &&
  surfaceCfg.actionLine === 70 && surfaceCfg.minEvidence === 2 &&
  !!(surfaceCfg.surfaces && surfaceCfg.surfaces.site && surfaceCfg.surfaces.site.on) &&
  !!siteRow && Array.isArray(siteRow.devices) && siteRow.devices[0] === 'e5f60718',
  `actionLine=${surfaceCfg.actionLine} dev=${siteRow && JSON.stringify(siteRow.devices)}`)

// ── 7. 低置信只有标记，不动作 ──────────────────────────────────────
const weak = await report('site', evs('198.18.1.7', 5, { status: 404, path: '/random-page' }))
log('低置信仅标记不封禁', weak.status === 200 && weak.data.actions.length === 0 && !store.has(ipKey('198.18.1.7')),
  `tiers=${JSON.stringify(weak.data.tiers)}`)

// ── 8. 关闭分面开关后只记录 ────────────────────────────────────────
await admin('/api/admin/settings', { method: 'POST', body: { patch: { riskDlBan: false } } })
const offDl = await report('download', evs('198.18.1.8', 8, { status: 403, path: '/owner/repo/releases/download/v1.0/app.exe', ua: '' }))
log('关闭下载面封禁后不动作', offDl.status === 200 && offDl.data.actions.length === 0 && !store.has(ipKey('198.18.1.8')),
  `actions=${JSON.stringify(offDl.data.actions)} tiers=${(offDl.data.tiers || []).length}`)
const bansOff = await jsonOf(await admin('/api/admin/ip-bans'))
log('分面开关反映到策略快照', bansOff.status === 200 && !!(bansOff.data.cfg.surfaces) && bansOff.data.cfg.surfaces.download.on === false)

// ── 9. 无 UA / 单一弱信号不能把设备堆成高风险 ─────────────────────
const cliDev = 'c11a2b3c4d5e6f70'
store.set('lic:d:' + cliDev, JSON.stringify({ at: Date.now(), first: Date.now() }))
await onRequest({
  request: new Request('https://api.test/api/status', {
    headers: { 'x-csh-did': cliDev, 'cf-connecting-ip': '198.18.9.9' },
  }),
  env,
  waitUntil(p) { pending.push(p) },
})
await flush()
const cliRecRaw = store.get('lic:risk:d:' + cliDev)
const cliRec = cliRecRaw ? JSON.parse(cliRecRaw) : null
log('无 UA 的命令行请求不产生风险信号', !cliRec || !cliRec.r || !cliRec.r.empty_ua,
  cliRec ? `reasons=${JSON.stringify(cliRec.r)}` : '未写入风险记录')

const now = Date.now()
const legacy = '5cc4d1a3ab98db19'
const scriptOnly = 'f00dbabe12345678'
store.set('lic:risk:d:' + legacy, JSON.stringify({
  s: 99, at: now, r: { empty_ua: { n: 88 }, err4xx: { n: 1 } }, hits: 88, ip: 'unknown', _exp: now + 86400000,
}))
store.set('lic:risk:d:' + scriptOnly, JSON.stringify({
  s: 100, at: now, r: { script_ua: { n: 90 } }, hits: 90, ip: 'unknown', _exp: now + 86400000,
}))
store.set('lic:risk:index', JSON.stringify({
  at: now,
  items: [
    { k: 'd', id: legacy, ip: 'unknown', s: 99, at: now, h: 88, r: { empty_ua: 88, err4xx: 1 }, hs: 0, hat: 0, hr: {} },
    { k: 'd', id: scriptOnly, ip: 'unknown', s: 100, at: now, h: 90, r: { script_ua: 90 }, hs: 0, hat: 0, hr: {} },
  ],
}))
const legacyList = await jsonOf(await admin('/api/admin/risk?kind=d'))
const legacyRow = (legacyList.data.items || []).find((x) => x.id === legacy)
const scriptRow = (legacyList.data.items || []).find((x) => x.id === scriptOnly)
log('旧的无 UA 记录被压回低风险且不再展示该原因', !!legacyRow && legacyRow.s <= 20 && legacyRow.level === 'low' &&
  !(legacyRow.reasons || []).some((r) => r.key === 'empty_ua'),
  legacyRow && `s=${legacyRow.s} level=${legacyRow.level} reasons=${JSON.stringify(legacyRow.reasons.map((r) => r.key))}`)
log('单一弱信号重复 90 次也达不到高风险', !!scriptRow && scriptRow.s <= 20 && scriptRow.level !== 'high',
  scriptRow && `s=${scriptRow.s} level=${scriptRow.level}`)
const legacyDetail = await jsonOf(await admin('/api/admin/device-events?device=' + legacy))
log('设备详情不再把无 UA 当风险原因', legacyDetail.status === 200 &&
  Number(legacyDetail.data.risk && legacyDetail.data.risk.s) <= 20 &&
  !((legacyDetail.data.risk && legacyDetail.data.risk.reasons) || []).some((r) => r.key === 'empty_ua'),
  `s=${legacyDetail.data.risk && legacyDetail.data.risk.s} level=${legacyDetail.data.risk && legacyDetail.data.risk.level}`)
log('设备详情不再展示 unknown 来源 IP', legacyDetail.status === 200 &&
  String(legacyDetail.data.risk && legacyDetail.data.risk.ip) === '' && !legacyDetail.data.ipRisk,
  `ip=${JSON.stringify(legacyDetail.data.risk && legacyDetail.data.risk.ip)}`)

// ── 10. 单一 4xx / 多范围请求都不能单独触发封禁 ─────────────────────
const site4xx = await report('site', evs('198.18.1.10', 20, { status: 403, path: '/assets/app.js', tag: 's4' }))
log('全站代理连续 403 不封禁', site4xx.status === 200 && site4xx.data.actions.length === 0 && !store.has(ipKey('198.18.1.10')),
  `actions=${JSON.stringify(site4xx.data.actions)} tiers=${(site4xx.data.tiers || []).length}`)

const rangeMany = Array.from({ length: 20 }, (_, i) => ({
  id: `range-many-${i}`,
  ts: Date.now() - i * 400,
  ip: '198.18.1.11',
  method: 'GET',
  status: 206,
  path: '/owner/repo/releases/download/v1.0/app.exe',
  ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0',
  op: 'range-many',
}))
const rm = await report('download', rangeMany)
log('多范围下载请求不封禁', rm.status === 200 && rm.data.actions.length === 0 && !store.has(ipKey('198.18.1.11')),
  `actions=${JSON.stringify(rm.data.actions)} tiers=${(rm.data.tiers || []).length}`)


await flush()
console.log(failed ? `\n${failed} 项失败` : '\n全部通过')
process.exitCode = failed ? 1 : 0
