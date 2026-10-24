const STATUS_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>班级小屋 · 后端状态</title>
<style>
:root { color-scheme: light dark; }
body { font-family: system-ui, "Microsoft YaHei", sans-serif; margin: 0; background: #f6f7f9; color: #1c1e21; }
main { max-width: 720px; margin: 0 auto; padding: 32px 16px; }
h1 { font-size: 20px; margin: 0 0 4px; }
h2 { font-size: 13px; color: #888; margin: 0 0 10px; font-weight: 600; letter-spacing: .05em; }
.sub { color: #888; font-size: 13px; margin-bottom: 20px; }
.card { background: #fff; border-radius: 12px; padding: 16px 18px; box-shadow: 0 1px 4px rgba(0,0,0,.06); margin-bottom: 14px; }
.row { display: flex; justify-content: space-between; align-items: center; padding: 7px 0; font-size: 14px; gap: 10px; }
.row + .row { border-top: 1px solid #f0f0f0; }
.row .name { flex-shrink: 0; }
.row .mid { flex: 1; color: #999; font-size: 12px; text-align: right; }
.badge { padding: 2px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; flex-shrink: 0; }
.ok { background: #e6f7e9; color: #167a2c; }
.bad { background: #fdeaea; color: #b3261e; }
.kv { color: #666; font-size: 12px; }
@media (prefers-color-scheme: dark) {
  body { background: #16181c; color: #e8eaed; }
  .card { background: #1f2226; box-shadow: none; }
  .row + .row { border-top: 1px solid #2a2d33; }
  .sub, .kv, h2 { color: #9aa0a6; }
  .row .mid { color: #7a8087; }
  .ok { background: #12351a; color: #6ee787; }
  .bad { background: #43201d; color: #ff9b93; }
}
</style>
</head>
<body>
<main>
  <h1>班级小屋 · 后端状态</h1>
  <div class="sub" id="meta">加载中…</div>
  <div id="banner" class="card">…</div>
  <div class="card">
    <h2>基础服务</h2>
    <div id="svc"></div>
  </div>
  <div class="card">
    <h2>用户服务可用性</h2>
    <div id="feat"></div>
  </div>
  <div class="card">
    <h2>运行数据</h2>
    <div id="extra"></div>
  </div>
</main>
<script>
function badge(v, t, f) {
  var s = document.createElement('span')
  s.className = 'badge ' + (v ? 'ok' : 'bad')
  s.textContent = v ? (t || '可用') : (f || '不可用')
  return s
}
function row(label, el, note, mid) {
  var d = document.createElement('div')
  d.className = 'row'
  var l = document.createElement('span')
  l.className = 'name'
  l.textContent = label
  d.appendChild(l)
  if (mid) {
    var m = document.createElement('span')
    m.className = 'mid'
    m.textContent = mid
    d.appendChild(m)
  }
  var r = document.createElement('span')
  r.style.display = 'flex'
  r.style.alignItems = 'center'
  r.style.gap = '8px'
  if (note) {
    var n = document.createElement('span')
    n.className = 'kv'
    n.textContent = note
    r.appendChild(n)
  }
  r.appendChild(el)
  d.appendChild(r)
  return d
}
function fmtBytes(n) {
  if (!n && n !== 0) return '-'
  var u = ['B', 'KB', 'MB', 'GB', 'TB']
  var i = 0
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++ }
  return n.toFixed(n >= 100 || i === 0 ? 0 : 1) + ' ' + u[i]
}
function renderFeatures(list) {
  var el = document.getElementById('feat')
  el.innerHTML = ''
  if (!list || !list.length) {
    el.appendChild(row('服务清单', badge(false, '无数据')))
    return
  }
  for (var i = 0; i < list.length; i++) {
    var f = list[i]
    var mid = f.ok ? '' : ('缺：' + f.need.join('、'))
    el.appendChild(row(f.name, badge(f.ok), '', mid))
  }
}
async function refresh() {
  try {
    var r = await fetch('/api/status', { cache: 'no-store' })
    var d = await r.json()
    document.getElementById('meta').textContent = '运行环境 ' + (d.runtime || '-') + ' · 检查耗时 ' + (d.ms || '-') + ' ms · ' + d.time
    var banner = document.getElementById('banner')
    var feat = d.features || []
    var featOk = feat.length && feat.every(function (f) { return f.ok })
    var degraded = feat.length && !featOk && d.services.kv
    banner.className = 'card'
    if (d.ok && featOk) {
      banner.style.color = '#167a2c'; banner.style.background = '#e6f7e9'
      banner.textContent = '✅ 全部服务运行正常'
    } else if (degraded) {
      banner.style.color = '#9a6b00'; banner.style.background = '#fff5e0'
      var miss = feat.filter(function (f) { return !f.ok }).map(function (f) { return f.name }).join('、')
      banner.textContent = '⚠️ 核心链路正常，以下功能待补密钥：' + miss
    } else {
      banner.style.color = '#b3261e'; banner.style.background = '#fdeaea'
      banner.textContent = '❌ 核心服务异常'
    }
    var svc = document.getElementById('svc')
    svc.innerHTML = ''
    svc.appendChild(row('状态存储（Blob/KV）', badge(d.services.kv), d.kvError ? String(d.kvError).slice(0, 40) : ''))
    svc.appendChild(row('OSS 对象存储', badge(d.services.oss), d.services.ossConfig ? (d.ossProbeMs ? d.ossProbeMs + 'ms · ' + (d.ossObjectsProbed || 0) + ' 个对象' : '') : '未配置密钥'))
    svc.appendChild(row('GitHub API', badge(d.services.githubApi), d.services.githubConfig ? '' : '未配置 Token（匿名探测）'))
    svc.appendChild(row('加速签名配置', badge(d.services.signConfig), d.services.signConfig ? '' : '未配置'))
    renderFeatures(feat)
    var extra = document.getElementById('extra')
    extra.innerHTML = ''
    if (d.stats) {
      extra.appendChild(row('已登记文件', badge(true, String(d.stats.files)), '图标 ' + (d.stats.icons || 0)))
      extra.appendChild(row('OSS 文件总数', badge(true, String(d.ossFiles != null ? d.ossFiles : (d.ossObjectsProbed || 0))), '桶内全部对象'))
      extra.appendChild(row('待认领对象', badge((d.stats.pending || 0) === 0, String(d.stats.pending || 0)), '0 = 无孤儿'))
      extra.appendChild(row('本月中继用量', badge(true, fmtBytes(d.stats.relay))))
      extra.appendChild(row('本月直连用量', badge(true, fmtBytes(d.stats.direct))))
    } else {
      extra.appendChild(row('统计信息', badge(false, '不可用'), '状态存储未就绪'))
    }
    if (d.lastGc && d.lastGc.at) {
      extra.appendChild(row('最近回收任务', badge(!!d.lastGc.ok || !!d.lastGc.lazy, d.lastGc.ok ? '成功' : (d.lastGc.lazy ? '已排队' : '失败'), d.lastGc.lazy ? '已排队' : ''), new Date(d.lastGc.at).toLocaleString('zh-CN')))
    }
  } catch (e) {
    document.getElementById('banner').textContent = '状态接口不可达：' + e
  }
}
refresh()
setInterval(refresh, 30000)
</script>
</body>
</html>
`

export function onRequest() {
  return new Response(STATUS_HTML, { headers: { 'content-type': 'text/html; charset=utf-8' } })
}
