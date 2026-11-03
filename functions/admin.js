// ClassSoftwareHub 管理后台（/admin）
//
// 页面本身是静态 HTML，只负责渲染；登录态、签发、封禁全部在 /api/admin/*。
// 会话 Cookie 由服务端下发（HttpOnly + Secure + SameSite=Strict），前端不接触令牌。
const ADMIN_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta name="robots" content="noindex,nofollow"/>
<title>ClassSoftwareHub · 控制台</title>
<style>
:root{
  color-scheme:light dark;
  --bg:#f5f6f8; --card:#fff; --fg:#1a1c1f; --muted:#767c85; --line:#e7e9ec;
  --brand:#2f6fed; --brand-soft:#eaf1fe; --ok:#167a2c; --ok-bg:#e6f7e9;
  --warn:#8a5d00; --warn-bg:#fff4dd; --bad:#b3261e; --bad-bg:#fdeaea;
  --mono:"Cascadia Mono",Consolas,"SF Mono",Menlo,monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#14161a; --card:#1e2126; --fg:#e7e9ec; --muted:#959ba4; --line:#2b2f36;
    --brand:#6b9bff; --brand-soft:#1d2a42; --ok:#6ee787; --ok-bg:#12351a;
    --warn:#ffc53d; --warn-bg:#3a2f12; --bad:#ff9b93; --bad-bg:#43201d;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,"Microsoft YaHei",sans-serif}
a{color:var(--brand)}
h1,h2,h3{margin:0;font-weight:600}
h1{font-size:20px}
h2{font-size:15px}
.mono{font-family:var(--mono)}
.muted{color:var(--muted)}
.hidden{display:none !important}

/* 登录 */
.login{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.login-card{width:100%;max-width:380px;background:var(--card);border-radius:16px;padding:28px 26px 24px;box-shadow:0 8px 28px rgba(0,0,0,.08)}
.brand{display:flex;align-items:center;gap:8px;font-weight:600;letter-spacing:.01em}
.dot{width:10px;height:10px;border-radius:3px;background:linear-gradient(135deg,#2f6fed,#7aa7ff)}
.login-card .brand{font-size:13px;color:var(--muted);margin-bottom:18px}
.login-card h1{margin-bottom:6px}
.login-card .sub{color:var(--muted);font-size:13px;margin:0 0 20px}
label.field{display:flex;flex-direction:column;gap:6px;font-size:12px;color:var(--muted);margin-bottom:14px}
input,select{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:9px 11px;width:100%;outline:none}
input:focus,select:focus{border-color:var(--brand);box-shadow:0 0 0 3px var(--brand-soft)}
button{font:inherit;cursor:pointer;border:1px solid transparent;border-radius:9px;padding:9px 14px;background:transparent;color:var(--fg)}
button:disabled{opacity:.45;cursor:not-allowed}
.primary{background:var(--brand);color:#fff;font-weight:600}
.primary:hover:not(:disabled){filter:brightness(1.06)}
.ghost{border-color:var(--line);background:var(--card)}
.ghost:hover:not(:disabled){border-color:var(--muted)}
.danger{background:var(--bad);color:#fff;font-weight:600}
.sm{padding:5px 10px;font-size:12px;border-radius:7px}
.err{color:var(--bad);font-size:12px;margin:12px 0 0;min-height:16px}

/* 控制台 */
.topbar{position:sticky;top:0;z-index:5;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line)}
.topbar .right{display:flex;align-items:center;gap:12px;font-size:12px}
.tag{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:1px 8px;margin-left:2px}
main{max-width:1040px;margin:0 auto;padding:20px 16px 48px}
.strip{font-size:12.5px;color:var(--muted);background:var(--card);border:1px solid var(--line);border-radius:12px;padding:10px 14px;margin-bottom:14px;display:flex;flex-wrap:wrap;gap:6px 16px}
.strip b{color:var(--fg);font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:14px}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.hint{color:var(--muted);font-size:12.5px;margin:6px 0 14px}
.form{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form .field{margin:0;width:110px}
.form .grow{flex:1;min-width:180px}
.issued{margin-top:14px;border:1px dashed var(--brand);border-radius:11px;padding:12px;background:var(--brand-soft)}
.issued-head{display:flex;align-items:center;justify-content:space-between;font-size:12.5px;font-weight:600;margin-bottom:8px}
.codes{display:flex;flex-wrap:wrap;gap:8px}
.codes button{font-family:var(--mono);font-size:13px;background:var(--card);border:1px solid var(--line);padding:6px 10px;border-radius:8px}
.tools{display:flex;gap:8px;align-items:center}
.search{width:220px;padding:6px 10px;font-size:12.5px;border-radius:8px}
.table-wrap{overflow-x:auto;margin:0 -4px}
table{width:100%;border-collapse:collapse;font-size:13px;min-width:560px}
th{text-align:left;font-size:11.5px;font-weight:600;color:var(--muted);letter-spacing:.03em;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:none}
.code-cell{font-family:var(--mono);font-size:12.5px;background:none;border:none;padding:0;color:var(--brand);cursor:pointer;letter-spacing:.02em}
.dev-cell{font-family:var(--mono);font-size:12px;cursor:pointer;color:var(--fg)}
.badge{display:inline-block;font-size:11.5px;font-weight:600;border-radius:999px;padding:2px 9px;white-space:nowrap}
.b-ok{background:var(--ok-bg);color:var(--ok)}
.b-warn{background:var(--warn-bg);color:var(--warn)}
.b-bad{background:var(--bad-bg);color:var(--bad)}
.b-idle{background:var(--bg);color:var(--muted)}
.empty{color:var(--muted);font-size:12.5px;text-align:center;padding:16px 0 6px;margin:0}
.foot{color:var(--muted);font-size:12px;text-align:center;margin:20px 0 0}
.nowrap{white-space:nowrap}
.dim{color:var(--muted);font-size:11.5px}

/* 弹窗 */
.modal{position:fixed;inset:0;background:rgba(0,0,0,.42);display:flex;align-items:center;justify-content:center;padding:20px;z-index:20}
.modal-card{width:100%;max-width:360px;background:var(--card);border-radius:14px;padding:20px}
.modal-card h3{margin-bottom:10px}
.modal-card .mono{font-size:12px;color:var(--muted);margin:0 0 14px;word-break:break-all}
.modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:6px}

.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%);background:#1f2329;color:#fff;font-size:13px;padding:9px 16px;border-radius:999px;box-shadow:0 6px 20px rgba(0,0,0,.25);z-index:30}
@media (max-width:600px){
  .topbar{padding:10px 14px}
  main{padding:14px 10px 40px}
  .form .field{width:100%}
  .search{width:140px}
}
</style>
</head>
<body>

<section id="login" class="login hidden">
  <div class="login-card">
    <div class="brand"><span class="dot"></span> ClassSoftwareHub</div>
    <h1>管理后台</h1>
    <p class="sub">维护者专用。登录后可签发激活码、查看已激活设备、封禁设备。</p>
    <label class="field">账号<input id="user" autocomplete="username" autocapitalize="off" spellcheck="false" value="admin"></label>
    <label class="field">密码<input id="pass" type="password" autocomplete="current-password"></label>
    <button id="loginBtn" class="primary" style="width:100%;margin-top:4px">登录</button>
    <p id="loginErr" class="err"></p>
  </div>
</section>

<div id="app" class="hidden">
  <header class="topbar">
    <div class="brand"><span class="dot"></span> ClassSoftwareHub<span class="tag">控制台</span></div>
    <div class="right"><span id="who" class="muted"></span><button id="logoutBtn" class="ghost sm">退出</button></div>
  </header>
  <main>
    <div id="strip" class="strip"></div>

    <section class="card">
      <h2>签发激活码</h2>
      <p class="hint">非官方构建首次联网时会被要求激活。把生成的码发给对方，客户端输入后即可正常使用（一台设备一个码，换机重装需重新签发）。</p>
      <div class="form">
        <label class="field">数量<input id="count" type="number" min="1" max="50" value="1"></label>
        <label class="field grow">备注<input id="note" maxlength="60" placeholder="给谁用 / 用途，方便以后对账"/></label>
        <button id="issueBtn" class="primary">生成</button>
      </div>
      <div id="issued" class="issued hidden">
        <div class="issued-head"><span id="issuedTitle">已生成</span><button id="copyAll" class="ghost sm">复制全部</button></div>
        <div id="issuedList" class="codes"></div>
      </div>
    </section>

    <section class="card">
      <div class="card-head">
        <h2>签发记录</h2>
        <div class="tools">
          <input id="codeFilter" class="search" placeholder="搜激活码 / 备注 / 设备"/>
          <button id="reloadCodes" class="ghost sm">刷新</button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>激活码</th><th>备注</th><th>签发时间</th><th>状态</th><th></th></tr></thead>
          <tbody id="codeBody"></tbody>
        </table>
      </div>
      <p id="codeEmpty" class="empty hidden">还没有签发记录。</p>
    </section>

    <section class="card">
      <div class="card-head">
        <h2>已激活设备</h2>
        <div class="tools">
          <input id="devFilter" class="search" placeholder="搜设备码"/>
          <button id="reloadDevices" class="ghost sm">刷新</button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>设备码</th><th>最近激活</th><th>码尾号</th><th>构建</th><th>状态</th><th></th></tr></thead>
          <tbody id="devBody"></tbody>
        </table>
      </div>
      <p id="devEmpty" class="empty hidden">还没有设备激活。</p>
    </section>

    <p class="foot">激活码是离线签名凭证：吊销只对未激活的码生效；已激活的设备要失效，需要在这里封禁。</p>
  </main>
</div>

<div id="banModal" class="modal hidden">
  <div class="modal-card">
    <h3>封禁设备</h3>
    <p id="banDevice" class="mono"></p>
    <label class="field">时长
      <select id="banHours">
        <option value="24">1 天</option>
        <option value="72" selected>3 天</option>
        <option value="168">7 天</option>
        <option value="720">30 天</option>
        <option value="0">永久</option>
      </select>
    </label>
    <label class="field">原因<input id="banReason" maxlength="80" placeholder="可选，会显示在客户端提示里"/></label>
    <div class="modal-actions">
      <button id="banCancel" class="ghost">取消</button>
      <button id="banOk" class="danger">确认封禁</button>
    </div>
  </div>
</div>

<div id="toast" class="toast hidden"></div>

<script>
var state = { codes: [], devices: [], pendingBan: '', license: null };

function $(id) { return document.getElementById(id); }
function el(tag, cls, text) {
  var n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}
function show(node, on) { node.classList.toggle('hidden', !on); }
function fmtTime(ms) {
  if (!ms) return '—';
  var d = new Date(Number(ms));
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString('zh-CN', { hour12: false });
}
function shortDate(ms) {
  if (!ms) return '—';
  var d = new Date(Number(ms));
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleDateString('zh-CN');
}
var toastTimer = 0;
function toast(msg) {
  var t = $('toast');
  t.textContent = msg;
  show(t, true);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { show(t, false); }, 1800);
}
function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  return new Promise(function (resolve, reject) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); resolve(); } catch (e) { reject(e); }
    document.body.removeChild(ta);
  });
}
function copyInto(text, label) {
  copyText(text).then(function () { toast((label || '已复制') + '：' + text); },
    function () { toast('复制失败，请手动选中'); });
}

async function api(path, opts) {
  opts = opts || {};
  var init = { method: opts.method || 'GET', credentials: 'same-origin', headers: {} };
  if (opts.body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(opts.body);
  }
  var res = await fetch('/api/admin' + path, init);
  var data = {};
  try { data = await res.json(); } catch (e) {}
  data.status = res.status;
  return data;
}

function enterLogin(info) {
  show($('app'), false);
  show($('login'), true);
  var err = $('loginErr');
  err.textContent = '';
  if (info && info.ready === false) {
    err.textContent = '后台未配置：请先在环境变量里设置 CSH_ADMIN_PASS 与 CSH_LICENSE_SECRET。';
  } else if (info && info.error) {
    err.textContent = info.error;
  }
  setTimeout(function () { $('pass').focus(); }, 30);
}

function enterApp(info) {
  state.license = info.license || null;
  $('who').textContent = info.user || '';
  show($('login'), false);
  show($('app'), true);
  renderStrip();
  loadCodes();
  loadDevices();
}

function renderStrip() {
  var lic = state.license || {};
  var parts = [];
  var mode = lic.enforce ? '拦截已开启' : '观察期（只记日志）';
  if (!lic.enforce && lic.enforceAt) mode += '，' + shortDate(Date.parse(lic.enforceAt)) + ' 起自动开闸';
  parts.push('授权闸门：<b>' + mode + '</b>');
  parts.push('激活有效期：<b>' + (lic.days || 365) + ' 天</b>');
  parts.push('官方构建令牌：<b>' + (lic.officialDays || 30) + ' 天</b>');
  if (lic.legacyUntil) parts.push('旧客户端豁免至：<b>' + shortDate(Date.parse(lic.legacyUntil)) + '</b>');
  if (!lic.licenseSecret) parts.push('<b style="color:var(--bad)">未配置 CSH_LICENSE_SECRET，无法签发</b>');
  $('strip').innerHTML = parts.join('<span class="dim">·</span>');
}

async function login() {
  var btn = $('loginBtn');
  var err = $('loginErr');
  err.textContent = '';
  btn.disabled = true;
  btn.textContent = '登录中…';
  try {
    var r = await api('/login', { method: 'POST', body: { user: $('user').value.trim(), pass: $('pass').value } });
    if (!r.ok) {
      err.textContent = r.error || '登录失败';
      if (r.detail) err.textContent += ' ' + r.detail;
      $('pass').value = '';
      return;
    }
    var me = await api('/session');
    enterApp(me.ok ? me : { user: r.user, license: null });
  } catch (e) {
    err.textContent = '网络异常：' + e;
  } finally {
    btn.disabled = false;
    btn.textContent = '登录';
  }
}

async function logout() {
  try { await api('/logout', { method: 'POST' }); } catch (e) {}
  enterLogin({});
}

async function issue() {
  var btn = $('issueBtn');
  var count = Math.max(1, Math.min(50, Math.floor(Number($('count').value) || 1)));
  btn.disabled = true;
  btn.textContent = '生成中…';
  try {
    var r = await api('/codes', { method: 'POST', body: { count: count, note: $('note').value.trim() } });
    if (!r.ok) { toast(r.error || '生成失败'); return; }
    var list = $('issuedList');
    list.innerHTML = '';
    var lines = [];
    r.codes.forEach(function (item) {
      var b = el('button', '', item.code);
      b.title = '点击复制';
      b.addEventListener('click', function () { copyInto(item.code); });
      list.appendChild(b);
      lines.push(item.code);
    });
    $('issuedTitle').textContent = '已生成 ' + r.codes.length + ' 个' + (r.note ? '（' + r.note + '）' : '');
    $('copyAll').onclick = function () { copyInto(lines.join('\\n'), '已复制全部 ' + lines.length + ' 个'); };
    show($('issued'), true);
    $('note').value = '';
    loadCodes();
  } catch (e) {
    toast('网络异常：' + e);
  } finally {
    btn.disabled = false;
    btn.textContent = '生成';
  }
}

async function loadCodes() {
  var r = await api('/codes');
  if (r.status === 401) return enterLogin({});
  if (!r.ok) return toast(r.error || '读取签发记录失败');
  state.codes = r.codes || [];
  renderCodes();
}

async function loadDevices() {
  var r = await api('/devices');
  if (r.status === 401) return enterLogin({});
  if (!r.ok) return toast(r.error || '读取设备列表失败');
  state.devices = r.devices || [];
  renderDevices();
}

function codeStatus(rec) {
  if (rec.r) return { cls: 'b-bad', text: '已吊销' };
  if (rec.u) return { cls: 'b-ok', text: '已激活' };
  if (rec.ext) return { cls: 'b-warn', text: '外部签发' };
  return { cls: 'b-idle', text: '未使用' };
}

function renderCodes() {
  var q = $('codeFilter').value.trim().toLowerCase();
  var body = $('codeBody');
  body.innerHTML = '';
  var rows = state.codes.filter(function (c) {
    if (!q) return true;
    return String(c.c || '').toLowerCase().indexOf(q) >= 0 ||
      String(c.note || '').toLowerCase().indexOf(q) >= 0 ||
      String(c.u || '').toLowerCase().indexOf(q) >= 0 ||
      String(c.s || '').indexOf(q) >= 0;
  });
  rows.forEach(function (c) {
    var tr = el('tr');

    var tdCode = el('td');
    if (c.c) {
      var btn = el('button', 'code-cell', c.c);
      btn.title = '点击复制';
      btn.addEventListener('click', function () { copyInto(c.c); });
      tdCode.appendChild(btn);
    } else {
      tdCode.appendChild(el('span', 'dim mono', '#' + c.s));
    }
    tr.appendChild(tdCode);

    var tdNote = el('td');
    if (c.note) tdNote.textContent = c.note;
    else tdNote.appendChild(el('span', 'dim', '—'));
    if (c.u) {
      var sub = el('div', 'dim');
      sub.textContent = '设备 ' + String(c.u).slice(0, 8) + '… · ' + fmtTime(c.ua);
      tdNote.appendChild(sub);
    }
    tr.appendChild(tdNote);

    tr.appendChild(el('td', 'nowrap', c.at ? fmtTime(c.at) : '—'));

    var st = codeStatus(c);
    var tdSt = el('td');
    tdSt.appendChild(el('span', 'badge ' + st.cls, st.text));
    tr.appendChild(tdSt);

    var tdOp = el('td', 'nowrap');
    if (c.c) {
      var op = el('button', 'ghost sm', c.r ? '恢复' : '吊销');
      op.disabled = !!c.u;
      if (c.u) op.title = '已激活的码不能吊销，需要封禁设备';
      op.addEventListener('click', async function () {
        op.disabled = true;
        var res = await api('/code-revoke', { method: 'POST', body: { serial: c.s, revoke: !c.r } });
        if (!res.ok) { toast(res.error || '操作失败'); op.disabled = false; return; }
        toast(c.r ? '已恢复' : '已吊销');
        loadCodes();
      });
      tdOp.appendChild(op);
    }
    tr.appendChild(tdOp);
    body.appendChild(tr);
  });
  show($('codeEmpty'), rows.length === 0);
}

function banState(rec) {
  var b = rec.b;
  if (b === undefined || b === null) return null;
  if (b === 0) return { forever: true, until: 0 };
  if (Number(b) > Date.now()) return { forever: false, until: Number(b) };
  return null;
}

function renderDevices() {
  var q = $('devFilter').value.trim().toLowerCase();
  var body = $('devBody');
  body.innerHTML = '';
  var rows = state.devices.filter(function (d) {
    if (!q) return true;
    return String(d.d || '').toLowerCase().indexOf(q) >= 0;
  });
  rows.forEach(function (d) {
    var tr = el('tr');

    var tdDev = el('td');
    var devBtn = el('button', 'dev-cell', d.d || '');
    devBtn.title = '点击复制';
    devBtn.addEventListener('click', function () { copyInto(d.d, '已复制设备码'); });
    tdDev.appendChild(devBtn);
    tr.appendChild(tdDev);

    var tdTime = el('td');
    tdTime.appendChild(el('div', 'nowrap', fmtTime(d.at)));
    if (d.first && d.first !== d.at) {
      var f = el('div', 'dim');
      f.textContent = '首次 ' + fmtTime(d.first);
      tdTime.appendChild(f);
    }
    tr.appendChild(tdTime);

    tr.appendChild(el('td', 'mono', d.tail || '—'));
    tr.appendChild(el('td', 'dim nowrap', d.build || '—'));

    var ban = banState(d);
    var tdSt = el('td');
    if (ban) {
      tdSt.appendChild(el('span', 'badge b-bad', ban.forever ? '永久封禁' : '封禁至 ' + shortDate(ban.until)));
    } else {
      tdSt.appendChild(el('span', 'badge b-ok', '正常'));
    }
    tr.appendChild(tdSt);

    var tdOp = el('td', 'nowrap');
    if (ban) {
      var un = el('button', 'ghost sm', '解封');
      un.addEventListener('click', async function () {
        un.disabled = true;
        var res = await api('/unban', { method: 'POST', body: { device: d.d } });
        if (!res.ok) { toast(res.error || '操作失败'); un.disabled = false; return; }
        toast('已解封');
        loadDevices();
      });
      tdOp.appendChild(un);
    } else {
      var banBtn = el('button', 'ghost sm', '封禁');
      banBtn.addEventListener('click', function () { openBan(d.d); });
      tdOp.appendChild(banBtn);
    }
    tr.appendChild(tdOp);
    body.appendChild(tr);
  });
  show($('devEmpty'), rows.length === 0);
}

function openBan(device) {
  state.pendingBan = device;
  $('banDevice').textContent = device;
  $('banReason').value = '';
  show($('banModal'), true);
}

async function confirmBan() {
  var device = state.pendingBan;
  if (!device) return;
  var hours = Number($('banHours').value) || 0;
  var r = await api('/ban', { method: 'POST', body: { device: device, hours: hours, reason: $('banReason').value.trim() } });
  if (!r.ok) return toast(r.error || '封禁失败');
  show($('banModal'), false);
  toast(hours ? '已封禁 ' + hours + ' 小时' : '已永久封禁');
  loadDevices();
}

$('loginBtn').addEventListener('click', login);
$('pass').addEventListener('keydown', function (e) { if (e.key === 'Enter') login(); });
$('logoutBtn').addEventListener('click', logout);
$('issueBtn').addEventListener('click', issue);
$('reloadCodes').addEventListener('click', loadCodes);
$('reloadDevices').addEventListener('click', loadDevices);
$('codeFilter').addEventListener('input', renderCodes);
$('devFilter').addEventListener('input', renderDevices);
$('banCancel').addEventListener('click', function () { show($('banModal'), false); });
$('banOk').addEventListener('click', confirmBan);
$('banModal').addEventListener('click', function (e) { if (e.target === $('banModal')) show($('banModal'), false); });

(async function boot() {
  try {
    var r = await api('/session');
    if (r.ok) enterApp(r);
    else enterLogin(r);
  } catch (e) {
    enterLogin({ error: '无法连接后端：' + e });
  }
})();
</script>
</body>
</html>
`

export function onRequest() {
  return new Response(ADMIN_HTML, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'referrer-policy': 'no-referrer',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'x-robots-tag': 'noindex, nofollow',
    },
  })
}
