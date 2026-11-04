// 把训练好的风险模型上传到生产 KV（lic:risk:model）。
// 用法：
//   CSH_API_BASE=https://api.classsoftwarehub.cn CSH_ADMIN_API_TOKEN=... \
//     node tools/upload-risk-model.mjs [model.json] [--dry-run]
// 令牌只从环境变量读取，绝不回显。
import fs from 'node:fs';

const args = process.argv.slice(2);
const dryOnly = args.includes('--dry-run');
const file = args.find((a) => !a.startsWith('--')) || 'tools/risk-model.json';
const base = (process.env.CSH_API_BASE || 'https://api.classsoftwarehub.cn').replace(/\/+$/, '');
const token = String(process.env.CSH_ADMIN_API_TOKEN || '').trim();

if (token.length < 16) {
  console.error('缺少 CSH_ADMIN_API_TOKEN（至少 16 字符）');
  process.exit(1);
}
let model;
try {
  model = JSON.parse(fs.readFileSync(file, 'utf8'));
} catch (e) {
  console.error(`读取模型失败: ${file} (${e.message})`);
  process.exit(1);
}

const auth = { authorization: `Bearer ${token}` };
const url = `${base}/api/admin/risk/model`;

async function call(method, body) {
  const r = await fetch(url, {
    method,
    headers: { ...auth, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, data };
}

function describe(m) {
  if (!m || !m.loaded) return '未加载';
  return `feature=${m.feature} dim=${m.dim} weights=${m.weights} threshold=${m.threshold} high=${m.high}${m.createdAt ? ` at=${m.createdAt}` : ''}`;
}

const before = await call('GET');
if (before.status !== 200) {
  console.error(`读取状态失败 HTTP ${before.status}: ${JSON.stringify(before.data)}`);
  process.exit(1);
}
console.log(`当前模型: ${describe(before.data.model)}`);

if (dryOnly) {
  const dry = await call('POST', { model, dryRun: true });
  if (dry.status !== 200) {
    console.error(`试运行失败 HTTP ${dry.status}: ${JSON.stringify(dry.data)}`);
    process.exit(1);
  }
  console.log(`试运行通过: ${describe(dry.data.model)}`);
} else {
  const dry = await call('POST', { model, dryRun: true });
  if (dry.status !== 200) {
    console.error(`试运行失败 HTTP ${dry.status}: ${JSON.stringify(dry.data)}`);
    process.exit(1);
  }
  console.log(`试运行通过: dim=${dry.data.model?.dim} weights=${dry.data.model?.weights}`);

  const saved = await call('POST', { model });
  if (saved.status !== 200 || !saved.data?.ok) {
    console.error(`上传失败 HTTP ${saved.status}: ${JSON.stringify(saved.data)}`);
    process.exit(1);
  }
  const after = await call('GET');
  if (after.status !== 200 || !after.data?.model?.loaded) {
    console.error(`上传后状态异常 HTTP ${after.status}: ${JSON.stringify(after.data)}`);
    process.exit(1);
  }
  if (after.data.model.dim !== model.dim || after.data.model.threshold !== model.threshold) {
    console.error(`上传后参数不一致: ${describe(after.data.model)}`);
    process.exit(1);
  }
  console.log(`已上线: ${describe(after.data.model)}`);
}
