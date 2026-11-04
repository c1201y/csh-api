// 风险模型训练 worker：持有整份稀疏数据集，按主进程下发的配置做逻辑回归 SGD。
// 只负责计算，不读写 KV / 网络；结果通过 postMessage 返回。
import fs from 'node:fs';
import { parentPort, workerData } from 'node:worker_threads';
import { sigmoid, averagePrecision, auc, bestThreshold, metricsAt } from './risk-metrics.mjs';

const HEADER = 56;

function loadDataset(file) {
  const raw = fs.readFileSync(file);
  if (raw.length < HEADER) throw new Error('数据集过短');
  // 复制到独立 ArrayBuffer，保证 byteOffset=0 且 4 字节对齐，worker 内可安全建视图。
  const buf = Buffer.from(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength));
  if (buf.toString('latin1', 0, 8) !== 'RMDATA02') throw new Error('数据集头不匹配');
  const dim = buf.readUInt32LE(8);
  const n = buf.readUInt32LE(12);
  const nnz = buf.readUInt32LE(16);
  const at = (i) => buf.readUInt32LE(20 + i * 4);
  const view = (Ctor, off, len) => new Ctor(buf.buffer, buf.byteOffset + off, len);
  return {
    dim, n, nnz,
    idx: view(Uint32Array, at(0), nnz),
    val: view(Float32Array, at(1), nnz),
    off: view(Uint32Array, at(2), n + 1),
    weight: view(Float32Array, at(3), n),
    label: view(Uint8Array, at(4), n),
    split: view(Uint8Array, at(5), n),
    svc: view(Uint8Array, at(6), n),
    origin: view(Uint8Array, at(7), n),
  };
}

let data;
try {
  data = loadDataset(workerData.file);
} catch (e) {
  parentPort.postMessage({ type: 'fatal', error: e.message });
  throw e;
}
parentPort.postMessage({ type: 'ready', n: data.n, nnz: data.nnz, dim: data.dim });

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function rowsFor(splits, rng, subsample) {
  const rows = [];
  for (let i = 0; i < data.n; i++) if (splits.includes(data.split[i])) rows.push(i);
  if (subsample < 1 && rows.length) {
    for (let i = rows.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [rows[i], rows[j]] = [rows[j], rows[i]];
    }
    return rows.slice(0, Math.max(1, Math.floor(rows.length * subsample)));
  }
  return rows;
}

function scoreRow(w, bias, row) {
  let z = bias;
  for (let p = data.off[row]; p < data.off[row + 1]; p++) z += w[data.idx[p]] * data.val[p];
  return sigmoid(z);
}

function trainOnce(cfg) {
  const rng = mulberry32(cfg.seed);
  const rows = rowsFor(cfg.splits, rng, cfg.subsample ?? 1);
  if (!rows.length) throw new Error('训练集为空');
  const w = new Float32Array(data.dim);
  let bias = 0;
  const order = rows.slice();
  const steps = cfg.epochs * order.length;
  let done = 0;
  for (let epoch = 0; epoch < cfg.epochs; epoch++) {
    for (let i = order.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [order[i], order[j]] = [order[j], order[i]];
    }
    const step = cfg.lr / (1 + 0.08 * epoch);
    for (const row of order) {
      let z = bias;
      for (let p = data.off[row]; p < data.off[row + 1]; p++) z += w[data.idx[p]] * data.val[p];
      const y = data.label[row];
      const sw = data.weight[row] * (y ? cfg.posBoost || 1 : 1);
      const g = (sigmoid(z) - y) * sw;
      bias -= step * g;
      for (let p = data.off[row]; p < data.off[row + 1]; p++) {
        const k = data.idx[p];
        w[k] -= step * (g * data.val[p] + cfg.l2 * w[k]);
      }
      done++;
      if (cfg.onProgress && done % 200000 === 0) cfg.onProgress(done / steps);
    }
  }

  const valRows = [];
  for (let i = 0; i < data.n; i++) if (cfg.evalSplit != null && data.split[i] === cfg.evalSplit) valRows.push(i);
  const scores = valRows.map((r) => scoreRow(w, bias, r));
  const labels = valRows.map((r) => data.label[r]);
  const best = valRows.length ? bestThreshold(scores, labels, cfg.minPrecision ?? 0.9) : null;
  const idx = [];
  const vals = [];
  for (let i = 0; i < w.length; i++) {
    if (Math.abs(w[i]) >= 1e-4) { idx.push(i); vals.push(w[i]); }
  }
  return {
    bias,
    indices: Uint32Array.from(idx),
    values: Float32Array.from(vals),
    eval: valRows.length ? {
      n: valRows.length,
      pos: labels.reduce((a, y) => a + y, 0),
      ap: averagePrecision(scores, labels),
      auc: auc(scores, labels),
      ...metricsAt(scores, labels, best ? best.threshold : 0.5),
      bestThreshold: best ? best.threshold : 0.5,
    } : null,
  };
}

parentPort.on('message', (msg) => {
  if (!msg || msg.type !== 'run') return;
  try {
    const out = trainOnce(msg.config);
    parentPort.postMessage({ type: 'result', jobId: msg.jobId, ...out }, [out.indices.buffer, out.values.buffer]);
  } catch (e) {
    parentPort.postMessage({ type: 'error', jobId: msg.jobId, error: e.message });
  }
});
