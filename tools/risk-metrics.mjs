// 风险模型评估工具：AUC / 平均精度(AP) / Brier / 阈值扫描。
// 训练器主进程与 worker 共用，保证搜索与最终评估口径一致。

export function sigmoid(z) {
  if (z >= 0) { const e = Math.exp(-z); return 1 / (1 + e); }
  const e = Math.exp(z); return e / (1 + e);
}

/** 按分数升序排列后的平均精度（AP），比 AUC 更敏感于正类排序质量。 */
export function averagePrecision(scores, labels) {
  const pairs = scores.map((s, i) => [s, labels[i]]).sort((a, b) => b[0] - a[0]);
  let tp = 0, fp = 0, sum = 0, pos = 0;
  for (const [, y] of pairs) if (y === 1) pos++;
  if (!pos) return 0;
  for (let i = 0; i < pairs.length; i++) {
    if (pairs[i][1] === 1) {
      tp++;
      sum += tp / (tp + fp + 1);
    } else fp++;
  }
  return sum / pos;
}

export function auc(scores, labels) {
  const pairs = scores.map((s, i) => [s, labels[i]]).sort((a, b) => a[0] - b[0]);
  let pos = 0, neg = 0, rankSum = 0;
  for (let i = 0; i < pairs.length; i++) {
    if (pairs[i][1] === 1) { pos++; rankSum += i + 1; } else neg++;
  }
  if (!pos || !neg) return 0;
  return (rankSum - (pos * (pos + 1)) / 2) / (pos * neg);
}

export function brier(scores, labels) {
  if (!scores.length) return 0;
  let s = 0;
  for (let i = 0; i < scores.length; i++) {
    const d = scores[i] - labels[i];
    s += d * d;
  }
  return s / scores.length;
}

export function metricsAt(scores, labels, threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (let i = 0; i < scores.length; i++) {
    const hit = scores[i] >= threshold;
    if (labels[i] === 1) hit ? tp++ : fn++;
    else hit ? fp++ : tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  return { threshold, tp, fp, tn, fn, precision, recall, f1 };
}

/** F1 最优阈值；可选最低精确率约束，避免为召回牺牲误报。 */
export function bestThreshold(scores, labels, minPrecision = 0.9) {
  let best = null;
  let fallback = null;
  for (let i = 50; i <= 990; i += 5) {
    const t = i / 1000;
    const m = metricsAt(scores, labels, t);
    if (!fallback || m.f1 > fallback.f1) fallback = m;
    if (m.precision < minPrecision) continue;
    if (!best || m.f1 > best.f1 || (m.f1 === best.f1 && m.precision > best.precision)) best = m;
  }
  return best || fallback || metricsAt(scores, labels, 0.5);
}

/** 高置信阈值：优先 precision>=0.995 且至少 tp>=20，其次 0.99。 */
export function highThreshold(scores, labels, base, minTp = 20) {
  const floor = Math.max(base, 0.7);
  for (const target of [0.995, 0.99]) {
    for (let i = Math.ceil(floor * 1000); i <= 990; i += 5) {
      const m = metricsAt(scores, labels, i / 1000);
      if (m.precision >= target && m.tp >= minTp) return m;
    }
  }
  for (let i = Math.ceil(floor * 1000); i <= 990; i += 5) {
    const m = metricsAt(scores, labels, i / 1000);
    if (m.precision >= 0.95 && m.tp >= Math.max(5, Math.floor(minTp / 4))) return m;
  }
  return metricsAt(scores, labels, Math.min(0.99, floor + 0.1));
}

export function summarize(scores, labels, threshold) {
  const m = metricsAt(scores, labels, threshold);
  return {
    n: labels.length,
    pos: labels.reduce((a, y) => a + y, 0),
    ...m,
    auc: auc(scores, labels),
    ap: averagePrecision(scores, labels),
    brier: brier(scores, labels),
  };
}
