/** l2-regularised logistic regression, full-batch gradient descent, and the paper's metrics. */

export interface TrainOpts {
  epochs: number;
  lr: number;
  l2: number;
}

export const sigmoid = (z: number) => (z >= 0 ? 1 / (1 + Math.exp(-z)) : Math.exp(z) / (1 + Math.exp(z)));

export function predictProba(w: number[], X: number[][]): number[] {
  return X.map((x) => {
    let z = 0;
    for (let j = 0; j < w.length; j++) z += w[j] * x[j];
    return sigmoid(z);
  });
}

export function localTrain(w0: number[], X: number[][], y: number[], o: TrainOpts): number[] {
  const w = w0.slice();
  const d = w.length;
  const n = X.length;
  for (let e = 0; e < o.epochs; e++) {
    const g = new Array(d).fill(0);
    for (let i = 0; i < n; i++) {
      let z = 0;
      for (let j = 0; j < d; j++) z += w[j] * X[i][j];
      const err = sigmoid(z) - y[i];
      for (let j = 0; j < d; j++) g[j] += err * X[i][j];
    }
    for (let j = 0; j < d; j++) {
      const reg = j === d - 1 ? 0 : o.l2 * w[j]; // the bias term is not regularised
      w[j] -= o.lr * (g[j] / n + reg);
    }
  }
  return w;
}

export function logLoss(w: number[], X: number[][], y: number[]): number {
  const p = predictProba(w, X);
  const eps = 1e-12;
  let s = 0;
  for (let i = 0; i < y.length; i++) s -= y[i] * Math.log(Math.max(p[i], eps)) + (1 - y[i]) * Math.log(Math.max(1 - p[i], eps));
  return s / y.length;
}

export function accuracy(w: number[], X: number[][], y: number[]): number {
  const p = predictProba(w, X);
  let ok = 0;
  for (let i = 0; i < y.length; i++) if ((p[i] >= 0.5 ? 1 : 0) === y[i]) ok++;
  return ok / y.length;
}

/** AUC via the Wilcoxon-Mann-Whitney statistic with mid-ranks for ties. */
export function auc(w: number[], X: number[][], y: number[]): number {
  const p = predictProba(w, X);
  const idx = p.map((_, i) => i).sort((a, b) => p[a] - p[b]);
  const ranks = new Array(p.length).fill(0);
  for (let i = 0; i < idx.length; ) {
    let j = i;
    while (j + 1 < idx.length && p[idx[j + 1]] === p[idx[i]]) j++;
    const r = (i + j) / 2 + 1;
    for (let k = i; k <= j; k++) ranks[idx[k]] = r;
    i = j + 1;
  }
  let nPos = 0, sumPos = 0;
  for (let i = 0; i < y.length; i++) if (y[i] === 1) { nPos++; sumPos += ranks[i]; }
  const nNeg = y.length - nPos;
  if (nPos === 0 || nNeg === 0) return NaN;
  return (sumPos - (nPos * (nPos + 1)) / 2) / (nPos * nNeg);
}

export interface Metrics {
  accuracy: number;
  logLoss: number;
  auc: number;
}

export function evaluate(w: number[], X: number[][], y: number[]): Metrics {
  return { accuracy: accuracy(w, X, y), logLoss: logLoss(w, X, y), auc: auc(w, X, y) };
}

export const l2norm = (v: number[]) => Math.sqrt(v.reduce((a, b) => a + b * b, 0));

export function clipToNorm(v: number[], B: number): number[] {
  const n = l2norm(v);
  return n <= B ? v.slice() : v.map((x) => (x * B) / n);
}

/** Plaintext FedAvg weighted by sample counts: the non-private baseline. */
export function fedAvgRound(w: number[], shards: { X: number[][]; y: number[] }[], o: TrainOpts, clipB?: number): number[] {
  const nS = shards.reduce((a, s) => a + s.y.length, 0);
  const agg = new Array(w.length).fill(0);
  for (const s of shards) {
    let delta = localTrain(w, s.X, s.y, o).map((x, j) => x - w[j]);
    if (clipB !== undefined) delta = clipToNorm(delta, clipB);
    for (let j = 0; j < w.length; j++) agg[j] += (s.y.length / nS) * delta[j];
  }
  return w.map((x, j) => x + agg[j]);
}

export function centralized(train: { X: number[][]; y: number[] }, w0: number[], o: TrainOpts): number[] {
  return localTrain(w0, train.X, train.y, o);
}

// ---------------------------------------------------------------- quantisation (scale s)
export function quantize(v: number[], scale: number): bigint[] {
  return v.map((x) => BigInt(Math.round(x * scale)));
}

export function normSqInt(q: bigint[]): bigint {
  return q.reduce((a, b) => a + b * b, 0n);
}
