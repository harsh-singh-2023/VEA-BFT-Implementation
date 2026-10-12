/**
 * The three public clinical datasets of the evaluation (paper Table I) and the exact
 * preprocessing / partitioning protocol of Section VII-C:
 *   - median imputation of documented missing values, z-score normalisation,
 *   - stratified 75 % train / 25 % hold-out split,
 *   - training set divided among h hospitals by sorting on the first standardised feature
 *     (an artificial non-IID split).
 * Imputation and normalisation statistics are fitted on the training part only, so the
 * hold-out set never leaks into preprocessing.
 */
import * as fs from "fs";
import * as path from "path";

export type DatasetName = "heart" | "pima" | "wdbc";

export interface RawDataset {
  name: DatasetName;
  title: string;
  task: string;
  features: string[];
  X: number[][]; // NaN marks a missing value
  y: number[];
}

export interface Split {
  X: number[][];
  y: number[];
}

export interface Prepared {
  name: DatasetName;
  title: string;
  task: string;
  features: string[]; // includes the trailing "bias"
  train: Split;
  test: Split;
  shards: Split[];
  nFeatures: number; // incl. bias
}

export const DATASETS: Record<DatasetName, { title: string; task: string }> = {
  heart: { title: "Cleveland Heart Disease", task: "Coronary disease" },
  pima: { title: "Pima Indians Diabetes", task: "Diabetes onset" },
  wdbc: { title: "Wisconsin Diagnostic Breast Cancer", task: "Malignant or benign" },
};

const DATA_DIR = path.resolve(__dirname, "../../data/raw");

function readLines(file: string): string[] {
  return fs.readFileSync(path.join(DATA_DIR, file), "utf8").split(/\r?\n/).filter((l) => l.trim().length);
}

export function loadRaw(name: DatasetName): RawDataset {
  const meta = DATASETS[name];
  if (name === "heart") {
    const features = ["age", "sex", "cp", "trestbps", "chol", "fbs", "restecg", "thalach", "exang", "oldpeak", "slope", "ca", "thal"];
    const X: number[][] = [];
    const y: number[] = [];
    for (const line of readLines("cleveland.data")) {
      const f = line.split(",");
      X.push(f.slice(0, 13).map((v) => (v.trim() === "?" ? NaN : Number(v))));
      y.push(Number(f[13]) > 0 ? 1 : 0);
    }
    return { name, ...meta, features, X, y };
  }
  if (name === "pima") {
    const features = ["pregnancies", "glucose", "blood_pressure", "skin_thickness", "insulin", "bmi", "pedigree", "age"];
    const X: number[][] = [];
    const y: number[] = [];
    for (const line of readLines("pima.csv")) {
      const f = line.split(",").map(Number);
      const row = f.slice(0, 8);
      // documented missing values: physiologically impossible zeros
      for (const c of [1, 2, 3, 4, 5]) if (row[c] === 0) row[c] = NaN;
      X.push(row);
      y.push(f[8]);
    }
    return { name, ...meta, features, X, y };
  }
  const features = ["radius", "texture", "perimeter", "area", "smoothness", "compactness", "concavity", "concave_points", "symmetry", "fractal_dim"];
  const X: number[][] = [];
  const y: number[] = [];
  for (const line of readLines("wdbc.data")) {
    const f = line.split(",");
    y.push(f[1] === "M" ? 1 : 0);
    X.push(f.slice(2, 12).map(Number)); // the ten "mean" features
  }
  return { name, ...meta, features, X, y };
}

// ---------------------------------------------------------------- deterministic PRNG
function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function hashSeed(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function shuffle<T>(arr: T[], rnd: () => number): T[] {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rnd() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

const median = (v: number[]) => {
  const s = v.filter((x) => !Number.isNaN(x)).sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

export function prepare(raw: RawDataset, opts: { seed?: string; hospitals?: number; testFraction?: number } = {}): Prepared {
  const seed = opts.seed ?? "vea-bft";
  const h = opts.hospitals ?? 5;
  const testFrac = opts.testFraction ?? 0.25;
  const rnd = mulberry32(hashSeed(seed + "/" + raw.name));

  // stratified split
  const trainIdx: number[] = [];
  const testIdx: number[] = [];
  for (const cls of [0, 1]) {
    const idx = shuffle(raw.y.map((v, i) => (v === cls ? i : -1)).filter((i) => i >= 0), rnd);
    const nTest = Math.round(idx.length * testFrac);
    testIdx.push(...idx.slice(0, nTest));
    trainIdx.push(...idx.slice(nTest));
  }
  const pick = (idx: number[]) => ({ X: idx.map((i) => raw.X[i].slice()), y: idx.map((i) => raw.y[i]) });
  const train = pick(shuffle(trainIdx, rnd));
  const test = pick(shuffle(testIdx, rnd));

  const d = raw.features.length;
  const med: number[] = [];
  const mean: number[] = [];
  const sd: number[] = [];
  for (let j = 0; j < d; j++) {
    med.push(median(train.X.map((r) => r[j])));
    const col = train.X.map((r) => (Number.isNaN(r[j]) ? med[j] : r[j]));
    const mu = col.reduce((a, b) => a + b, 0) / col.length;
    const v = col.reduce((a, b) => a + (b - mu) ** 2, 0) / col.length;
    mean.push(mu);
    sd.push(Math.sqrt(v) || 1);
  }
  const norm = (s: Split): Split => ({
    y: s.y,
    X: s.X.map((r) => [...r.map((x, j) => ((Number.isNaN(x) ? med[j] : x) - mean[j]) / sd[j]), 1]), // trailing bias
  });
  const trainN = norm(train);
  const testN = norm(test);

  // artificial non-IID partition: sort by the first standardised feature, cut into h shards
  const order = trainN.X.map((_, i) => i).sort((a, b) => trainN.X[a][0] - trainN.X[b][0]);
  const shards: Split[] = [];
  for (let k = 0; k < h; k++) {
    const lo = Math.floor((k * order.length) / h);
    const hi = Math.floor(((k + 1) * order.length) / h);
    const ids = order.slice(lo, hi);
    shards.push({ X: ids.map((i) => trainN.X[i]), y: ids.map((i) => trainN.y[i]) });
  }
  return {
    name: raw.name,
    title: raw.title,
    task: raw.task,
    features: [...raw.features, "bias"],
    train: trainN,
    test: testN,
    shards,
    nFeatures: d + 1,
  };
}

export function loadPrepared(name: DatasetName, opts?: { seed?: string; hospitals?: number }): Prepared {
  return prepare(loadRaw(name), opts);
}
