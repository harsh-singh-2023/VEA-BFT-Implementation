/** Dependency-free SVG line charts for the evaluation figures. */
export interface Series { name: string; color: string; dash?: string; values: number[] }

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

export function lineChart(o: { title: string; xlabel: string; ylabel: string; series: Series[]; vline?: number; w?: number; h?: number }): string {
  const W = o.w ?? 640, H = o.h ?? 380, ml = 64, mr = 20, mt = 46, mb = 52;
  const all = o.series.flatMap((s) => s.values).filter((v) => Number.isFinite(v));
  let lo = Math.min(...all), hi = Math.max(...all);
  const pad = (hi - lo || 0.01) * 0.08;
  lo -= pad; hi += pad;
  const n = Math.max(...o.series.map((s) => s.values.length));
  const x = (i: number) => ml + (i / Math.max(1, n - 1)) * (W - ml - mr);
  const y = (v: number) => H - mb - ((v - lo) / (hi - lo)) * (H - mt - mb);
  let g = `<rect width="${W}" height="${H}" fill="white"/>`;
  g += `<text x="${W / 2}" y="22" text-anchor="middle" font-size="15" font-family="sans-serif" font-weight="600">${esc(o.title)}</text>`;
  for (let k = 0; k <= 5; k++) {
    const v = lo + ((hi - lo) * k) / 5, yy = y(v);
    g += `<line x1="${ml}" x2="${W - mr}" y1="${yy}" y2="${yy}" stroke="#e5e7eb"/><text x="${ml - 6}" y="${yy + 4}" text-anchor="end" font-size="11" font-family="sans-serif">${v.toFixed(3)}</text>`;
  }
  for (let i = 0; i < n; i += Math.max(1, Math.round(n / 6))) {
    g += `<text x="${x(i)}" y="${H - mb + 16}" text-anchor="middle" font-size="11" font-family="sans-serif">${i + 1}</text>`;
  }
  g += `<text x="${(ml + W - mr) / 2}" y="${H - 10}" text-anchor="middle" font-size="12" font-family="sans-serif">${esc(o.xlabel)}</text>`;
  g += `<text transform="translate(16 ${H / 2}) rotate(-90)" text-anchor="middle" font-size="12" font-family="sans-serif">${esc(o.ylabel)}</text>`;
  g += `<rect x="${ml}" y="${mt}" width="${W - ml - mr}" height="${H - mt - mb}" fill="none" stroke="#9ca3af"/>`;
  if (o.vline !== undefined) g += `<line x1="${x(o.vline - 1)}" x2="${x(o.vline - 1)}" y1="${mt}" y2="${H - mb}" stroke="#16a34a" stroke-dasharray="4 3"/>`;
  o.series.forEach((s, k) => {
    const pts = s.values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
    g += `<polyline points="${pts}" fill="none" stroke="${s.color}" stroke-width="2" ${s.dash ? `stroke-dasharray="${s.dash}"` : ""}/>`;
    g += `<line x1="${ml + 8 + k * 150}" x2="${ml + 30 + k * 150}" y1="${mt - 12}" y2="${mt - 12}" stroke="${s.color}" stroke-width="2" ${s.dash ? `stroke-dasharray="${s.dash}"` : ""}/><text x="${ml + 34 + k * 150}" y="${mt - 8}" font-size="11" font-family="sans-serif">${esc(s.name)}</text>`;
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}">${g}</svg>`;
}
