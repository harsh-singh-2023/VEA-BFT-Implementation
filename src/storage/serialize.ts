/** Canonical, deterministic serialization used for everything that is hashed or stored. */
export function canonicalize(value: unknown): Uint8Array {
  const json = JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? "bn:" + v.toString(16) : v));
  return new Uint8Array(Buffer.from(json, "utf8"));
}

export function parse<T = any>(bytes: Uint8Array): T {
  return JSON.parse(Buffer.from(bytes).toString("utf8"), (_k, v) =>
    typeof v === "string" && v.startsWith("bn:") ? BigInt("0x" + v.slice(3)) : v
  ) as T;
}
