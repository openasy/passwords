// Two-step codes (TOTP, RFC 6238) from an item's secret, made in the browser like the Bitwarden apps make them. The
// secret is an otpauth:// URI or a plain base32 key.

export interface TotpSpec {
  key: Uint8Array<ArrayBuffer>;
  digits: number;
  period: number;
  algorithm: "SHA-1" | "SHA-256" | "SHA-512";
}

function base32(s: string): Uint8Array<ArrayBuffer> | null {
  const clean = s.replace(/[\s=-]/g, "").toUpperCase();
  if (!clean || /[^A-Z2-7]/.test(clean)) return null;
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const c of clean) {
    value = (value << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Reads an item's TOTP field; null when it is empty or not a TOTP secret (Steam codes are left to the apps). */
export function parseTotp(secret: string | null): TotpSpec | null {
  if (!secret?.trim()) return null;
  const s = secret.trim();
  if (s.toLowerCase().startsWith("otpauth://")) {
    const url = URL.parse(s);
    if (!url || url.host.toLowerCase() !== "totp") return null;
    const key = base32(url.searchParams.get("secret") ?? "");
    const digits = Number(url.searchParams.get("digits") ?? 6);
    const period = Number(url.searchParams.get("period") ?? 30);
    const alg = (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase();
    const algorithm = alg === "SHA256" ? "SHA-256" : alg === "SHA512" ? "SHA-512" : "SHA-1";
    if (!key || !key.length || digits < 6 || digits > 10 || period < 1) return null;
    return { key, digits, period, algorithm };
  }
  const key = base32(s);
  return key?.length ? { key, digits: 6, period: 30, algorithm: "SHA-1" } : null;
}

/** The code at a time (ms), and the seconds it stays valid. */
export async function totp(spec: TotpSpec, at: number): Promise<{ code: string; remaining: number }> {
  const step = Math.floor(at / 1000 / spec.period);
  const counter = new Uint8Array(8);
  new DataView(counter.buffer).setBigUint64(0, BigInt(step));
  const key = await globalThis.crypto.subtle.importKey("raw", spec.key, { name: "HMAC", hash: spec.algorithm }, false, ["sign"]);
  const mac = new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", key, counter));
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  const code = String(bin % 10 ** spec.digits).padStart(spec.digits, "0");
  return { code, remaining: spec.period - (Math.floor(at / 1000) % spec.period) };
}
