// Password health, worked out in the browser from the items it decrypted: weak, reused across items, not changed in two
// years, and, when the install allows it, leaked. A leak is looked up with the k-anonymity range API of Have I Been
// Pwned: only the first five characters of the password's SHA-1 leave the browser, never the password or its full hash.

export type Strength = "strong" | "fair" | "weak";
export type Issue = "leaked" | "weak" | "reused" | "old";

/** Passwords every list of leaked passwords starts with; matched without case, digits and symbols at the ends. */
const COMMON = new Set([
  "password",
  "passw0rd",
  "123456",
  "12345678",
  "123456789",
  "qwerty",
  "qwertyuiop",
  "letmein",
  "welcome",
  "admin",
  "administrator",
  "iloveyou",
  "monkey",
  "dragon",
  "football",
  "baseball",
  "sunshine",
  "princess",
  "abc123",
  "changeme",
  "secret",
  "default",
  "summer",
  "winter",
  "spring",
  "autumn",
]);

const classes = (p: string) => [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;

export function strength(password: string): Strength {
  const core = password.toLowerCase().replace(/^[\d\W_]+|[\d\W_]+$/g, "");
  if (password.length < 10 || COMMON.has(core) || COMMON.has(password.toLowerCase())) return "weak";
  // A word and a year or a number, such as Summer2025.
  if (/^[A-Za-z]+\d{1,4}[!?.#*]?$/.test(password) || /^(.)\1+$/.test(password)) return "weak";
  if (password.length < 14 || classes(password) < 3) return "fair";
  return "strong";
}

export interface Checked {
  id: string;
  password: string | null;
  /** When the password last changed, or when the item was made. */
  changedAt: string | null;
}

export interface Finding {
  itemId: string;
  issue: Issue;
  /** Leaked: times seen in breaches. Reused: other items with the same password. Weak: length. Old: the date. */
  detail: number | string;
}

const TWO_YEARS = 2 * 365 * 86_400_000;

/** The problems of each login with a password; `leaks` holds the breach counts the range API gave. */
export function findings(items: Checked[], { now, leaks = new Map<string, number>() }: { now: number; leaks?: Map<string, number> }): Finding[] {
  const withPassword = items.filter((i) => i.password);
  const same = new Map<string, string[]>();
  for (const i of withPassword) same.set(i.password!, [...(same.get(i.password!) ?? []), i.id]);
  const out: Finding[] = [];
  for (const i of withPassword) {
    const leaked = leaks.get(i.id);
    if (leaked) out.push({ itemId: i.id, issue: "leaked", detail: leaked });
    if (strength(i.password!) === "weak") out.push({ itemId: i.id, issue: "weak", detail: i.password!.length });
    const others = same.get(i.password!)!.length - 1;
    if (others) out.push({ itemId: i.id, issue: "reused", detail: others });
    if (i.changedAt && now - Date.parse(i.changedAt) > TWO_YEARS) out.push({ itemId: i.id, issue: "old", detail: i.changedAt });
  }
  return out;
}

/** Share of items with no problem, as a whole percentage. */
export function score(itemIds: string[], found: Finding[]): number {
  if (!itemIds.length) return 100;
  const bad = new Set(found.map((f) => f.itemId));
  return Math.round((100 * itemIds.filter((id) => !bad.has(id)).length) / itemIds.length);
}

async function sha1Hex(s: string): Promise<string> {
  const d = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-1", new TextEncoder().encode(s)));
  return [...d]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

export const RANGE_API = "https://api.pwnedpasswords.com/range/";

/**
 * How often each password was seen in breaches, by item id, from the range API. Each prefix is asked once, with
 * padding, so the answer's size says nothing either.
 */
export async function leaks(items: Checked[], f: typeof fetch = fetch): Promise<Map<string, number>> {
  const byPrefix = new Map<string, Array<{ id: string; suffix: string }>>();
  for (const i of items) {
    if (!i.password) continue;
    const h = await sha1Hex(i.password);
    byPrefix.set(h.slice(0, 5), [...(byPrefix.get(h.slice(0, 5)) ?? []), { id: i.id, suffix: h.slice(5) }]);
  }
  const out = new Map<string, number>();
  for (const [prefix, list] of byPrefix) {
    const res = await f(RANGE_API + prefix, { headers: { "add-padding": "true" }, referrerPolicy: "no-referrer", credentials: "omit" });
    if (!res.ok) throw new Error(`The leak lookup answered ${res.status}.`);
    const counts = new Map(
      (await res.text()).split("\n").map((line) => {
        const [suffix, count] = line.trim().split(":");
        return [suffix ?? "", Number(count ?? 0)] as const;
      }),
    );
    for (const i of list) {
      const n = counts.get(i.suffix) ?? 0;
      if (n > 0) out.set(i.id, n);
    }
  }
  return out;
}
