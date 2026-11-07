// Items written in this browser, in the shape the Bitwarden clients send to Vaultwarden (1.37.4: CipherData in
// src/api/core/ciphers.rs). Every value is encrypted here with the item's own key before it leaves the page; the
// server only passes it on.
//
// A new item gets its own key, as the current Bitwarden clients make one: 64 random bytes, encrypted with the vault's
// key (the person's user key, or the organization's key for a shared vault). A changed item keeps its key, and only
// the fields of the form are encrypted again; everything else the item has (custom fields, passkeys, attachments, its
// folder, favourite and archive state) is sent back as it came, so nothing a Bitwarden app added is lost.
import { b64, decrypt, encrypt, encryptText, sha256, symmetricKey, type SymmetricKey } from "./crypto.ts";

type Raw = Record<string, any>;

export type EditableKind = "login" | "note" | "card";
const TYPE: Record<EditableKind, number> = { login: 1, note: 2, card: 3 };

/** What the form holds, in plain text, only in this page. */
export interface Draft {
  kind: EditableKind;
  name: string;
  notes: string;
  username: string;
  password: string;
  totp: string;
  /** The first web address; the item's other addresses are kept as they are. */
  uri: string;
  card: { holder: string; brand: string; number: string; expMonth: string; expYear: string; code: string };
}

export const emptyDraft = (kind: EditableKind = "login"): Draft => ({
  kind,
  name: "",
  notes: "",
  username: "",
  password: "",
  totp: "",
  uri: "",
  card: { holder: "", brand: "", number: "", expMonth: "", expYear: "", code: "" },
});

/** An item as it was opened: Vaultwarden's encrypted record, the key its fields are encrypted with, and that key's bytes when it has its own. */
export interface Opened {
  raw: Raw;
  key: SymmetricKey;
  itemKey: Uint8Array<ArrayBuffer> | null;
}

/** How many earlier passwords an item keeps, as the Bitwarden clients do. */
const HISTORY = 5;

/** The fields of CipherData a client sends; the rest of what Vaultwarden answers (dates, permissions) stays out. */
function sendable(raw: Raw): Raw {
  const out: Raw = {};
  for (const k of [
    "type",
    "organizationId",
    "folderId",
    "key",
    "name",
    "notes",
    "fields",
    "login",
    "secureNote",
    "card",
    "identity",
    "sshKey",
    "favorite",
    "reprompt",
    "passwordHistory",
    "archivedDate",
  ])
    if (raw[k] !== undefined) out[k] = raw[k];
  return out;
}

/** The checksum the Bitwarden clients keep next to a web address, so a changed one is noticed: SHA-256, encrypted. */
async function uriChecksum(uri: string, key: SymmetricKey): Promise<string> {
  return encryptText(b64.encode(await sha256(new TextEncoder().encode(uri))), key);
}

export interface BuildOptions {
  draft: Draft;
  /** The person's Vaultwarden user id: Vaultwarden refuses an item not encrypted for the caller. */
  userId: string;
  /** For a new item: the key of the vault it goes in, and the organization when it is a shared one. */
  vaultKey?: SymmetricKey;
  organizationId?: string | null;
  /** For a changed item: what was opened, and its decrypted values to compare with. */
  previous?: { opened: Opened; password: string | null; uri: string | null };
  now?: Date;
}

/** The encrypted record to send to Vaultwarden for a new or changed item. */
export async function buildCipher({ draft, userId, vaultKey, organizationId = null, previous, now = new Date() }: BuildOptions): Promise<Raw> {
  const name = draft.name.trim();
  if (!name) throw new Error("An item needs a name.");
  let key: SymmetricKey;
  let out: Raw;
  if (previous) {
    key = previous.opened.key;
    out = sendable(previous.opened.raw);
    out.lastKnownRevisionDate = previous.opened.raw.revisionDate;
    if (out.type !== TYPE[draft.kind]) throw new Error("An item keeps its kind.");
  } else {
    if (!vaultKey) throw new Error("A new item needs the key of its vault.");
    const itemKey = globalThis.crypto.getRandomValues(new Uint8Array(64));
    key = await symmetricKey(itemKey);
    out = { type: TYPE[draft.kind], organizationId, folderId: null, key: await encrypt(itemKey, vaultKey), favorite: false, reprompt: 0, fields: null };
  }
  const enc = async (v: string) => (v ? encryptText(v, key) : null);
  out.encryptedFor = userId;
  out.name = await encryptText(name, key);
  out.notes = await enc(draft.notes);

  if (draft.kind === "login") {
    const login: Raw = { ...out.login };
    login.username = await enc(draft.username.trim());
    login.password = await enc(draft.password);
    login.totp = await enc(draft.totp.trim());
    const uris: Raw[] = [...(login.uris ?? [])];
    const uri = draft.uri.trim();
    if (uri !== (previous?.uri ?? "")) {
      const first = uri ? { ...(uris[0] ?? { match: null }), uri: await encryptText(uri, key), uriChecksum: await uriChecksum(uri, key) } : null;
      if (previous?.uri) uris.splice(0, 1, ...(first ? [first] : []));
      else if (first) uris.unshift(first);
    }
    login.uris = uris.length ? uris : null;
    const old = previous?.password ?? null;
    if (previous && old && old !== draft.password) {
      out.passwordHistory = [{ password: await encryptText(old, key), lastUsedDate: now.toISOString() }, ...(out.passwordHistory ?? [])].slice(0, HISTORY);
    }
    if (previous && old !== (draft.password || null)) login.passwordRevisionDate = now.toISOString();
    else login.passwordRevisionDate ??= null;
    login.fido2Credentials ??= null;
    out.login = login;
  } else if (draft.kind === "note") {
    out.secureNote = { type: 0 };
  } else {
    const c = draft.card;
    out.card = {
      ...out.card,
      cardholderName: await enc(c.holder.trim()),
      brand: await enc(c.brand.trim()),
      number: await enc(c.number.replace(/\s+/g, "")),
      expMonth: await enc(c.expMonth.trim()),
      expYear: await enc(c.expYear.trim()),
      code: await enc(c.code.trim()),
    };
  }
  return out;
}

const isEncString = (s: string) => /^2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/.test(s);

/** Every encrypted value of a record, decrypted with one key and encrypted with another. */
async function reencrypt(value: unknown, from: SymmetricKey, to: SymmetricKey): Promise<unknown> {
  if (typeof value === "string") return isEncString(value) ? encrypt(await decrypt(value, from), to) : value;
  if (Array.isArray(value)) return Promise.all(value.map((v) => reencrypt(v, from, to)));
  if (value && typeof value === "object") {
    const out: Raw = {};
    for (const [k, v] of Object.entries(value)) out[k] = await reencrypt(v, from, to);
    return out;
  }
  return value;
}

/**
 * A personal item made ready for a shared vault: its own key, encrypted again with the organization's key. An old
 * item without its own key gets one, and its fields are encrypted again with it.
 */
export async function shareCipher(
  opened: Opened,
  { userId, organizationId, orgKey }: { userId: string; organizationId: string; orgKey: SymmetricKey },
): Promise<Raw> {
  if (opened.raw.organizationId) throw new Error("This item is already in a shared vault.");
  if ((opened.raw.attachments ?? []).length) throw new Error("Items with attachments are moved in a Bitwarden app, which also moves the files.");
  let out = sendable(opened.raw);
  if (opened.itemKey) {
    out.key = await encrypt(opened.itemKey, orgKey);
  } else {
    const itemKey = globalThis.crypto.getRandomValues(new Uint8Array(64));
    const key = await symmetricKey(itemKey);
    out = { ...((await reencrypt({ ...out, key: undefined }, opened.key, key)) as Raw), key: await encrypt(itemKey, orgKey) };
  }
  return { ...out, organizationId, encryptedFor: userId, lastKnownRevisionDate: opened.raw.revisionDate };
}

/** A password made in this browser, following the file's generator policy. */
export function generatePassword(policy: { minLength: number; useUpper: boolean; useLower: boolean; useNumbers: boolean; useSpecial: boolean } | null): string {
  const sets = {
    upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",
    lower: "abcdefghijkmnopqrstuvwxyz",
    numbers: "23456789",
    special: "!@#$%^&*",
  };
  const length = Math.max(20, policy?.minLength ?? 0);
  // Upper and lower case letters, digits and special characters are each in it at least once, so it meets any
  // useUpper, useLower, useNumbers or useSpecial the policy asks for.
  const want = [sets.upper, sets.lower, sets.numbers, sets.special];
  const all = want.join("");
  const pick = (from: string) => {
    // Rejection sampling, so every character is equally likely.
    const limit = 256 - (256 % from.length);
    for (;;) {
      const [b] = globalThis.crypto.getRandomValues(new Uint8Array(1));
      if (b! < limit) return from[b! % from.length]!;
    }
  };
  const chars = [...want.map(pick), ...Array.from({ length: length - want.length }, () => pick(all))];
  for (let i = chars.length - 1; i > 0; i--) {
    const [r] = globalThis.crypto.getRandomValues(new Uint32Array(1));
    const j = r! % (i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join("");
}
