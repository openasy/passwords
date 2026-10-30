// Unlocking a person's vault in their browser, the way the Bitwarden web vault does: the key derivation settings, the
// master password hash to sign in to Vaultwarden, then the encrypted vault, opened here with keys that never leave
// this page. Requests go through this product's /api/v1/vault, which passes them to Vaultwarden as they are.
//
// The unlocked session lives in memory only: closing or reloading the page, or locking, drops every key and item.
import { type VaultSettings } from "./api.ts";
import {
  CryptoError,
  decrypt,
  decryptText,
  encryptText,
  masterKey,
  masterPasswordHash,
  rsaDecrypt,
  rsaEncrypt,
  symmetricKey,
  userKey,
  type SymmetricKey,
} from "./crypto.ts";

export type Kind = "login" | "note" | "card" | "identity" | "other";
const KINDS: Record<number, Kind> = { 1: "login", 2: "note", 3: "card", 4: "identity" };

export interface Item {
  id: string;
  kind: Kind;
  organizationId: string | null;
  collectionIds: string[];
  name: string;
  notes: string | null;
  username: string | null;
  password: string | null;
  totp: string | null;
  uris: string[];
  card: { holder: string | null; number: string | null; brand: string | null; expiry: string | null; code: string | null } | null;
  creationDate: string;
  revisionDate: string;
  /** When the password last changed, or null when it never did. */
  passwordRevisionDate: string | null;
  /** Earlier passwords kept with the item. */
  history: number;
  edit: boolean;
  viewPassword: boolean;
  deleted: boolean;
  /** Set when this item cannot be opened with the keys this browser has. */
  error: string | null;
}

export interface Collection {
  id: string;
  organizationId: string;
  name: string;
  externalId: string | null;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

/** Vaultwarden asks for a second step; `providers` are Bitwarden's ids (0 authenticator app, 1 email, 7 passkey). */
export class TwoFactorRequired extends Error {
  readonly providers: number[];
  constructor(providers: number[]) {
    super("Two-step login is on for this account.");
    this.providers = providers;
  }
}
/** Signed out of Passwords itself, not only of Vaultwarden. */
export class SessionEnded extends Error {}
export class VaultError extends Error {}

/** Bitwarden's event types the page reports, as the apps do. */
export const EVENT = { viewed: 1107, passwordShown: 1108, cardCodeShown: 1110, copiedPassword: 1111, copiedCardCode: 1113, cardNumberShown: 1117 } as const;

/** Bitwarden's device type of this browser, so Vaultwarden's log says where an item was opened. */
export function deviceType(ua: string = globalThis.navigator?.userAgent ?? ""): number {
  if (/Edg\//.test(ua)) return 12;
  if (/OPR\//.test(ua)) return 11;
  if (/Vivaldi/.test(ua)) return 18;
  if (/Firefox\//.test(ua)) return 10;
  if (/Chrome\//.test(ua)) return 9;
  if (/Safari\//.test(ua)) return 17;
  return 14;
}

/** A device id kept by this browser, so Vaultwarden sees one device rather than a new one at each unlock. */
function deviceId(): string {
  try {
    const known = localStorage.getItem("passwords.device");
    if (known) return known;
    const id = crypto.randomUUID();
    localStorage.setItem("passwords.device", id);
    return id;
  } catch {
    return crypto.randomUUID();
  }
}

/** Vaultwarden's own words for a refusal. */
function reason(body: unknown, status: number): string {
  const b = (body ?? {}) as { message?: string; error_description?: string; errorModel?: { message?: string }; ErrorModel?: { Message?: string } };
  return b.errorModel?.message || b.ErrorModel?.Message || b.message || b.error_description || `Vaultwarden answered ${status}.`;
}

type Raw = Record<string, any>;

export interface Session {
  email: string;
  organizationId: string;
  items: Item[];
  collections: Collection[];
  /** Owner or admin of the organization in Vaultwarden: can see every shared item, confirm members and make vaults. */
  orgAdmin: boolean;
  /** Every item of the organization, for owners and admins: Activity and Leavers name items with it. */
  organizationItems(): Promise<Item[]>;
  /** Tells Vaultwarden's log that the person opened or copied a shared item, as the Bitwarden apps do. */
  report(type: number, item: Item): void;
  /** Gives the organization's key to members who joined, encrypted to each one's public key. */
  confirm(memberIds: string[]): Promise<{ confirmed: string[]; failed: Array<{ id: string; error: string }> }>;
  /** Creates the collection of a vault of the file, its name encrypted with the organization's key. */
  createVault(id: string, name: string): Promise<void>;
  /** Gives a vault's collection the name of the file. */
  renameVault(collectionId: string, id: string, name: string): Promise<void>;
  /** Reads the vault again. */
  reload(): Promise<void>;
}

export interface UnlockOptions {
  twoFactor?: { provider: number; code: string };
  fetch?: typeof fetch;
}

export async function unlock(password: string, settings: VaultSettings, { twoFactor, fetch: f = fetch }: UnlockOptions = {}): Promise<Session> {
  let access = "";
  let refresh = "";

  async function call(path: string, init: RequestInit = {}, retry = true): Promise<any> {
    const res = await f(path, {
      ...init,
      credentials: "same-origin",
      headers: {
        ...(typeof init.body === "string" && { "content-type": "application/json" }),
        ...(access && { "x-vault-authorization": `Bearer ${access}` }),
        "device-type": String(deviceType()),
        ...(init.headers as Record<string, string>),
      },
    });
    const type = res.headers.get("content-type") ?? "";
    const body = await res.json().catch(() => ({}));
    if (res.status === 401 && type.startsWith("application/problem+json")) throw new SessionEnded((body as { detail?: string }).detail);
    if (res.status === 401 && retry && refresh) {
      await token({ grant_type: "refresh_token", refresh_token: refresh });
      return call(path, init, false);
    }
    if (!res.ok) {
      if (type.startsWith("application/problem+json")) throw new VaultError((body as { detail?: string }).detail ?? `${res.status}`);
      if (res.status === 400 && (body as { TwoFactorProviders?: string[] }).TwoFactorProviders)
        throw new TwoFactorRequired((body as { TwoFactorProviders: string[] }).TwoFactorProviders.map(Number));
      throw new VaultError(reason(body, res.status));
    }
    return body;
  }

  async function token(fields: Record<string, string>): Promise<Raw> {
    const body = await call(
      "/api/v1/vault/token",
      { method: "POST", body: new URLSearchParams(fields).toString(), headers: { "content-type": "application/x-www-form-urlencoded" } },
      false,
    );
    access = body.access_token;
    if (body.refresh_token) refresh = body.refresh_token;
    return body;
  }

  const pre = await call("/api/v1/vault/prelogin", { method: "POST", body: "{}" });
  const mk = await masterKey(password, settings.email, {
    kdf: pre.kdf ?? pre.Kdf ?? 0,
    iterations: pre.kdfIterations ?? pre.KdfIterations,
    memory: pre.kdfMemory ?? pre.KdfMemory ?? null,
    parallelism: pre.kdfParallelism ?? pre.KdfParallelism ?? null,
  });
  const signedIn = await token({
    grant_type: "password",
    password: await masterPasswordHash(mk, password),
    device_identifier: deviceId(),
    device_name: "OpenAsy Passwords",
    device_type: String(deviceType()),
    ...(twoFactor && { two_factor_provider: String(twoFactor.provider), two_factor_token: twoFactor.code.replace(/\s/g, ""), two_factor_remember: "0" }),
  });
  if (!signedIn.Key) throw new VaultError("This account has no key yet: set it up in a Bitwarden app or the web vault first.");
  const user = await symmetricKey(await userKey(signedIn.Key, mk));
  mk.fill(0);

  let orgRaw: Uint8Array<ArrayBuffer> | null = null;
  let orgKey: SymmetricKey | null = null;
  let orgAdmin = false;
  const session: Session = {
    email: settings.email,
    organizationId: settings.organizationId,
    items: [],
    collections: [],
    orgAdmin: false,

    async reload() {
      const sync = await call("/api/v1/vault/sync");
      const pkcs8 = await decrypt(sync.profile.privateKey, user);
      const orgs = new Map<string, SymmetricKey>();
      for (const o of (sync.profile.organizations ?? []) as Raw[]) {
        if (!o.key) continue;
        try {
          const raw = await rsaDecrypt(o.key, pkcs8);
          orgs.set(o.id, await symmetricKey(raw));
          if (o.id === settings.organizationId) ((orgRaw = raw), (orgKey = orgs.get(o.id)!), (orgAdmin = o.type === 0 || o.type === 1));
        } catch {
          // An organization this page cannot open is left out; the Bitwarden apps still can.
        }
      }
      pkcs8.fill(0);
      session.orgAdmin = orgAdmin;
      session.items = await Promise.all(((sync.ciphers ?? []) as Raw[]).map((c) => openItem(c, c.organizationId ? orgs.get(c.organizationId) : user)));
      session.collections = await Promise.all(
        ((sync.collections ?? []) as Raw[]).map(async (c) => ({
          id: c.id,
          organizationId: c.organizationId,
          name: await opened(c.name, orgs.get(c.organizationId)),
          externalId: c.externalId ?? null,
          readOnly: !!c.readOnly,
          hidePasswords: !!c.hidePasswords,
          manage: !!c.manage,
        })),
      );
    },

    async organizationItems() {
      if (!orgAdmin || !orgKey) return session.items.filter((i) => i.organizationId === settings.organizationId);
      const r = await call("/api/v1/vault/organization/items");
      return Promise.all(((r.data ?? []) as Raw[]).map((c) => openItem(c, orgKey!)));
    },

    report(type, item) {
      if (item.organizationId !== settings.organizationId) return;
      void call("/api/v1/vault/events", {
        method: "POST",
        body: JSON.stringify([{ type, cipherId: item.id, organizationId: item.organizationId, date: new Date().toISOString() }]),
      }).catch(() => {});
    },

    async confirm(memberIds) {
      if (!orgRaw) throw new VaultError("This browser does not hold the organization's key.");
      const keys = (await call("/api/v1/vault/organization/public-keys", { method: "POST", body: JSON.stringify({ ids: memberIds }) })).data as Array<{
        id: string;
        key: string | null;
      }>;
      const given = await Promise.all(keys.filter((k) => k.key).map(async (k) => ({ id: k.id, key: await rsaEncrypt(orgRaw!, k.key!) })));
      const r = given.length ? await call("/api/v1/vault/organization/confirm", { method: "POST", body: JSON.stringify({ keys: given }) }) : { data: [] };
      const failed = [
        ...memberIds.filter((id) => !given.some((g) => g.id === id)).map((id) => ({ id, error: "This member has not set up their account yet." })),
        ...((r.data ?? []) as Array<{ id: string; error: string }>).filter((x) => x.error),
      ];
      return { confirmed: given.map((g) => g.id).filter((id) => !failed.some((x) => x.id === id)), failed };
    },

    async createVault(id, name) {
      if (!orgKey) throw new VaultError("This browser does not hold the organization's key.");
      await call("/api/v1/vault/organization/collections", {
        method: "POST",
        body: JSON.stringify({ name: await encryptText(name, orgKey), externalId: id, groups: [], users: [] }),
      });
    },

    async renameVault(collectionId, id, name) {
      if (!orgKey) throw new VaultError("This browser does not hold the organization's key.");
      await call(`/api/v1/vault/organization/collections/${encodeURIComponent(collectionId)}`, {
        method: "PUT",
        body: JSON.stringify({ name: await encryptText(name, orgKey), externalId: id, groups: [], users: [] }),
      });
    },
  };
  await session.reload();
  return session;
}

/** Decrypts a value, or null when there is none. */
async function opened(value: string | null | undefined, key: SymmetricKey | undefined): Promise<string> {
  if (!value) return "";
  if (!key) throw new CryptoError("No key for this value.");
  return decryptText(value, key);
}

/** An item as Vaultwarden sends it, decrypted with its own key when it has one, else its vault's. */
export async function openItem(c: Raw, vaultKey: SymmetricKey | undefined): Promise<Item> {
  const base: Item = {
    id: c.id,
    kind: KINDS[c.type] ?? "other",
    organizationId: c.organizationId ?? null,
    collectionIds: c.collectionIds ?? [],
    name: "",
    notes: null,
    username: null,
    password: null,
    totp: null,
    uris: [],
    card: null,
    creationDate: c.creationDate ?? c.revisionDate,
    revisionDate: c.revisionDate,
    passwordRevisionDate: c.login?.passwordRevisionDate ?? null,
    history: Array.isArray(c.passwordHistory) ? c.passwordHistory.length : 0,
    edit: c.edit !== false,
    viewPassword: c.viewPassword !== false,
    deleted: !!c.deletedDate,
    error: null,
  };
  try {
    if (!vaultKey) throw new CryptoError("This browser does not hold this vault's key.");
    const key = c.key ? await symmetricKey(await decrypt(c.key, vaultKey)) : vaultKey;
    const text = async (v: unknown) => (typeof v === "string" && v ? decryptText(v, key) : null);
    base.name = (await text(c.name)) ?? "";
    base.notes = await text(c.notes);
    if (c.login) {
      base.username = await text(c.login.username);
      base.password = await text(c.login.password);
      base.totp = await text(c.login.totp);
      base.uris = (await Promise.all(((c.login.uris ?? []) as Raw[]).map((u) => text(u.uri)))).filter((u): u is string => !!u);
    }
    if (c.card) {
      const month = await text(c.card.expMonth);
      const year = await text(c.card.expYear);
      base.card = {
        holder: await text(c.card.cardholderName),
        number: await text(c.card.number),
        brand: await text(c.card.brand),
        expiry: month && year ? `${month.padStart(2, "0")}/${year}` : null,
        code: await text(c.card.code),
      };
    }
  } catch (err) {
    base.error = (err as Error).message;
  }
  return base;
}
