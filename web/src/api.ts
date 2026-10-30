// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json; a person's vault follows
// Bitwarden's API as Vaultwarden serves it, through /api/v1/vault, and is decrypted in vault.ts.

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export type Access = "read" | "edit" | "manage";

export type ConfigFile = { path: string; appliedAt: string | null; vaults: number; groups: number; error: string | null } | null;

export interface SyncResult {
  at: string;
  ok: boolean;
  added: string[];
  removed: string[];
  vaults: string[];
  missing: string[];
  policies: string[];
  notes: string[];
  error: string | null;
}

export interface Policies {
  twoStepLogin: boolean;
  masterPassword: { minLength: number; minComplexity: number } | null;
  passwordGenerator: { minLength: number } | null;
  disableSend: boolean;
}

export interface Summary {
  vaults: number;
  groups: number;
  members: number | null;
  waiting: number | null;
  keyHolders: number | null;
  missing: string[];
  policies: Policies;
  file: ConfigFile;
  sync: SyncResult | null;
  identity: string | null;
  organizationId: string;
  vaultwardenUrl: string;
  leakCheck: boolean;
  features: { email: string; groups: boolean; events: boolean } | null;
}

export interface VaultMember {
  name: string;
  email: string;
  access: Access;
  group: string;
}

export interface Vault {
  id: string;
  name: string;
  access: Array<{ group: string; access: Access }>;
  collectionId: string | null;
  members: VaultMember[];
}

export interface Confirmation {
  id: string;
  email: string;
  name: string;
}

export type Action = "opened" | "copied" | "filled" | "changed" | "added" | "moved" | "removed";

export interface VaultEvent {
  id: string;
  at: string;
  type: number;
  action: Action;
  actor: { email: string; name: string } | null;
  itemId: string;
  vaults: string[];
  collections: string[];
  deviceType: number | null;
  ip: string | null;
}

export interface LeaverItem {
  itemId: string;
  vaults: string[];
  lastOpened: string | null;
  recent: boolean;
  changed: boolean;
  changedBy: string | null;
  deleted: boolean;
}

export interface Leaver {
  id: number;
  email: string;
  name: string;
  reason: "planned" | "disabled" | "no-group" | "gone";
  leavesOn: string | null;
  leftAt: string | null;
  items: LeaverItem[];
  changed: number;
}

export interface VaultSettings {
  email: string;
  organizationId: string;
  vaultwardenUrl: string;
  leakCheck: boolean;
  member: { id: string; status: number; type: number } | null;
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {
  readonly code: string | undefined;
  constructor(message: string, code?: string) {
    super(message);
    this.code = code;
  }
}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(typeof init.body === "string" ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`, problem.code);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export type Call = <T>(path: string, init?: RequestInit) => Promise<T>;
