// The password server. Vaultwarden keeps every vault, encrypted on people's devices; Passwords talks to it as the
// Bitwarden clients do, with the shapes of its source (1.37.4: src/api/core/public.rs, organizations.rs, events.rs,
// src/api/identity.rs). Two keys, both made in Vaultwarden's web vault:
//
// - the organization's API key, for the directory import Bitwarden's Directory Connector uses
//   (POST /api/public/organization/import): members and groups, with Identity person ids and group names as their
//   external ids;
// - the API key of a service account that is an admin of the organization, for what the import does not do: which
//   groups see which collection, the policies, the members' state, the event log and which item is in which collection.
//
// Neither key can decrypt anything: names and items are encrypted with the organization's key, which only members'
// browsers and apps hold.

/** A member as GET /organizations/<org>/users?includeGroups=true&includeCollections=true returns one. */
export interface VwMember {
  id: string;
  userId: string;
  name: string | null;
  email: string;
  externalId: string | null;
  /** -1 revoked, 0 invited, 1 accepted (waiting to be confirmed), 2 confirmed. */
  status: number;
  /** 0 owner, 1 admin, 2 user, 4 custom (Vaultwarden's manager). */
  type: number;
  groups: string[];
  /** Collections given to the member directly, not through a group. */
  collections: CollectionAccess[];
}

export interface CollectionAccess {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface VwGroup {
  id: string;
  name: string;
  externalId: string | null;
  collections: CollectionAccess[];
}

export interface VwCollection {
  id: string;
  /** Encrypted with the organization's key (an EncString); the server cannot read it. */
  name: string;
  externalId: string | null;
}

export interface VwPolicy {
  type: number;
  enabled: boolean;
  data: Record<string, unknown> | null;
}

/** An event of the organization's log, as GET /organizations/<org>/events returns it. */
export interface VwEvent {
  type: number;
  userId: string | null;
  cipherId: string | null;
  collectionId: string | null;
  groupId: string | null;
  organizationUserId: string | null;
  actingUserId: string | null;
  date: string;
  deviceType: number | null;
  ipAddress: string | null;
}

/** What the server keeps of an organization item: where it is and when it changed, never its encrypted content. */
export interface VwItem {
  id: string;
  type: number;
  collectionIds: string[];
  revisionDate: string;
  deletedDate: string | null;
  /** When a login's password last changed, as the apps record it; null for other items or when never changed. */
  passwordRevisionDate: string | null;
}

export interface ImportPayload {
  groups: Array<{ name: string; externalId: string; memberExternalIds: string[] }>;
  members: Array<{ email: string; externalId: string; deleted: boolean }>;
  overwriteExisting: boolean;
}

export class VaultwardenError extends Error {
  /** The HTTP status Vaultwarden answered with, or 0 when it could not be reached. */
  readonly status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.status = status;
  }
}

export interface VaultwardenOptions {
  /** Where Passwords reaches Vaultwarden, such as http://vaultwarden:80. */
  url: string;
  organizationId: string;
  /** The organization API key's client_secret; its client_id is organization.<organizationId>. */
  orgSecret: string;
  /** The service account's API key: client_id user.<uuid>, and its client_secret. */
  serviceClientId: string;
  serviceSecret: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  now?: () => number;
}

/** The service account appears in Vaultwarden as this device, so its sign-ins are recognisable. */
const SERVICE_DEVICE = "8f0a3a52-41c6-4b4e-9f2e-0a7e5a5d0e11";

/** Vaultwarden's own words for a refusal, from its error body. */
async function reason(res: Response): Promise<string> {
  const text = await res.text();
  try {
    const body = JSON.parse(text) as { message?: string; error_description?: string; errorModel?: { message?: string } };
    return body.errorModel?.message || body.message || body.error_description || text.slice(0, 300);
  } catch {
    return text.slice(0, 300);
  }
}

export function createVaultwarden({
  url,
  organizationId,
  orgSecret,
  serviceClientId,
  serviceSecret,
  fetch: f = fetch,
  timeoutMs = 15_000,
  now = Date.now,
}: VaultwardenOptions) {
  const base = url.replace(/\/$/, "");
  const org = encodeURIComponent(organizationId);
  const tokens = new Map<string, { token: string; until: number }>();

  async function request(path: string, init: RequestInit = {}): Promise<Response> {
    try {
      return await f(base + path, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    } catch (err) {
      throw new VaultwardenError(`Vaultwarden at ${base} cannot be reached: ${(err as Error).message}`);
    }
  }

  /** A bearer token from client credentials, kept until a minute before it ends. */
  async function token(kind: "organization" | "service"): Promise<string> {
    const hit = tokens.get(kind);
    if (hit && hit.until > now()) return hit.token;
    const form = new URLSearchParams(
      kind === "organization"
        ? { grant_type: "client_credentials", scope: "api.organization", client_id: `organization.${organizationId}`, client_secret: orgSecret }
        : {
            grant_type: "client_credentials",
            scope: "api",
            client_id: serviceClientId,
            client_secret: serviceSecret,
            device_identifier: SERVICE_DEVICE,
            device_name: "OpenAsy Passwords",
            device_type: "22",
          },
    );
    const res = await request("/identity/connect/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form });
    if (!res.ok) {
      const which = kind === "organization" ? "the organization API key (PASSWORDS_ORGANIZATION_ID and its secret)" : "the service account's API key";
      throw new VaultwardenError(`Vaultwarden refused ${which}: ${await reason(res)}`, res.status);
    }
    const body = (await res.json()) as { access_token: string; expires_in: number };
    tokens.set(kind, { token: body.access_token, until: now() + Math.max(0, body.expires_in - 60) * 1000 });
    return body.access_token;
  }

  async function call<T>(kind: "organization" | "service", method: string, path: string, body?: unknown): Promise<T> {
    const res = await request(path, {
      method,
      headers: { authorization: `Bearer ${await token(kind)}`, ...(body !== undefined && { "content-type": "application/json" }) },
      ...(body !== undefined && { body: JSON.stringify(body) }),
    });
    if (res.status === 401) tokens.delete(kind);
    if (!res.ok) throw new VaultwardenError(`Vaultwarden answered ${res.status} to ${method} ${path.split("?")[0]}: ${await reason(res)}`, res.status);
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  const list = async <T>(path: string) => (await call<{ data: T[] }>("service", "GET", path)).data;

  return {
    url: base,
    organizationId,

    /** Members and groups as Directory Connector sends them; with overwriteExisting, members left out are removed. */
    async importDirectory(payload: ImportPayload): Promise<void> {
      await call("organization", "POST", "/api/public/organization/import", payload);
    },

    members: () => list<VwMember>(`/api/organizations/${org}/users?includeGroups=true&includeCollections=true`),
    groups: () => list<VwGroup>(`/api/organizations/${org}/groups/details`),
    collections: () => list<VwCollection>(`/api/organizations/${org}/collections`),

    /** Sets which groups see a collection, and removes any member given it directly; its name is left as it is. */
    async setCollectionAccess(collectionId: string, groups: CollectionAccess[]): Promise<void> {
      await call("service", "POST", `/api/organizations/${org}/collections/bulk-access`, { collectionIds: [collectionId], groups, users: [] });
    },

    policies: () => list<VwPolicy>(`/api/organizations/${org}/policies`),
    async setPolicy(type: number, enabled: boolean, data: Record<string, unknown> | null): Promise<void> {
      await call("service", "PUT", `/api/organizations/${org}/policies/${type}`, { policy: { enabled, data } });
    },

    /** One page of the event log, newest first, from start to end; Vaultwarden pages by 30 with the last date as token. */
    async events(start: string, end: string): Promise<{ data: VwEvent[]; continuationToken: string | null }> {
      const q = new URLSearchParams({ start, end });
      return call("service", "GET", `/api/organizations/${org}/events?${q}`);
    },

    /** Every organization item, reduced to where it is and when it changed; the encrypted fields are dropped here. */
    async items(): Promise<VwItem[]> {
      const data = await list<{
        id: string;
        type: number;
        collectionIds?: string[];
        revisionDate: string;
        deletedDate?: string | null;
        login?: { passwordRevisionDate?: string | null } | null;
      }>(`/api/ciphers/organization-details?organizationId=${org}`);
      return data.map((c) => ({
        id: c.id,
        type: c.type,
        collectionIds: c.collectionIds ?? [],
        revisionDate: c.revisionDate,
        deletedDate: c.deletedDate ?? null,
        passwordRevisionDate: c.login?.passwordRevisionDate ?? null,
      }));
    },

    /**
     * The service account's own address, and what Vaultwarden turns on for the organization: groups and events need
     * ORG_GROUPS_ENABLED and ORG_EVENTS_ENABLED.
     */
    async features(): Promise<{ email: string; groups: boolean; events: boolean }> {
      const p = await call<{ email: string; organizations: Array<{ id: string; useGroups?: boolean; useEvents?: boolean }> }>(
        "service",
        "GET",
        "/api/accounts/profile",
      );
      const o = p.organizations.find((x) => x.id === organizationId);
      if (!o) throw new VaultwardenError(`The service account is not a member of organization ${organizationId}.`, 200);
      return { email: p.email.toLowerCase(), groups: o.useGroups === true, events: o.useEvents === true };
    },

    /** Removes a member the import does not know, such as one added by hand before Passwords ran. */
    async removeMember(memberId: string): Promise<void> {
      await call("service", "DELETE", `/api/organizations/${org}/users/${encodeURIComponent(memberId)}`);
    },

    /**
     * A request from a person's browser, passed on as it is: the person's own Vaultwarden token, and a body only their
     * browser can read. Nothing is kept or logged.
     */
    async pass(method: string, path: string, init: { authorization?: string; body?: Buffer | string; contentType?: string; deviceType?: string; ip?: string }) {
      return request(path, {
        method,
        headers: {
          ...(init.authorization && { authorization: init.authorization }),
          ...(init.contentType && { "content-type": init.contentType }),
          ...(init.deviceType && { "device-type": init.deviceType }),
          // Vaultwarden reads the person's address from X-Real-IP (IP_HEADER), for its limits and its event log.
          ...(init.ip && { "x-real-ip": init.ip }),
        },
        ...(init.body !== undefined && { body: init.body }),
      });
    },

    async ping(): Promise<void> {
      await token("service");
    },
  };
}

export type Vaultwarden = ReturnType<typeof createVaultwarden>;
