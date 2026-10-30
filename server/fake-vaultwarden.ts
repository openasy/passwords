// A Vaultwarden in memory for tests, answering the calls Passwords makes the way Vaultwarden 1.37.4 does (same paths,
// shapes and rules as src/api/core/public.rs, organizations.rs and events.rs). Given to createVaultwarden() as its
// fetch, so the real client code runs against it. Item contents are opaque strings here: the server never reads them.
import type { CollectionAccess, VwEvent } from "./vaultwarden.ts";

export const ORG = "8b2f0c9e-org0-4d2a-9c1e-000000000001";
export const ORG_SECRET = "org-api-key-secret";
export const SERVICE_CLIENT = "user.5e2c-service";
export const SERVICE_SECRET = "service-api-key-secret";
/** The master password hash a test person signs in with (the browser derives it; here it is just a value). */
export const PASSWORD_HASH = "bWFzdGVyLXBhc3N3b3JkLWhhc2g=";

interface FakeMember {
  id: string;
  userId: string;
  email: string;
  name: string | null;
  externalId: string | null;
  status: number;
  type: number;
  groups: string[];
  collections: CollectionAccess[];
  key: string | null;
}

interface FakeItem {
  id: string;
  type: number;
  collectionIds: string[];
  revisionDate: string;
  deletedDate: string | null;
  login: { password: string; passwordRevisionDate: string | null } | null;
}

export function fakeVaultwarden() {
  let next = 0;
  const id = (p: string) => `${p}-${(next++).toString(36)}`;
  /** Accounts by email: whether they set a master password yet, and their public key. */
  const users = new Map<string, { id: string; name: string; hasPassword: boolean; publicKey: string | null }>();
  const members = new Map<string, FakeMember>();
  const groups = new Map<string, { id: string; name: string; externalId: string | null; collections: CollectionAccess[] }>();
  const collections = new Map<string, { id: string; name: string; externalId: string | null }>();
  const policies = new Map<number, { enabled: boolean; data: Record<string, unknown> | null }>();
  const events: VwEvent[] = [];
  const items: FakeItem[] = [];
  /** Every call, with the token it came with and its body. */
  const calls: Array<{ method: string; path: string; token: string | null; body: unknown; headers: Record<string, string> }> = [];
  const state = { down: false, features: { groups: true, events: true } };

  function addUser(email: string, name: string, hasPassword = true) {
    const u = { id: id("user"), name, hasPassword, publicKey: hasPassword ? `pk-${email}` : null };
    users.set(email.toLowerCase(), u);
    return u;
  }
  function addMember(email: string, { type = 2, status = 2, externalId = null as string | null } = {}) {
    const u = users.get(email.toLowerCase()) ?? addUser(email, email);
    const m: FakeMember = {
      id: id("member"),
      userId: u.id,
      email,
      name: u.name,
      externalId,
      status,
      type,
      groups: [],
      collections: [],
      key: status === 2 ? "4.org-key" : null,
    };
    members.set(m.id, m);
    return m;
  }
  const memberByEmail = (email: string) => [...members.values()].find((m) => m.email.toLowerCase() === email.toLowerCase());

  // The service account is an admin of the organization, as the README sets it up.
  addUser("passwords-service@example.com", "Passwords service");
  addMember("passwords-service@example.com", { type: 1 });

  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const error = (message: string, status = 400) => json({ message, errorModel: { message, object: "error" }, object: "error" }, status);

  /** Who a bearer token is: the organization key, the service account or a person. */
  function who(token: string | null): { kind: "org" } | { kind: "user"; email: string } | null {
    if (token === "org-token") return { kind: "org" };
    if (token === "service-token") return { kind: "user", email: "passwords-service@example.com" };
    if (token?.startsWith("user-")) return { kind: "user", email: token.slice(5) };
    return null;
  }
  /** AdminHeaders: a confirmed owner or admin of the organization. */
  const isAdmin = (email: string) => {
    const m = memberByEmail(email);
    return !!m && m.status === 2 && m.type <= 1;
  };

  function importDirectory(body: {
    groups: Array<{ name: string; externalId: string; memberExternalIds: string[] }>;
    members: Array<{ email: string; externalId: string; deleted: boolean }>;
    overwriteExisting: boolean;
  }) {
    for (const d of body.members) {
      const m = memberByEmail(d.email);
      if (d.deleted) {
        if (m && m.type !== 0) ((m.status = -1), (m.externalId = d.externalId));
      } else if (m) {
        if (m.status === -1 && m.type !== 0) m.status = 0;
        m.externalId = d.externalId;
      } else {
        const u = users.get(d.email.toLowerCase()) ?? addUser(d.email, d.email, false);
        // No SMTP: someone who already has an account is accepted at once, the others when they set a master password.
        addMember(d.email, { status: u.hasPassword ? 1 : 0, externalId: d.externalId });
      }
    }
    if (state.features.groups)
      for (const g of body.groups) {
        let group = [...groups.values()].find((x) => x.externalId === g.externalId);
        if (!group) ((group = { id: id("group"), name: g.name, externalId: g.externalId, collections: [] }), groups.set(group.id, group));
        for (const m of members.values()) m.groups = m.groups.filter((x) => x !== group.id);
        for (const ext of g.memberExternalIds) {
          const m = [...members.values()].find((x) => x.externalId === ext);
          if (m) m.groups.push(group.id);
        }
      }
    if (body.overwriteExisting) {
      const listed = new Set(body.members.map((m) => m.externalId));
      for (const m of members.values()) if (m.externalId && !listed.has(m.externalId) && m.type !== 0) members.delete(m.id);
    }
  }

  const memberJson = (m: FakeMember) => ({
    id: m.id,
    userId: m.userId,
    name: m.status >= 1 ? m.name : null,
    email: m.email,
    externalId: m.externalId,
    status: m.status,
    type: m.type,
    groups: m.groups,
    collections: m.collections,
    object: "organizationUserUserDetails",
  });

  /** Collections a person sees: directly, through a group, or all of them as an owner or admin. */
  function visible(email: string): Set<string> {
    const m = memberByEmail(email);
    if (!m || m.status !== 2) return new Set();
    if (m.type <= 1) return new Set(collections.keys());
    const ids = new Set(m.collections.map((c) => c.id));
    for (const g of groups.values()) if (m.groups.includes(g.id)) for (const c of g.collections) ids.add(c.id);
    return ids;
  }

  function route(method: string, url: URL, token: string | null, body: unknown, form: URLSearchParams | null): Response {
    const path = url.pathname;
    const prefix = `/api/organizations/${ORG}`;

    if (path === "/identity/connect/token" && method === "POST" && form) {
      const grant = form.get("grant_type");
      if (grant === "client_credentials") {
        if (form.get("scope") === "api.organization" && form.get("client_id") === `organization.${ORG}` && form.get("client_secret") === ORG_SECRET)
          return json({ access_token: "org-token", expires_in: 3600, token_type: "Bearer", scope: "api.organization" });
        if (
          form.get("scope") === "api" &&
          form.get("client_id") === SERVICE_CLIENT &&
          form.get("client_secret") === SERVICE_SECRET &&
          form.get("device_identifier")
        )
          return json({ access_token: "service-token", expires_in: 7200, token_type: "Bearer", scope: "api" });
        return json({ error: "invalid_client", error_description: "Incorrect client_secret" }, 400);
      }
      if (grant === "password") {
        const email = form.get("username") ?? "";
        const u = users.get(email.toLowerCase());
        if (!u?.hasPassword || form.get("password") !== PASSWORD_HASH || form.get("client_id") !== "web" || form.get("scope") !== "api offline_access")
          return error("Username or password is incorrect. Try again");
        return json({
          access_token: `user-${email.toLowerCase()}`,
          refresh_token: `refresh-${email.toLowerCase()}`,
          expires_in: 7200,
          token_type: "Bearer",
          Key: "2.encrypted-user-key",
          PrivateKey: "2.encrypted-private-key",
          Kdf: 0,
          KdfIterations: 600000,
        });
      }
      if (grant === "refresh_token" && form.get("refresh_token")?.startsWith("refresh-"))
        return json({ access_token: `user-${form.get("refresh_token")!.slice(8)}`, expires_in: 7200, token_type: "Bearer" });
      return error("Invalid refresh token");
    }
    if (path === "/identity/accounts/prelogin" && method === "POST") {
      return json({ kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null, salt: null });
    }

    const caller = who(token);
    if (!caller) return error("Invalid claim", 401);

    if (path === "/api/public/organization/import" && method === "POST") {
      if (caller.kind !== "org") return error("Invalid claim", 401);
      importDirectory(body as Parameters<typeof importDirectory>[0]);
      return new Response(null, { status: 200 });
    }
    if (caller.kind !== "user") return error("Invalid claim", 401);
    const me = caller.email;

    if (path === "/api/accounts/profile" && method === "GET") {
      const m = memberByEmail(me);
      return json({
        email: me,
        organizations: m ? [{ id: ORG, useGroups: state.features.groups, useEvents: state.features.events, type: m.type, status: m.status, key: m.key }] : [],
      });
    }
    if (path === "/api/sync" && method === "GET") {
      const m = memberByEmail(me);
      const seen = visible(me);
      return json({
        profile: {
          email: me,
          key: "2.encrypted-user-key",
          privateKey: "2.encrypted-private-key",
          organizations: m?.status === 2 ? [{ id: ORG, key: m.key, type: m.type }] : [],
        },
        ciphers: items.filter((i) => i.collectionIds.some((c) => seen.has(c))).map((i) => ({ ...i, organizationId: ORG, name: `2.name-${i.id}` })),
        collections: [...collections.values()].filter((c) => seen.has(c.id)).map((c) => ({ ...c, organizationId: ORG, readOnly: false })),
      });
    }
    if (path === "/events/collect" && method === "POST") {
      const m = memberByEmail(me);
      for (const e of body as Array<{ type: number; cipherId?: string; date: string }>)
        events.push({
          type: e.type,
          userId: null,
          cipherId: e.cipherId ?? null,
          collectionId: null,
          groupId: null,
          organizationUserId: null,
          actingUserId: m?.userId ?? null,
          date: e.date,
          deviceType: Number(calls.at(-1)?.headers["device-type"] ?? 14),
          ipAddress: calls.at(-1)?.headers["x-real-ip"] ?? null,
        });
      return new Response(null, { status: 200 });
    }
    if (path === "/api/ciphers/organization-details" && method === "GET") {
      if (url.searchParams.get("organizationId") !== ORG || !isAdmin(me)) return error("Resource not found.", 404);
      return json({ data: items.map((i) => ({ ...i, name: `2.name-${i.id}` })), object: "list", continuationToken: null });
    }

    if (!path.startsWith(prefix)) return error("Not found", 404);
    if (!isAdmin(me)) return error("You need to be Admin or Owner to call this endpoint", 401);
    const rest = path.slice(prefix.length);

    if (rest === "/users" && method === "GET") return json({ data: [...members.values()].map(memberJson), object: "list" });
    const del = /^\/users\/([^/]+)$/.exec(rest);
    if (del && method === "DELETE") {
      const m = members.get(del[1]!);
      if (!m) return error("User to delete isn't member of the organization");
      if (m.type !== 2 && memberByEmail(me)!.type !== 0) return error("Only Owners can delete Admins or Owners");
      members.delete(m.id);
      return new Response(null, { status: 200 });
    }
    if (rest === "/groups/details" && method === "GET") return json({ data: [...groups.values()], object: "list" });
    if (rest === "/collections" && method === "GET") return json({ data: [...collections.values()], object: "list" });
    if (rest === "/collections" && method === "POST") {
      const b = body as { name: string; externalId?: string | null; groups: CollectionAccess[] };
      const c = { id: id("collection"), name: b.name, externalId: b.externalId || null };
      collections.set(c.id, c);
      for (const g of b.groups ?? []) groups.get(g.id)?.collections.push({ ...g, id: c.id });
      return json({ ...c, object: "collectionDetails" });
    }
    const put = /^\/collections\/([^/]+)$/.exec(rest);
    if (put && method === "PUT") {
      const c = collections.get(put[1]!);
      if (!c) return error("Collection not found");
      const b = body as { name: string; externalId?: string | null; groups: CollectionAccess[] };
      c.name = b.name;
      c.externalId = b.externalId || null;
      for (const g of groups.values()) g.collections = g.collections.filter((x) => x.id !== c.id);
      for (const g of b.groups ?? []) groups.get(g.id)?.collections.push({ ...g, id: c.id });
      return json({ ...c, object: "collectionDetails" });
    }
    if (rest === "/collections/bulk-access" && method === "POST") {
      const b = body as { collectionIds: string[]; groups: CollectionAccess[]; users: CollectionAccess[] };
      for (const g of b.groups) if (!groups.has(g.id)) return error("Invalid group");
      for (const cid of b.collectionIds) {
        if (!collections.has(cid)) return error("Collection not found");
        for (const g of groups.values()) g.collections = g.collections.filter((x) => x.id !== cid);
        for (const g of b.groups) groups.get(g.id)!.collections.push({ ...g, id: cid });
        for (const m of members.values()) m.collections = m.collections.filter((x) => x.id !== cid);
        for (const u of b.users) members.get(u.id)?.collections.push({ ...u, id: cid });
      }
      return new Response(null, { status: 200 });
    }
    if (rest === "/policies" && method === "GET") return json({ data: [...policies].map(([type, p]) => ({ type, ...p, object: "policy" })), object: "list" });
    const pol = /^\/policies\/(\d+)$/.exec(rest);
    if (pol && method === "PUT") {
      const b = body as { policy: { enabled: boolean; data: Record<string, unknown> | null } };
      policies.set(Number(pol[1]), { enabled: b.policy.enabled, data: b.policy.data });
      return json({ type: Number(pol[1]), ...b.policy, object: "policy" });
    }
    if (rest === "/events" && method === "GET") {
      const start = url.searchParams.get("start")!;
      const end = url.searchParams.get("end")!;
      // Newest first, 30 at a time, both ends included, the last date as the next page's end.
      const page = events
        .filter((e) => e.date >= start && e.date <= end)
        .sort((a, b) => b.date.localeCompare(a.date))
        .slice(0, 30);
      return json({ data: page, object: "list", continuationToken: page.length === 30 ? page.at(-1)!.date : null });
    }
    if (rest === "/users/public-keys" && method === "POST") {
      const ids = (body as { ids: string[] }).ids;
      return json({
        data: ids.flatMap((mid) => {
          const m = members.get(mid);
          const u = m && users.get(m.email.toLowerCase());
          return u ? [{ id: mid, userId: u.id, key: u.publicKey, object: "organizationUserPublicKeyResponseModel" }] : [];
        }),
        object: "list",
      });
    }
    if (rest === "/users/confirm" && method === "POST") {
      const keys = (body as { keys: Array<{ id: string; key: string }> }).keys;
      return json({
        data: keys.map((k) => {
          const m = members.get(k.id);
          if (!m || m.status !== 1) return { id: k.id, error: "User in invalid state", object: "OrganizationBulkConfirmResponseModel" };
          ((m.status = 2), (m.key = k.key));
          return { id: k.id, error: "", object: "OrganizationBulkConfirmResponseModel" };
        }),
        object: "list",
      });
    }
    return error("Not found", 404);
  }

  const fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    if (state.down) throw new TypeError("fetch failed");
    const url = new URL(String(input));
    const headers = Object.fromEntries(new Headers(init.headers).entries());
    const auth = headers.authorization;
    const token = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
    const text = init.body === undefined || init.body === null ? "" : String(init.body);
    const form = headers["content-type"] === "application/x-www-form-urlencoded" ? new URLSearchParams(text) : null;
    const body = !form && text ? JSON.parse(text) : undefined;
    calls.push({ method: init.method ?? "GET", path: url.pathname, token, body: form ? Object.fromEntries(form) : body, headers });
    return route(init.method ?? "GET", url, token, body, form);
  }) as typeof globalThis.fetch;

  return { fetch, users, members, groups, collections, policies, events, items, calls, state, addUser, addMember, memberByEmail };
}

export type FakeVaultwarden = ReturnType<typeof fakeVaultwarden>;
