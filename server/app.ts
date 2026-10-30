import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { AuthError, atLeast, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import { PasswordsError, type Passwords, type ProblemCode } from "./passwords.ts";
import type { ProductLink } from "./products.ts";
import type { Vaultwarden } from "./vaultwarden.ts";

export interface AppOptions {
  db: DatabaseSync;
  passwords: Passwords;
  vaultwarden: Vaultwarden;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** For tests and local scripts: tokens that act as a signed-in person with a role, by token. main.ts never sets it. */
  personTokens?: Record<string, { email: string; role: Role }>;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(passwords: Passwords, version: string) {
  return renderMetrics(version, { ...passwords.gauges(), fileError: !!passwords.summary().file?.error });
}

/** Serves only /metrics, for a port that is not exposed with the rest (PASSWORDS_METRICS_PORT). */
export function createMetricsHandler(passwords: Passwords, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(passwords, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".wasm": "application/wasm",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);
/** The range API the browser looks leaked passwords up at, with the first five characters of a hash only. */
export const PWNED = "https://api.pwnedpasswords.com";

/**
 * The pages decrypt vaults, so nothing from another origin may run in them: scripts only from this server, and
 * WebAssembly for Argon2id. The browser talks to this server, to Identity for preferences and, when leak checks are on,
 * to the range API.
 */
function securityHeaders(leakCheck: boolean) {
  return {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
    "content-security-policy": `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}${leakCheck ? ` ${PWNED}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  };
}

/** Largest body the browser sends on to Vaultwarden. */
const PASS_LIMIT = 256 * 1024;

let SECURITY_HEADERS: Record<string, string> = securityHeaders(false);

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown) => send(res, status, JSON.stringify(data), "application/json");

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  "vault-server-unavailable": "Vault server unavailable",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > limit) throw new PasswordsError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024)} KiB.`);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<unknown> {
  const raw = await readBody(req, limit);
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new PasswordsError(400, "invalid-json", "The body must be JSON.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The address the request came from, as the TLS proxy says, so Vaultwarden limits and logs the person, not us. */
function clientIp(req: IncomingMessage): string {
  const real = req.headers["x-real-ip"];
  if (typeof real === "string" && real) return real;
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded) return forwarded.split(",")[0]!.trim();
  return req.socket.remoteAddress ?? "";
}

/** Token request fields the browser may send; anything else is dropped. */
const TOKEN_FIELDS = [
  "grant_type",
  "password",
  "refresh_token",
  "device_type",
  "device_identifier",
  "device_name",
  "two_factor_token",
  "two_factor_provider",
  "two_factor_remember",
];

/**
 * The role a route needs (ADR 0003). "none" for the version; "self" for a person's own vault, which needs a signed-in
 * person (not an API token) and acts only as that person; "self-admin" also needs the admin role.
 */
type Access = "none" | "self" | "self-admin" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  /** The signed-in person's address, or null for an API token. */
  email: string | null;
  role: Role;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

export function createApp({
  db,
  passwords,
  vaultwarden,
  version,
  auth,
  adminToken,
  personTokens = {},
  webDir,
  docsDir,
  openapi,
  serveMetrics = true,
  products = [],
}: AppOptions) {
  SECURITY_HEADERS = securityHeaders(passwords.summary().leakCheck);
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const org = encodeURIComponent(vaultwarden.organizationId);

  /** Sends a browser's request on to Vaultwarden and its answer back as it is. */
  async function pass(ctx: Ctx, method: string, path: string, body?: Buffer | string, contentType = "application/json") {
    const authorization = ctx.req.headers["x-vault-authorization"];
    const r = await passwords.server(() =>
      vaultwarden.pass(method, path, {
        authorization: typeof authorization === "string" ? authorization : undefined,
        body,
        contentType: body === undefined ? undefined : contentType,
        deviceType: typeof ctx.req.headers["device-type"] === "string" ? ctx.req.headers["device-type"] : undefined,
        ip: clientIp(ctx.req),
      }),
    );
    const text = await r.text();
    // Vaultwarden answers JSON; an empty answer is sent as an empty object so the page reads every answer the same way.
    send(ctx.res, r.status === 204 ? 200 : r.status, text || "{}", "application/json", { "cache-control": "no-store" });
  }
  const jsonBody = async (req: IncomingMessage) => JSON.stringify(await readJson(req, PASS_LIMIT));

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "passwords", version }) },
    { method: "GET", path: "/api/v1/products", auth: "user", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => passwords.summary() },

    // The vaults, as the file sets them. There is no route that adds, changes or removes one, an access or a policy.
    {
      method: "GET",
      path: "/api/v1/vaults",
      auth: "user",
      handle: ({ email, role }) => ({ vaults: passwords.vaults(atLeast(role, "viewer") ? null : email), file: passwords.summary().file }),
    },
    { method: "GET", path: "/api/v1/confirmations", auth: "viewer", handle: () => ({ members: passwords.confirmations() }) },

    // Bringing Vaultwarden in step with the file and Identity, which also happens after every change and every five minutes.
    {
      method: "GET",
      path: "/api/v1/sync",
      auth: "viewer",
      handle: () => ({
        last: passwords.lastSync(),
        runs: db
          .prepare("SELECT at, ok, added, removed, vaults, policies, error FROM sync_runs ORDER BY id DESC LIMIT 20")
          .all()
          .map((r) => ({ ...r, ok: r.ok === 1 })),
      }),
    },
    { method: "POST", path: "/api/v1/sync", auth: "admin", handle: () => passwords.syncNow() },

    // Who opened, copied or changed which shared item; the names are decrypted in the browser.
    {
      method: "GET",
      path: "/api/v1/activity",
      auth: "viewer",
      handle: ({ url }) => ({
        events: passwords.activity({
          vault: url.searchParams.get("vault") ?? undefined,
          limit: Number(url.searchParams.get("limit") ?? 200) || 200,
          before: url.searchParams.get("before") ?? undefined,
        }),
      }),
    },

    // People who leave, and what they could see.
    { method: "GET", path: "/api/v1/leavers", auth: "viewer", handle: () => ({ leavers: passwords.leavers() }) },
    {
      method: "POST",
      path: "/api/v1/leavers",
      auth: "editor",
      handle: async ({ req, res, email }) => json(res, 201, passwords.planLeaver(await readJson(req), email ?? "api-token")),
    },
    {
      method: "DELETE",
      path: "/api/v1/leavers/:id",
      auth: "editor",
      handle: ({ res, params, email }) => (passwords.cancelLeaver(Number(params[0]), email ?? "api-token"), noContent(res)),
    },
    {
      method: "PUT",
      path: "/api/v1/leavers/:id/items/:item",
      auth: "editor",
      handle: async ({ req, params, email }) => passwords.markChanged(Number(params[0]), params[1]!, await readJson(req), email ?? "api-token"),
    },

    // A person's own vault, through Vaultwarden as it is: their browser derives every key and decrypts every item.
    { method: "GET", path: "/api/v1/vault/settings", auth: "self", handle: ({ email }) => passwords.vaultSettings(email!) },
    {
      method: "POST",
      path: "/api/v1/vault/prelogin",
      auth: "self",
      // Only the signed-in person's own address is ever asked about.
      handle: (ctx) => pass(ctx, "POST", "/identity/accounts/prelogin", JSON.stringify({ email: ctx.email })),
    },
    {
      method: "POST",
      path: "/api/v1/vault/token",
      auth: "self",
      handle: async (ctx) => {
        const given = new URLSearchParams((await readBody(ctx.req, 16 * 1024)).toString("utf8"));
        const grant = given.get("grant_type");
        if (grant !== "password" && grant !== "refresh_token") throw new PasswordsError(422, "invalid-body", "grant_type is password or refresh_token.");
        const form = new URLSearchParams();
        for (const k of TOKEN_FIELDS) if (given.has(k)) form.set(k, given.get(k)!);
        // The browser unlocks the signed-in person's vault and no one else's.
        form.set("client_id", "web");
        if (grant === "password") (form.set("username", ctx.email!), form.set("scope", "api offline_access"));
        return pass(ctx, "POST", "/identity/connect/token", form.toString(), "application/x-www-form-urlencoded");
      },
    },
    { method: "GET", path: "/api/v1/vault/sync", auth: "self", handle: (ctx) => pass(ctx, "GET", "/api/sync?excludeDomains=true") },
    {
      method: "GET",
      path: "/api/v1/vault/organization/items",
      auth: "self",
      handle: (ctx) => pass(ctx, "GET", `/api/ciphers/organization-details?organizationId=${org}`),
    },
    { method: "POST", path: "/api/v1/vault/events", auth: "self", handle: async (ctx) => pass(ctx, "POST", "/events/collect", await jsonBody(ctx.req)) },
    {
      method: "POST",
      path: "/api/v1/vault/organization/public-keys",
      auth: "self-admin",
      handle: async (ctx) => pass(ctx, "POST", `/api/organizations/${org}/users/public-keys`, await jsonBody(ctx.req)),
    },
    {
      method: "POST",
      path: "/api/v1/vault/organization/confirm",
      auth: "self-admin",
      handle: async (ctx) => {
        const r = await pass(ctx, "POST", `/api/organizations/${org}/users/confirm`, await jsonBody(ctx.req));
        void passwords.syncNow();
        return r;
      },
    },
    {
      method: "POST",
      path: "/api/v1/vault/organization/collections",
      auth: "self-admin",
      handle: async (ctx) => {
        const r = await pass(ctx, "POST", `/api/organizations/${org}/collections`, await jsonBody(ctx.req));
        // The new collection gets its groups from the file at once.
        void passwords.syncNow();
        return r;
      },
    },
    {
      method: "PUT",
      path: "/api/v1/vault/organization/collections/:id",
      auth: "self-admin",
      handle: async (ctx) => {
        const r = await pass(ctx, "PUT", `/api/organizations/${org}/collections/${encodeURIComponent(ctx.params[0]!)}`, await jsonBody(ctx.req));
        // Vaultwarden replaces the groups with the ones sent; the sync puts the file's back at once.
        void passwords.syncNow();
        return r;
      },
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[a-z]+/g, "([^/]+)")}$`) }));

  function authorize(req: IncomingMessage, access: Access): { email: string | null; role: Role } {
    if (access === "none") return { email: null, role: "viewer" };
    const self = access === "self" || access === "self-admin";
    if (!self && tokenMatches(req.headers.authorization, adminToken)) return { email: null, role: "admin" };
    for (const [token, who] of Object.entries(personTokens))
      if (tokenMatches(req.headers.authorization, token)) {
        const need = access === "self" ? "user" : access === "self-admin" ? "admin" : access;
        if (!atLeast(who.role, need)) throw new AuthError(403, "forbidden", `This needs the ${need} role.`);
        return who;
      }
    const p = auth.authorize(req, access === "self" ? "user" : access === "self-admin" ? "admin" : access);
    if (p.kind !== "session") {
      if (self) throw new AuthError(403, "forbidden", "Only a signed-in person can open their vault, not an API token.");
      return { email: null, role: p.role };
    }
    return { email: p.user.email.toLowerCase(), role: p.role };
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready while the database answers; Vaultwarden being away shows in the summary, not here, so the sign-in and
      // the admin pages stay up to say so.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      if (serveMetrics) send(res, 200, metricsText(passwords, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const who = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({ req, res, url, params, ...who });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof PasswordsError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url?.split("?")[0] });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      // The path only: query strings and bodies, which may hold tokens, are never logged.
      log("info", "request", { method: req.method, path: (req.url ?? "/").split("?")[0], status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}
