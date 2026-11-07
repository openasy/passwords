import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ORG, PASSWORD_HASH } from "./fake-vaultwarden.ts";
import { ADMIN_TOKEN, EMILY, SELIN, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "passwords-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1").replaceAll("{", "%7B").replaceAll("}", "%7D")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();
  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const admin = (init: RequestInit = {}) => ({
  ...init,
  headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json", ...init.headers },
});
const as = (token: string, init: RequestInit = {}) => ({
  ...init,
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers },
});
const vault = (token: string, person: string, init: RequestInit = {}) =>
  as(token, { ...init, headers: { "x-vault-authorization": `Bearer user-${person}`, ...init.headers } });
const form = (fields: Record<string, string>) => ({
  body: new URLSearchParams(fields).toString(),
  headers: { "content-type": "application/x-www-form-urlencoded" },
});

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // Passwords' own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
    await call("GET", "/api/v1/summary", as(EMILY));
  });

  it("vaults and syncs", async () => {
    await call("GET", "/api/v1/vaults", admin());
    await call("GET", "/api/v1/vaults", as(EMILY));
    await call("GET", "/api/v1/vaults", {});
    await call("GET", "/api/v1/confirmations", admin());
    await call("POST", "/api/v1/sync", admin());
    await call("POST", "/api/v1/sync", as(EMILY));
    await call("GET", "/api/v1/sync", admin());
  });

  it("activity and leavers", async () => {
    await call("GET", "/api/v1/activity", admin());
    await call("GET", "/api/v1/activity", admin(), "/api/v1/activity?vault=finance&limit=10");
    await call("GET", "/api/v1/activity", admin(), "/api/v1/activity?vault=nope");
    const { body } = await call("POST", "/api/v1/leavers", admin({ body: JSON.stringify({ email: "mark.wilson@example.com", leavesOn: "2026-11-30" }) }));
    const id = (body as { id: number; items: Array<{ itemId: string }> }).id;
    const item = (body as { items: Array<{ itemId: string }> }).items[0]!.itemId;
    await call("POST", "/api/v1/leavers", admin({ body: JSON.stringify({ email: "mark.wilson@example.com", leavesOn: "2026-12-01" }) }));
    await call("POST", "/api/v1/leavers", admin({ body: JSON.stringify({ email: "mark.wilson@example.com", leavesOn: "soon" }) }));
    await call("POST", "/api/v1/leavers", admin({ body: "{" }));
    await call("GET", "/api/v1/leavers", admin());
    await call("PUT", "/api/v1/leavers/{id}/items/{item}", admin({ body: JSON.stringify({ changed: true }) }), `/api/v1/leavers/${id}/items/${item}`);
    await call("PUT", "/api/v1/leavers/{id}/items/{item}", admin({ body: JSON.stringify({ changed: "yes" }) }), `/api/v1/leavers/${id}/items/${item}`);
    await call("PUT", "/api/v1/leavers/{id}/items/{item}", admin({ body: JSON.stringify({ changed: true }) }), `/api/v1/leavers/${id}/items/nope`);
    await call("DELETE", "/api/v1/leavers/{id}", admin(), `/api/v1/leavers/${id}`);
    await call("DELETE", "/api/v1/leavers/{id}", admin(), `/api/v1/leavers/${id}`);
    app.directory.people.find((p) => p.id === "p-ali")!.status = "disabled";
    await app.passwords.syncNow();
    const ali = app.passwords.leavers().find((l) => l.email === "ali.yilmaz@example.com")!;
    await call("DELETE", "/api/v1/leavers/{id}", admin(), `/api/v1/leavers/${ali.id}`);
  });

  it("the vault pass-through", async () => {
    await call("GET", "/api/v1/vault/settings", as(EMILY));
    await call("GET", "/api/v1/vault/settings", {});
    await call("GET", "/api/v1/vault/settings", admin());
    await call("POST", "/api/v1/vault/prelogin", as(EMILY, { body: "{}" }));
    await call("POST", "/api/v1/vault/prelogin", admin({ body: "{}" }));
    await call(
      "POST",
      "/api/v1/vault/token",
      as(EMILY, form({ grant_type: "password", password: PASSWORD_HASH, device_identifier: "d", device_name: "n", device_type: "9" })),
    );
    await call("POST", "/api/v1/vault/token", as(EMILY, form({ grant_type: "password", password: "wrong" })));
    await call("POST", "/api/v1/vault/token", as(EMILY, form({ grant_type: "client_credentials" })));
    await call("POST", "/api/v1/vault/token", as(EMILY, { ...form({ grant_type: "password" }), body: "x".repeat(17 * 1024) }));
    app.fake.memberByEmail("emily.clark@example.com")!.status = 2;
    await call("GET", "/api/v1/vault/sync", vault(EMILY, "emily.clark@example.com"));
    await call("GET", "/api/v1/vault/sync", as(EMILY));
    await call(
      "POST",
      "/api/v1/vault/events",
      vault(EMILY, "emily.clark@example.com", { body: JSON.stringify([{ type: 1107, cipherId: "item-bank", date: "2026-11-04T09:00:00Z" }]) }),
    );
    await call("POST", "/api/v1/vault/events", vault(EMILY, "emily.clark@example.com", { body: "x".repeat(300 * 1024) }));
    await call("GET", "/api/v1/vault/organization/items", vault(SELIN, "selin.demir@example.com"));
    await call("GET", "/api/v1/vault/organization/items", vault(EMILY, "emily.clark@example.com"));
    const member = app.fake.memberByEmail("mark.wilson@example.com")!.id;
    await call("POST", "/api/v1/vault/organization/public-keys", vault(SELIN, "selin.demir@example.com", { body: JSON.stringify({ ids: [member] }) }));
    await call("POST", "/api/v1/vault/organization/public-keys", vault(EMILY, "emily.clark@example.com", { body: JSON.stringify({ ids: [member] }) }));
    await call("POST", "/api/v1/vault/organization/public-keys", vault(SELIN, "selin.demir@example.com", { body: "x".repeat(300 * 1024) }));
    await call(
      "POST",
      "/api/v1/vault/organization/confirm",
      vault(SELIN, "selin.demir@example.com", { body: JSON.stringify({ keys: [{ id: member, key: "4.x" }] }) }),
    );
    await call("POST", "/api/v1/vault/organization/confirm", vault(SELIN, "selin.demir@example.com", { body: "x".repeat(300 * 1024) }));
    await call("POST", "/api/v1/vault/organization/confirm", as(EMILY, { body: "{}" }));
    const { body } = await call(
      "POST",
      "/api/v1/vault/organization/collections",
      vault(SELIN, "selin.demir@example.com", { body: JSON.stringify({ name: "2.s", externalId: "sales", groups: [], users: [] }) }),
    );
    await call("POST", "/api/v1/vault/organization/collections", as(EMILY, { body: "{}" }));
    await call("POST", "/api/v1/vault/organization/collections", vault(SELIN, "selin.demir@example.com", { body: "x".repeat(300 * 1024) }));
    const id = (body as { id: string }).id;
    await call(
      "PUT",
      "/api/v1/vault/organization/collections/{id}",
      vault(SELIN, "selin.demir@example.com", { body: JSON.stringify({ name: "2.t", externalId: "sales", groups: [], users: [] }) }),
      `/api/v1/vault/organization/collections/${id}`,
    );
    await call(
      "PUT",
      "/api/v1/vault/organization/collections/{id}",
      vault(SELIN, "selin.demir@example.com", { body: JSON.stringify({ name: "2.t", groups: [], users: [] }) }),
      "/api/v1/vault/organization/collections/nope",
    );
    await call("PUT", "/api/v1/vault/organization/collections/{id}", as(EMILY, { body: "{}" }), "/api/v1/vault/organization/collections/nope");
    await call(
      "PUT",
      "/api/v1/vault/organization/collections/{id}",
      vault(SELIN, "selin.demir@example.com", { body: "x".repeat(300 * 1024) }),
      `/api/v1/vault/organization/collections/${id}`,
    );
    // Items, encrypted in the browser: here opaque strings.
    const emily = app.fake.users.get("emily.clark@example.com")!.id;
    const cipher = (over: object = {}) => ({ type: 2, name: "2.n|n|n", secureNote: { type: 0 }, encryptedFor: emily, organizationId: null, ...over });
    const { body: added } = await call(
      "POST",
      "/api/v1/vault/items",
      vault(EMILY, "emily.clark@example.com", { body: JSON.stringify({ cipher: cipher(), collectionIds: [] }) }),
    );
    const itemId = (added as { id: string }).id;
    await call(
      "POST",
      "/api/v1/vault/items",
      vault(EMILY, "emily.clark@example.com", { body: JSON.stringify({ cipher: cipher({ encryptedFor: "someone" }) }) }),
    );
    await call(
      "POST",
      "/api/v1/vault/items",
      vault(EMILY, "emily.clark@example.com", { body: JSON.stringify({ cipher: cipher({ organizationId: "other" }) }) }),
    );
    await call("POST", "/api/v1/vault/items", as(EMILY, { body: JSON.stringify({ cipher: cipher() }) }));
    await call("POST", "/api/v1/vault/items", vault(EMILY, "emily.clark@example.com", { body: "x".repeat(300 * 1024) }));
    await call("PUT", "/api/v1/vault/items/{id}", vault(EMILY, "emily.clark@example.com", { body: JSON.stringify(cipher()) }), `/api/v1/vault/items/${itemId}`);
    await call("PUT", "/api/v1/vault/items/{id}", vault(EMILY, "emily.clark@example.com", { body: JSON.stringify(cipher()) }), "/api/v1/vault/items/nope");
    await call("PUT", "/api/v1/vault/items/{id}", vault(EMILY, "emily.clark@example.com", { body: "[]" }), `/api/v1/vault/items/${itemId}`);
    await call("PUT", "/api/v1/vault/items/{id}", vault(EMILY, "emily.clark@example.com", { body: "x".repeat(300 * 1024) }), `/api/v1/vault/items/${itemId}`);
    await call("PUT", "/api/v1/vault/items/{id}", as(EMILY, { body: "{}" }), `/api/v1/vault/items/${itemId}`);
    const share = (cols: string[]) => JSON.stringify({ cipher: cipher({ organizationId: ORG }), collectionIds: cols });
    await call(
      "PUT",
      "/api/v1/vault/items/{id}/share",
      vault(EMILY, "emily.clark@example.com", { body: share(["col-finance"]) }),
      `/api/v1/vault/items/${itemId}/share`,
    );
    await call("PUT", "/api/v1/vault/items/{id}/share", vault(EMILY, "emily.clark@example.com", { body: share([]) }), `/api/v1/vault/items/${itemId}/share`);
    await call(
      "PUT",
      "/api/v1/vault/items/{id}/share",
      vault(EMILY, "emily.clark@example.com", { body: share(["col-board"]) }),
      "/api/v1/vault/items/nope/share",
    );
    await call(
      "PUT",
      "/api/v1/vault/items/{id}/share",
      vault(EMILY, "emily.clark@example.com", { body: "x".repeat(300 * 1024) }),
      `/api/v1/vault/items/${itemId}/share`,
    );
    await call("PUT", "/api/v1/vault/items/{id}/share", as(EMILY, { body: "{}" }), `/api/v1/vault/items/${itemId}/share`);
    await call("DELETE", "/api/v1/vault/items/{id}", vault(EMILY, "emily.clark@example.com"), `/api/v1/vault/items/${itemId}`);
    await call("DELETE", "/api/v1/vault/items/{id}", vault(EMILY, "emily.clark@example.com"), "/api/v1/vault/items/nope");
    await call(
      "DELETE",
      "/api/v1/vault/items/{id}",
      vault(EMILY, "emily.clark@example.com", { headers: { "x-vault-authorization": "Bearer nope" } }),
      `/api/v1/vault/items/${itemId}`,
    );
    await call("DELETE", "/api/v1/vault/items/{id}", as(EMILY), `/api/v1/vault/items/${itemId}`);
    app.fake.state.down = true;
    try {
      await call("GET", "/api/v1/vault/sync", vault(EMILY, "emily.clark@example.com"));
      await call("POST", "/api/v1/vault/prelogin", as(EMILY, { body: "{}" }));
      await call("POST", "/api/v1/vault/token", as(EMILY, form({ grant_type: "refresh_token", refresh_token: "refresh-x" })));
      await call("GET", "/api/v1/vault/organization/items", vault(SELIN, "selin.demir@example.com"));
      await call("POST", "/api/v1/vault/events", vault(EMILY, "emily.clark@example.com", { body: "[]" }));
      await call("DELETE", "/api/v1/vault/items/{id}", vault(EMILY, "emily.clark@example.com"), "/api/v1/vault/items/any");
    } finally {
      app.fake.state.down = false;
    }
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
