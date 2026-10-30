// Starts the app on a random port for tests, against a Vaultwarden and an Identity in memory. The people are the shared
// demo world: today is Wednesday 4 November 2026, Emily Clark uses Passwords, Mark Wilson leaves on 30 November, and
// Ali Yılmaz is the site's example of someone whose contract ended.
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createAuth, type Role } from "@openasy/auth";
import { createApp, type AppOptions } from "./app.ts";
import { parseConfig } from "./config.ts";
import { openDb } from "./db.ts";
import { fakeVaultwarden, ORG, ORG_SECRET, SERVICE_CLIENT, SERVICE_SECRET, type FakeVaultwarden } from "./fake-vaultwarden.ts";
import { createIdentity, type Person } from "./identity.ts";
import { createPasswords } from "./passwords.ts";
import { createVaultwarden } from "./vaultwarden.ts";

export const ADMIN_TOKEN = "test-admin-token";
/** Tokens that act as a signed-in person, as personTokens. */
export const EMILY = "test-emily-token";
export const SELIN = "test-selin-token";
export const STRANGER = "test-stranger-token";
export const IDENTITY_TOKEN = "identity-viewer-token";
export const NOW = Date.parse("2026-11-04T09:00:00Z");

/** The vaults file the tests start with. */
export const VAULTS = `
vaults:
  - id: finance
    name: Finance
    access: { finance-leads: manage, finance: edit }
  - id: sales
    name: Sales
    access: { sales: edit }
  - id: office
    name: Office
    access: { everyone: read }
policies:
  twoStepLogin: true
  masterPassword: { minLength: 14, minComplexity: 3 }
`;

export const PEOPLE: Person[] = [
  { id: "p-emily", email: "emily.clark@example.com", name: "Emily Clark", status: "active", groups: ["finance", "everyone"] },
  { id: "p-selin", email: "selin.demir@example.com", name: "Selin Demir", status: "active", groups: ["finance-leads", "it-admins", "everyone"] },
  { id: "p-mark", email: "mark.wilson@example.com", name: "Mark Wilson", status: "active", groups: ["sales", "everyone"] },
  { id: "p-ali", email: "ali.yilmaz@example.com", name: "Ali Yılmaz", status: "active", groups: ["finance", "everyone"] },
  { id: "p-jonas", email: "jonas.berg@example.com", name: "Jonas Berg", status: "active", groups: ["it-admins"] },
];

/** Identity's directory in memory: GET /api/v1/people with the viewer token. */
export function fakeIdentity(people: Person[] = structuredClone(PEOPLE)) {
  const state = { down: false };
  const fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    if (state.down) throw new TypeError("fetch failed");
    if (new Headers(init.headers).get("authorization") !== `Bearer ${IDENTITY_TOKEN}`) return new Response("{}", { status: 401 });
    if (new URL(String(input)).pathname !== "/api/v1/people") return new Response("{}", { status: 404 });
    return new Response(JSON.stringify({ people: people.map((p) => ({ ...p, role: "user", secondFactor: true, providers: [] })) }), {
      headers: { "content-type": "application/json" },
    });
  }) as typeof globalThis.fetch;
  return { fetch, people, state };
}

/** Collections that already exist, with items in them, as an admin made them in the Bitwarden apps. */
export function seedVault(fake: FakeVaultwarden) {
  // Everyone has set up their account; Selin is an admin of the organization and Mark and Ali were confirmed earlier.
  for (const p of PEOPLE.filter((x) => x.id !== "p-jonas")) fake.addUser(p.email, p.name);
  fake.addMember("selin.demir@example.com", { type: 1 });
  fake.addMember("mark.wilson@example.com");
  fake.addMember("ali.yilmaz@example.com");
  const finance = { id: "col-finance", name: "2.encrypted-finance", externalId: "finance" };
  const office = { id: "col-office", name: "2.encrypted-office", externalId: "office" };
  const handmade = { id: "col-board", name: "2.encrypted-board", externalId: null };
  for (const c of [finance, office, handmade]) fake.collections.set(c.id, c);
  const item = (id: string, collectionIds: string[], passwordRevisionDate: string | null = "2026-03-14T10:00:00.000000Z") =>
    fake.items.push({
      id,
      type: 1,
      collectionIds,
      revisionDate: "2026-03-14T10:00:00.000000Z",
      deletedDate: null,
      login: { password: "2.secret", passwordRevisionDate },
    });
  item("item-bank", ["col-finance"]);
  item("item-tax", ["col-finance"]);
  item("item-payroll", ["col-finance"], null);
  item("item-wifi", ["col-office"]);
  item("item-alarm", ["col-office"]);
  item("item-board", ["col-board"]);
}

export function setup(people?: Person[]) {
  const fake = fakeVaultwarden();
  seedVault(fake);
  const directory = fakeIdentity(people);
  const vw = createVaultwarden({
    url: "http://vaultwarden",
    organizationId: ORG,
    orgSecret: ORG_SECRET,
    serviceClientId: SERVICE_CLIENT,
    serviceSecret: SERVICE_SECRET,
    fetch: fake.fetch,
    now: () => NOW,
  });
  const identity = createIdentity({ url: "http://identity", token: IDENTITY_TOKEN, fetch: directory.fetch });
  return { fake, directory, vw, identity };
}

export async function startApp(opts: Partial<AppOptions> & { version: string; vaults?: string; people?: Person[]; clock?: () => number }) {
  const db = openDb(":memory:");
  const { vaults = VAULTS, people, clock = () => NOW, ...rest } = opts;
  const { fake, directory, vw, identity } = setup(people);
  const passwords = createPasswords(db, vw, identity, { vaultwardenUrl: "https://vault.example.com", leakCheck: true, clock });
  await passwords.setConfig(parseConfig(vaults));
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "passwords", productName: "OpenAsy Passwords", origin: base, users: true });
  const personTokens: Record<string, { email: string; role: Role }> = {
    [EMILY]: { email: "emily.clark@example.com", role: "user" },
    [SELIN]: { email: "selin.demir@example.com", role: "admin" },
    [STRANGER]: { email: "stranger@example.net", role: "user" },
  };
  handler = createApp({ db, passwords, vaultwarden: vw, auth, adminToken: ADMIN_TOKEN, personTokens, ...rest });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, passwords, fake, directory, auth, base, admin: as(ADMIN_TOKEN), emily: as(EMILY), selin: as(SELIN), as, close };
}
