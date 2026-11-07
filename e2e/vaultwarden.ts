// End to end against a running Vaultwarden (e2e/run.sh starts one): the first start of the README done through the
// API, then Passwords' server and its pages' own code (web/src/vault.ts, run here as the browser runs it) against it,
// and the official Bitwarden CLI on the same accounts, so what the pages write opens in a Bitwarden app and the other
// way round.
//
//   VW=http://localhost:18081 node e2e/vaultwarden.ts
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuth, type Role } from "@openasy/auth";
import { createApp } from "../server/app.ts";
import { parseConfig } from "../server/config.ts";
import { openDb } from "../server/db.ts";
import { createIdentity, type Person } from "../server/identity.ts";
import { createPasswords } from "../server/passwords.ts";
import { createVaultwarden } from "../server/vaultwarden.ts";
import type { VaultSettings } from "../web/src/api.ts";
import { b64, encrypt, encryptText, masterKey, masterPasswordHash, rsaEncrypt, stretch, symmetricKey, type Kdf } from "../web/src/crypto.ts";
import { emptyDraft } from "../web/src/items.ts";
import { unlock, type Session } from "../web/src/vault.ts";

const VW = (process.env.VW ?? "http://localhost:18081").replace(/\/$/, "");
const BW = process.env.BW_VERSION ?? "2026.7.0";
let failures = 0;
async function step(name: string, work: () => Promise<void>) {
  try {
    await work();
    console.log(`ok - ${name}`);
  } catch (err) {
    failures++;
    const cause = (err as { cause?: unknown }).cause;
    console.log(
      `not ok - ${name}\n  ${(err as Error).stack?.split("\n").slice(0, 4).join("\n  ")}${
        cause
          ? `\n  cause: ${String((cause as Error).stack ?? cause)
              .split("\n")
              .slice(0, 3)
              .join("\n  ")}`
          : ""
      }`,
    );
  }
}

// ---- Vaultwarden as the Bitwarden web vault talks to it, for the setup only ----

async function vw(path: string, init: RequestInit & { token?: string } = {}): Promise<any> {
  const { token, ...rest } = init;
  const res = await fetch(VW + path, {
    ...rest,
    headers: {
      ...(typeof rest.body === "string" && { "content-type": "application/json" }),
      ...(token && { authorization: `Bearer ${token}` }),
      ...(rest.headers as Record<string, string>),
    },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${init.method ?? "GET"} ${path}: ${res.status} ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : undefined;
}

interface Account {
  email: string;
  password: string;
  hash: string;
  token: string;
  id: string;
  publicKey: string;
}

const PBKDF2: Kdf = { kdf: 0, iterations: 600_000, memory: null, parallelism: null };
const ARGON2: Kdf = { kdf: 1, iterations: 3, memory: 64, parallelism: 4 };

/** Registers an account the way the web vault does: keys made on the device, only the hash and encrypted keys sent. */
async function register(email: string, name: string, password: string, kdf: Kdf): Promise<Account> {
  const verify = await vw("/identity/accounts/register/send-verification-email", {
    method: "POST",
    headers: { accept: "application/json" },
    body: JSON.stringify({ email, name, receiveMarketingEmails: false }),
  });
  const mk = await masterKey(password, email, kdf);
  const hash = await masterPasswordHash(mk, password);
  const userRaw = globalThis.crypto.getRandomValues(new Uint8Array(64));
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicKey = b64.encode(pair.publicKey.export({ type: "spki", format: "der" }));
  await vw("/identity/accounts/register/finish", {
    method: "POST",
    body: JSON.stringify({
      email,
      emailVerificationToken: verify,
      masterPasswordHash: hash,
      masterPasswordHint: null,
      key: await encrypt(userRaw, await stretch(mk)),
      kdf: kdf.kdf,
      kdfIterations: kdf.iterations,
      kdfMemory: kdf.memory,
      kdfParallelism: kdf.parallelism,
      userAsymmetricKeys: {
        publicKey,
        encryptedPrivateKey: await encrypt(new Uint8Array(pair.privateKey.export({ type: "pkcs8", format: "der" })), await symmetricKey(userRaw)),
      },
    }),
  });
  const token = await signIn(email, hash);
  const profile = await vw("/api/accounts/profile", { token });
  return { email, password, hash, token, id: profile.id, publicKey };
}

async function signIn(email: string, hash: string): Promise<string> {
  const form = new URLSearchParams({
    grant_type: "password",
    username: email,
    password: hash,
    scope: "api offline_access",
    client_id: "web",
    device_type: "9",
    device_identifier: randomUUID(),
    device_name: "e2e setup",
  });
  const res = await fetch(`${VW}/identity/connect/token`, { method: "POST", body: form, headers: { "content-type": "application/x-www-form-urlencoded" } });
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error(`sign-in of ${email} failed: ${JSON.stringify(body).slice(0, 300)}`);
  return body.access_token;
}

// ---- Identity's directory, as GET /api/v1/people answers ----

const people: Person[] = [
  { id: "p-selin", email: "selin.demir@example.com", name: "Selin Demir", status: "active", groups: ["finance-leads", "everyone"] },
  { id: "p-emily", email: "emily.clark@example.com", name: "Emily Clark", status: "active", groups: ["finance", "everyone"] },
  { id: "p-mark", email: "mark.wilson@example.com", name: "Mark Wilson", status: "active", groups: ["finance", "everyone"] },
  { id: "p-jonas", email: "jonas.weber@example.com", name: "Jonas Weber", status: "invited", groups: ["everyone"] },
];
const IDENTITY_TOKEN = "identity-viewer-e2e";
const identityServer = createServer((req, res) => {
  if (req.headers.authorization !== `Bearer ${IDENTITY_TOKEN}`) return void res.writeHead(401).end();
  res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ people }));
});

const VAULTS = `
vaults:
  - id: finance
    name: Finance
    access:
      finance-leads: manage
      finance: edit
  - id: office
    name: Office
    access: { everyone: read }
policies:
  passwordGenerator: { minLength: 24, useNumbers: true }
`;

const listen = (s: Server) => new Promise<string>((r) => s.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${(s.address() as AddressInfo).port}`)));

async function main() {
  // ---- The README's first start, steps 3 to 6 ----
  const selin = await register("selin.demir@example.com", "Selin Demir", "selin master password 2026", PBKDF2);
  const orgRaw = globalThis.crypto.getRandomValues(new Uint8Array(64));
  const orgKey = await symmetricKey(orgRaw);
  const orgPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const org = await vw("/api/organizations", {
    method: "POST",
    token: selin.token,
    body: JSON.stringify({
      name: "Acme",
      billingEmail: selin.email,
      collectionName: await encryptText("Default collection", orgKey),
      key: await rsaEncrypt(orgRaw, selin.publicKey),
      keys: {
        publicKey: b64.encode(orgPair.publicKey.export({ type: "spki", format: "der" })),
        encryptedPrivateKey: await encrypt(new Uint8Array(orgPair.privateKey.export({ type: "pkcs8", format: "der" })), orgKey),
      },
      planType: 0,
    }),
  });
  const orgId: string = org.id;
  const orgSecret: string = (
    await vw(`/api/organizations/${orgId}/api-key`, { method: "POST", token: selin.token, body: JSON.stringify({ masterPasswordHash: selin.hash }) })
  ).apiKey;

  const service = await register("passwords-service@example.com", "Passwords service", "service master password, kept elsewhere", PBKDF2);
  await vw(`/api/organizations/${orgId}/users/invite`, {
    method: "POST",
    token: selin.token,
    body: JSON.stringify({ emails: [service.email], groups: [], type: 1, collections: [], permissions: {} }),
  });
  const serviceMember = (await vw(`/api/organizations/${orgId}/users`, { token: selin.token })).data.find((m: { email: string }) => m.email === service.email);
  assert.equal(serviceMember.status, 1, "an invited account is accepted at once without SMTP");
  await vw(`/api/organizations/${orgId}/users/${serviceMember.id}/confirm`, {
    method: "POST",
    token: selin.token,
    body: JSON.stringify({ key: await rsaEncrypt(orgRaw, service.publicKey) }),
  });
  const serviceSecret: string = (
    await vw("/api/accounts/api-key", { method: "POST", token: service.token, body: JSON.stringify({ masterPasswordHash: service.hash }) })
  ).apiKey;

  // People set their master password before Passwords' first sync; Emily's account uses Argon2id.
  const emily = await register("emily.clark@example.com", "Emily Clark", "emily correct horse battery staple", ARGON2);
  const mark = await register("mark.wilson@example.com", "Mark Wilson", "mark master password 2026", PBKDF2);

  // ---- Passwords, step 7 ----
  const identityUrl = await listen(identityServer);
  const db = openDb(":memory:");
  const vaultwarden = createVaultwarden({ url: VW, organizationId: orgId, orgSecret, serviceClientId: `user.${service.id}`, serviceSecret });
  const passwords = createPasswords(db, vaultwarden, createIdentity({ url: identityUrl, token: IDENTITY_TOKEN }), { vaultwardenUrl: VW, leakCheck: false });
  let handler: RequestListener = (_q, s) => s.writeHead(503).end();
  const server = createServer((q, s) => handler(q, s));
  const base = await listen(server);
  const tokens: Record<string, { email: string; role: Role }> = {
    "e2e-selin": { email: selin.email, role: "admin" },
    "e2e-emily": { email: emily.email, role: "user" },
    "e2e-mark": { email: mark.email, role: "user" },
  };
  handler = createApp({
    db,
    passwords,
    vaultwarden,
    version: "e2e",
    auth: createAuth({ db, product: "passwords", productName: "OpenAsy Passwords", origin: base, users: true }),
    adminToken: "e2e-admin",
    personTokens: tokens,
  });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { ...(init.headers as Record<string, string>), authorization: `Bearer ${token}` } });
  const api = async (token: string, path: string, init: RequestInit = {}): Promise<any> => {
    const res = await as(token)(path, { ...init, headers: { "content-type": "application/json", ...(init.headers as Record<string, string>) } });
    assert.ok(res.ok, `${path}: ${res.status} ${await res.clone().text()}`);
    return res.status === 204 ? undefined : res.json();
  };
  /** A person's browser on the Vaults page: their settings, then the unlock with their master password. */
  const open = async (token: string, password: string): Promise<Session> =>
    unlock(password, (await api(token, "/api/v1/vault/settings")) as VaultSettings, { fetch: as(token) as typeof fetch });

  try {
    await step("the vaults file is applied and the first sync imports Identity's people and groups", async () => {
      await passwords.setConfig(parseConfig(VAULTS));
      const r = await passwords.syncNow();
      assert.equal(r.error, null);
      const members = await vaultwarden.members();
      const by = (email: string) => members.find((m) => m.email === email);
      assert.equal(by(emily.email)?.status, 1, "Emily set her master password, so she waits to be confirmed");
      assert.equal(by(mark.email)?.status, 1);
      assert.equal(by(selin.email)?.type, 0, "the owner stays the owner");
      assert.equal(by("jonas.weber@example.com")?.status, 0, "Jonas has no account yet: invited");
      assert.equal(by(emily.email)?.externalId, "p-emily");
      const groups = await vaultwarden.groups();
      assert.deepEqual(groups.map((g) => g.name).sort(), ["everyone", "finance", "finance-leads"]);
      const summary = await api("e2e-admin", "/api/v1/summary");
      assert.deepEqual(summary.missing.sort(), ["finance", "office"]);
      assert.deepEqual(summary.features, { email: service.email, groups: true, events: true });
    });

    await step("the generator policy reaches Vaultwarden as the apps read it", async () => {
      const p = (await vaultwarden.policies()).find((x) => x.type === 2);
      assert.equal(p?.enabled, true);
      assert.equal(p?.data?.minLength, 24);
      assert.equal(p?.data?.useNumbers, true);
    });

    let selinPage: Session;
    await step("the owner unlocks in the page, creates the file's vaults and they get the file's groups", async () => {
      selinPage = await open("e2e-selin", selin.password);
      assert.equal(selinPage.orgAdmin, true);
      await selinPage.createVault("finance", "Finance");
      await selinPage.createVault("office", "Office");
      await passwords.syncNow();
      const cols = await vaultwarden.collections();
      const finance = cols.find((c) => c.externalId === "finance")!;
      const groups = await vaultwarden.groups();
      const access = (name: string) => groups.find((g) => g.name === name)!.collections.find((c) => c.id === finance.id);
      assert.equal(access("finance")?.readOnly, false);
      assert.equal(access("finance")?.manage, false);
      assert.equal(access("finance-leads")?.manage, true);
      assert.equal(
        groups.find((g) => g.name === "everyone")!.collections.find((c) => c.id === finance.id),
        undefined,
      );
      await selinPage.reload();
      assert.deepEqual(selinPage.collections.map((c) => c.name).sort(), ["Default collection", "Finance", "Office"]);
      assert.deepEqual((await api("e2e-admin", "/api/v1/summary")).missing, []);
    });

    await step("the owner confirms the people waiting, from the page", async () => {
      const waiting = (await api("e2e-selin", "/api/v1/confirmations")).members as Array<{ id: string; email: string }>;
      assert.deepEqual(waiting.map((w) => w.email).sort(), [emily.email, mark.email]);
      const r = await selinPage.confirm(waiting.map((w) => w.id));
      assert.equal(r.failed.length, 0, JSON.stringify(r.failed));
      const members = await vaultwarden.members();
      assert.equal(members.find((m) => m.email === emily.email)?.status, 2);
    });

    let emilyPage: Session;
    let financeId = "";
    await step("Emily unlocks an Argon2id account and sees Finance and Office with her group's access", async () => {
      emilyPage = await open("e2e-emily", emily.password);
      const finance = emilyPage.collections.find((c) => c.name === "Finance")!;
      const office = emilyPage.collections.find((c) => c.name === "Office")!;
      financeId = finance.id;
      assert.equal(finance.readOnly, false);
      assert.equal(office.readOnly, true);
      assert.equal(emilyPage.orgAdmin, false);
    });

    await step("Emily adds a login to Finance and a note to her own vault, encrypted in the page", async () => {
      await emilyPage.addItem(
        {
          ...emptyDraft("login"),
          name: "Payroll provider",
          username: "finance@acme.example",
          password: "first-Pass-1234!",
          uri: "https://payroll.example",
          totp: "JBSWY3DPEHPK3PXP",
        },
        financeId,
      );
      await emilyPage.addItem({ ...emptyDraft("note"), name: "Desk drawer", notes: "Key under the plant" }, null);
      const payroll = emilyPage.items.find((i) => i.name === "Payroll provider")!;
      assert.equal(payroll.organizationId, orgId);
      assert.deepEqual(payroll.collectionIds, [financeId]);
      assert.equal(payroll.password, "first-Pass-1234!");
      assert.deepEqual(payroll.uris, ["https://payroll.example"]);
      assert.equal(emilyPage.items.find((i) => i.name === "Desk drawer")?.notes, "Key under the plant");
      // What Vaultwarden keeps is encrypted: the service account sees only ids and dates.
      const stored = await vaultwarden.items();
      assert.ok(stored.some((i) => i.id === payroll.id && i.collectionIds.includes(financeId)));
    });

    await step("a read-only vault refuses new items from Vaultwarden itself", async () => {
      const office = emilyPage.collections.find((c) => c.name === "Office")!;
      await assert.rejects(emilyPage.addItem({ ...emptyDraft("note"), name: "Not allowed", notes: "x" }, office.id));
    });

    await step("Emily changes the password; the old one goes to the item's history and the date moves", async () => {
      const payroll = emilyPage.items.find((i) => i.name === "Payroll provider")!;
      await emilyPage.updateItem(payroll, {
        ...emptyDraft("login"),
        name: "Payroll provider",
        username: "finance@acme.example",
        password: "second-Pass-5678!",
        uri: "https://payroll.example",
        totp: "JBSWY3DPEHPK3PXP",
      });
      const after = emilyPage.items.find((i) => i.id === payroll.id)!;
      assert.equal(after.password, "second-Pass-5678!");
      assert.equal(after.history, 1);
      assert.ok(after.passwordRevisionDate);
    });

    await step("a change from a stale copy is refused, so an edit made elsewhere is not overwritten", async () => {
      const stale = emilyPage.items.find((i) => i.name === "Payroll provider")!;
      // Selin changes it meanwhile.
      await selinPage.reload();
      const selinCopy = selinPage.items.find((i) => i.id === stale.id)!;
      // Vaultwarden refuses a copy more than one whole second older than the item.
      await new Promise((r) => setTimeout(r, 2500));
      await selinPage.updateItem(selinCopy, {
        ...emptyDraft("login"),
        name: "Payroll provider",
        username: "payroll@acme.example",
        password: "second-Pass-5678!",
        uri: "https://payroll.example",
        totp: "JBSWY3DPEHPK3PXP",
      });
      await assert.rejects(emilyPage.updateItem(stale, { ...emptyDraft("login"), name: "Payroll (Emily)", password: "x" }), /out of date/);
      await emilyPage.reload();
      assert.equal(emilyPage.items.find((i) => i.id === stale.id)?.username, "payroll@acme.example");
    });

    await step("Emily moves her note into Finance and the owner opens it with the organization's key", async () => {
      const note = emilyPage.items.find((i) => i.name === "Desk drawer")!;
      await emilyPage.moveItem(note, financeId);
      assert.equal(emilyPage.items.find((i) => i.id === note.id)?.organizationId, orgId);
      const all = await selinPage.organizationItems();
      assert.equal(all.find((i) => i.id === note.id)?.notes, "Key under the plant");
      assert.equal(all.find((i) => i.name === "Payroll provider")?.password, "second-Pass-5678!");
    });

    await step("Activity names who added and changed which item, from Vaultwarden's event log", async () => {
      await passwords.syncNow();
      const events = (await api("e2e-admin", "/api/v1/activity?vault=finance")).events as Array<{ action: string; actor: { email: string } | null }>;
      const by = (action: string, email: string) => events.some((e) => e.action === action && e.actor?.email === email);
      assert.ok(by("added", emily.email), JSON.stringify(events.map((e) => [e.action, e.actor?.email])));
      assert.ok(by("changed", emily.email));
      assert.ok(by("changed", selin.email));
    });

    // ---- The official Bitwarden CLI on the same accounts ----
    const bwHome = mkdtempSync(join(tmpdir(), "passwords-bw-"));
    // Run without blocking: Passwords' server runs in this process and must keep answering meanwhile.
    const bw = async (...args: string[]) =>
      (
        await promisify(execFile)("npx", ["-y", `@bitwarden/cli@${BW}`, ...args], {
          env: { ...process.env, BITWARDENCLI_APPDATA_DIR: bwHome, NODE_OPTIONS: "", npm_config_loglevel: "error" },
          encoding: "utf8",
        })
      ).stdout.trim();
    let session = "";
    await step(`the Bitwarden CLI ${BW} signs in to Emily's Argon2id account made by the same code`, async () => {
      await bw("config", "server", VW);
      session = await bw("login", emily.email, emily.password, "--raw");
      assert.ok(session.length > 20);
    });

    await step("the Bitwarden CLI opens what the page wrote: names, passwords, history and the moved note", async () => {
      await bw("sync", "--session", session);
      const items = JSON.parse(await bw("list", "items", "--session", session)) as Array<any>;
      const payroll = items.find((i) => i.name === "Payroll provider");
      assert.ok(payroll, `the CLI lists ${items.map((i) => i.name).join(", ")}`);
      assert.equal(payroll.login.password, "second-Pass-5678!");
      assert.equal(payroll.login.username, "payroll@acme.example");
      assert.equal(payroll.login.uris[0].uri, "https://payroll.example");
      assert.equal(payroll.login.totp, "JBSWY3DPEHPK3PXP");
      assert.equal(payroll.passwordHistory?.length, 1);
      assert.ok(payroll.passwordHistory.some((h: { password: string }) => h.password === "first-Pass-1234!"));
      const note = items.find((i) => i.name === "Desk drawer");
      assert.equal(note.notes, "Key under the plant");
      assert.equal(note.organizationId, orgId);
    });

    let cliItem = "";
    await step("the page opens items the Bitwarden CLI made, in her own vault and in Finance", async () => {
      const encode = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64");
      const login = (name: string, extra: object = {}) => ({
        type: 1,
        name,
        notes: "made by bw",
        favorite: true,
        fields: [{ name: "Customer number", value: "88213", type: 0 }],
        login: { username: "cli-user", password: "cli-Pass-9876!", uris: [{ uri: "https://cli.example", match: null }], totp: null },
        reprompt: 0,
        ...extra,
      });
      cliItem = JSON.parse(await bw("create", "item", encode(login("Made in the CLI")), "--session", session)).id;
      await bw("create", "item", encode(login("Shared from the CLI", { organizationId: orgId, collectionIds: [financeId] })), "--session", session);
      await emilyPage.reload();
      const mine = emilyPage.items.find((i) => i.id === cliItem)!;
      assert.equal(mine.error, null);
      assert.equal(mine.password, "cli-Pass-9876!");
      assert.deepEqual(mine.uris, ["https://cli.example"]);
      assert.equal(emilyPage.items.find((i) => i.name === "Shared from the CLI")?.password, "cli-Pass-9876!");
    });

    await step("changing a CLI item in the page keeps its custom field and star", async () => {
      const mine = emilyPage.items.find((i) => i.id === cliItem)!;
      await emilyPage.updateItem(mine, {
        ...emptyDraft("login"),
        name: "Made in the CLI, renamed",
        username: "cli-user",
        password: "cli-Pass-9876!",
        uri: "https://cli.example",
      });
      await bw("sync", "--session", session);
      const item = JSON.parse(await bw("get", "item", cliItem, "--session", session));
      assert.equal(item.name, "Made in the CLI, renamed");
      assert.equal(item.favorite, true);
      assert.deepEqual(
        item.fields.map((f: { name: string; value: string }) => [f.name, f.value]),
        [["Customer number", "88213"]],
      );
      assert.equal((item.passwordHistory ?? []).length, 0, `the password did not change, so no history was added: ${JSON.stringify(item.passwordHistory)}`);
    });

    await step("putting an item in the trash in the page shows in the CLI's trash", async () => {
      const mine = emilyPage.items.find((i) => i.id === cliItem)!;
      await emilyPage.deleteItem(mine);
      assert.equal(emilyPage.items.find((i) => i.id === cliItem)?.deleted, true);
      await bw("sync", "--session", session);
      const trash = JSON.parse(await bw("list", "items", "--trash", "--session", session)) as Array<{ id: string }>;
      assert.ok(trash.some((i) => i.id === cliItem));
    });

    await step("someone Identity disables leaves the organization at the next sync, with what they could see", async () => {
      people.find((p) => p.id === "p-mark")!.status = "disabled";
      await passwords.syncNow();
      const m = (await vaultwarden.members()).find((x) => x.email === mark.email);
      assert.ok(!m || m.status === -1, `Mark is ${JSON.stringify(m)}`);
      const leavers = (await api("e2e-admin", "/api/v1/leavers")).leavers as Array<{ email: string; items: unknown[] }>;
      const left = leavers.find((l) => l.email === mark.email);
      assert.ok(left && left.items.length >= 3, JSON.stringify(left));
    });
  } finally {
    server.close();
    identityServer.close();
  }
  console.log(failures ? `\n${failures} failed` : "\nall passed");
  process.exit(failures ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
