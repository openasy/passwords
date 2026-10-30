import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ORG, PASSWORD_HASH } from "./fake-vaultwarden.ts";
import { NOW, STRANGER, startApp } from "./test-app.ts";

let now = NOW;
let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0", clock: () => now });
});
afterAll(() => app.close());

const json = async (res: Response) => (await res.json()) as any;
const day = (d: string) => Date.parse(`${d}T09:00:00Z`);

describe("administration", () => {
  it("lists the vaults of the file with their people from Identity's groups", async () => {
    const body = await json(await app.admin("/api/v1/vaults"));
    expect(body.vaults.map((v: any) => [v.id, v.collectionId])).toEqual([
      ["finance", "col-finance"],
      ["sales", null],
      ["office", "col-office"],
    ]);
    expect(body.vaults[0].members).toEqual([
      { name: "Selin Demir", email: "selin.demir@example.com", access: "manage", group: "finance-leads" },
      { name: "Ali Yılmaz", email: "ali.yilmaz@example.com", access: "edit", group: "finance" },
      { name: "Emily Clark", email: "emily.clark@example.com", access: "edit", group: "finance" },
    ]);
  });

  it("shows a person only the vaults their groups give them", async () => {
    const body = await json(await app.emily("/api/v1/vaults"));
    expect(body.vaults.map((v: any) => v.id)).toEqual(["finance", "office"]);
    expect((await app.emily("/api/v1/summary")).status).toBe(403);
  });

  it("sums up the organization: missing vaults, people waiting, who holds the key", async () => {
    const s = await json(await app.admin("/api/v1/summary"));
    expect(s).toMatchObject({ vaults: 3, groups: 4, missing: ["sales"], waiting: 1, keyHolders: 1, leakCheck: true, organizationId: ORG });
    expect((await json(await app.admin("/api/v1/confirmations"))).members).toEqual([
      { id: expect.any(String), email: "emily.clark@example.com", name: "Emily Clark" },
    ]);
  });

  it("brings Vaultwarden in step on request and keeps the history", async () => {
    const run = await json(await app.admin("/api/v1/sync", { method: "POST" }));
    expect(run).toMatchObject({ ok: true, added: [], removed: [], missing: ["sales"] });
    const history = await json(await app.admin("/api/v1/sync"));
    expect(history.runs.length).toBe(2);
    expect(history.runs[1]).toMatchObject({ ok: true, added: 1, vaults: 2, policies: 2 });
    expect((await app.emily("/api/v1/sync", { method: "POST" })).status).toBe(403);
  });
});

describe("activity", () => {
  it("lists who opened, copied or changed which item, by vault, with the item's id for the browser to name", async () => {
    const ali = app.fake.memberByEmail("ali.yilmaz@example.com")!;
    const emily = app.fake.memberByEmail("emily.clark@example.com")!;
    const event = (type: number, item: string, who: string, date: string) =>
      app.fake.events.push({
        type,
        userId: null,
        cipherId: item,
        collectionId: null,
        groupId: null,
        organizationUserId: null,
        actingUserId: who,
        date,
        deviceType: 2,
        ipAddress: "203.0.113.7",
      });
    event(1111, "item-bank", ali.userId, "2026-11-03T18:02:00.000000Z");
    event(1107, "item-wifi", ali.userId, "2026-10-27T17:48:00.000000Z");
    event(1101, "item-tax", emily.userId, "2026-11-04T08:31:00.000000Z");
    event(1107, "item-payroll", ali.userId, "2026-06-01T10:00:00.000000Z");
    await app.passwords.pollEvents();
    const all = (await json(await app.admin("/api/v1/activity"))).events;
    expect(all.map((e: any) => [e.action, e.itemId, e.actor?.name, e.vaults])).toEqual([
      ["changed", "item-tax", "Emily Clark", ["finance"]],
      ["copied", "item-bank", "Ali Yılmaz", ["finance"]],
      ["opened", "item-wifi", "Ali Yılmaz", ["office"]],
      ["opened", "item-payroll", "Ali Yılmaz", ["finance"]],
    ]);
    expect(all[0]).toMatchObject({ deviceType: 2, ip: "203.0.113.7" });
    const office = (await json(await app.admin("/api/v1/activity?vault=office"))).events;
    expect(office.map((e: any) => e.itemId)).toEqual(["item-wifi"]);
    expect((await app.admin("/api/v1/activity?vault=nope")).status).toBe(404);
    // Read again, nothing is counted twice.
    await app.passwords.pollEvents();
    expect((await json(await app.admin("/api/v1/activity"))).events.length).toBe(4);
  });
});

describe("leavers", () => {
  it("lists what someone leaving could see, the recently opened first, before their last day", async () => {
    const made = await app.admin("/api/v1/leavers", { method: "POST", body: JSON.stringify({ email: "Mark.Wilson@example.com", leavesOn: "2026-11-30" }) });
    expect(made.status).toBe(201);
    const mark = await json(made);
    expect(mark).toMatchObject({ name: "Mark Wilson", reason: "planned", leavesOn: "2026-11-30", leftAt: null });
    // Mark is in sales, which has no collection yet, and in everyone, which reads the office vault.
    expect(mark.items.map((i: any) => i.itemId).sort()).toEqual(["item-alarm", "item-wifi"]);
    expect(
      (await app.admin("/api/v1/leavers", { method: "POST", body: JSON.stringify({ email: "mark.wilson@example.com", leavesOn: "2026-12-01" }) })).status,
    ).toBe(409);
    expect((await app.admin("/api/v1/leavers", { method: "POST", body: JSON.stringify({ email: "nobody@example.com", leavesOn: "2026-12-01" }) })).status).toBe(
      422,
    );
    expect((await app.emily("/api/v1/leavers")).status).toBe(403);
  });

  it("removes someone Identity disabled at the next sync and keeps what they could see", async () => {
    app.directory.people.find((p) => p.id === "p-ali")!.status = "disabled";
    const run = await json(await app.admin("/api/v1/sync", { method: "POST" }));
    expect(run.removed).toEqual(["ali.yilmaz@example.com"]);
    const ali = (await json(await app.admin("/api/v1/leavers"))).leavers.find((l: any) => l.email === "ali.yilmaz@example.com");
    expect(ali).toMatchObject({ name: "Ali Yılmaz", reason: "disabled", leftAt: expect.any(String), changed: 0 });
    expect(ali.items.map((i: any) => [i.itemId, i.recent])).toEqual([
      ["item-bank", true],
      ["item-wifi", true],
      ["item-payroll", false],
      ["item-alarm", false],
      ["item-tax", false],
    ]);
    // Marked as changed by hand, then the list counts it.
    const marked = await json(await app.admin(`/api/v1/leavers/${ali.id}/items/item-bank`, { method: "PUT", body: JSON.stringify({ changed: true }) }));
    expect(marked).toMatchObject({ itemId: "item-bank", changed: true, changedBy: "api-token" });
    expect((await app.admin(`/api/v1/leavers/${ali.id}/items/item-board`, { method: "PUT", body: JSON.stringify({ changed: true }) })).status).toBe(404);
    // A password changed after Ali left counts too.
    app.fake.items.find((i) => i.id === "item-tax")!.login!.passwordRevisionDate = "2026-11-04T12:00:00.000000Z";
    await app.admin("/api/v1/sync", { method: "POST" });
    const again = (await json(await app.admin("/api/v1/leavers"))).leavers.find((l: any) => l.id === ali.id);
    expect(again.changed).toBe(2);
    expect((await app.admin(`/api/v1/leavers/${ali.id}`, { method: "DELETE" })).status).toBe(409);
  });

  it("removes a planned leaver on their last day", async () => {
    now = day("2026-11-30");
    const run = await json(await app.admin("/api/v1/sync", { method: "POST" }));
    expect(run.removed).toEqual(["mark.wilson@example.com"]);
    const mark = (await json(await app.admin("/api/v1/leavers"))).leavers.find((l: any) => l.email === "mark.wilson@example.com");
    expect(mark).toMatchObject({ reason: "planned", leftAt: expect.any(String) });
    expect(mark.items.length).toBe(2);
    expect(app.fake.memberByEmail("mark.wilson@example.com")).toBeUndefined();
    now = NOW;
  });
});

describe("the vault pass-through", () => {
  it("asks Vaultwarden about the signed-in person only", async () => {
    const res = await app.emily("/api/v1/vault/prelogin", { method: "POST", body: JSON.stringify({ email: "selin.demir@example.com" }) });
    expect(await json(res)).toMatchObject({ kdf: 0, kdfIterations: 600000 });
    expect(app.fake.calls.at(-1)).toMatchObject({ path: "/identity/accounts/prelogin", body: { email: "emily.clark@example.com" } });
    expect((await app.admin("/api/v1/vault/prelogin", { method: "POST", body: "{}" })).status).toBe(401);
  });

  it("signs in to Vaultwarden as the signed-in person, whatever user name the browser sends", async () => {
    const form = new URLSearchParams({
      grant_type: "password",
      username: "selin.demir@example.com",
      password: PASSWORD_HASH,
      client_id: "cli",
      device_identifier: "d1",
    });
    const res = await app.emily("/api/v1/vault/token", {
      method: "POST",
      body: form.toString(),
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    expect(res.status).toBe(200);
    const token = await json(res);
    expect(token).toMatchObject({ access_token: "user-emily.clark@example.com", Key: "2.encrypted-user-key" });
    expect(app.fake.calls.at(-1)!.body).toMatchObject({ username: "emily.clark@example.com", client_id: "web", scope: "api offline_access" });
    expect(res.headers.get("cache-control")).toBe("no-store");
    const wrong = await app.emily("/api/v1/vault/token", { method: "POST", body: "grant_type=password&password=nope" });
    expect(wrong.status).toBe(400);
    expect((await json(wrong)).message).toBe("Username or password is incorrect. Try again");
    expect((await app.emily("/api/v1/vault/token", { method: "POST", body: "grant_type=client_credentials" })).status).toBe(422);
  });

  it("passes the person's own Vaultwarden token on, and their address for Vaultwarden's log", async () => {
    // Emily is confirmed now, so her browser gets the shared items.
    app.fake.memberByEmail("emily.clark@example.com")!.status = 2;
    const res = await app.emily("/api/v1/vault/sync", {
      headers: { "x-vault-authorization": "Bearer user-emily.clark@example.com", "x-real-ip": "198.51.100.4" },
    });
    const sync = await json(res);
    expect(sync.ciphers.map((c: any) => c.id).sort()).toEqual(["item-alarm", "item-bank", "item-payroll", "item-tax", "item-wifi"]);
    expect(app.fake.calls.at(-1)!.headers["x-real-ip"]).toBe("198.51.100.4");
    expect((await app.emily("/api/v1/vault/sync")).status).toBe(401);
    await app.emily("/api/v1/vault/events", {
      method: "POST",
      body: JSON.stringify([{ type: 1107, cipherId: "item-bank", date: "2026-11-04T09:12:00Z" }]),
      headers: { "x-vault-authorization": "Bearer user-emily.clark@example.com", "device-type": "9" },
    });
    expect(app.fake.events.at(-1)).toMatchObject({ type: 1107, cipherId: "item-bank", deviceType: 9 });
  });

  it("lets only admins confirm members and create vaults, from their browser", async () => {
    const token = { "x-vault-authorization": "Bearer user-selin.demir@example.com" };
    expect((await app.emily("/api/v1/vault/organization/confirm", { method: "POST", body: "{}" })).status).toBe(403);
    expect((await app.as(STRANGER)("/api/v1/vault/organization/collections", { method: "POST", body: "{}" })).status).toBe(403);
    const made = await json(
      await app.selin("/api/v1/vault/organization/collections", {
        method: "POST",
        body: JSON.stringify({ name: "2.encrypted-sales", externalId: "sales", groups: [], users: [] }),
        headers: token,
      }),
    );
    expect(made).toMatchObject({ name: "2.encrypted-sales", externalId: "sales" });
    await app.passwords.syncNow();
    expect((await json(await app.admin("/api/v1/summary"))).missing).toEqual([]);
  });

  it("is open to signed-in people only, and says when Vaultwarden does not answer", async () => {
    expect((await fetch(`${app.base}/api/v1/vault/settings`)).status).toBe(401);
    expect(await json(await app.emily("/api/v1/vault/settings"))).toMatchObject({
      email: "emily.clark@example.com",
      organizationId: ORG,
      vaultwardenUrl: "https://vault.example.com",
      leakCheck: true,
      member: { status: 2, type: 2 },
    });
    app.fake.state.down = true;
    try {
      const res = await app.emily("/api/v1/vault/sync", { headers: { "x-vault-authorization": "Bearer user-emily.clark@example.com" } });
      expect(res.status).toBe(502);
      expect((await json(res)).code).toBe("vault-server-unavailable");
    } finally {
      app.fake.state.down = false;
    }
  });

  it("serves pages that run nothing from elsewhere", async () => {
    const res = await fetch(`${app.base}/api/v1/version`);
    expect(res.headers.get("content-security-policy")).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(res.headers.get("content-security-policy")).toContain("https://api.pwnedpasswords.com");
  });
});
