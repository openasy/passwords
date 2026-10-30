import { describe, expect, it } from "vitest";
import { parseConfig } from "./config.ts";
import { sync } from "./sync.ts";
import { setup, VAULTS } from "./test-app.ts";

const config = parseConfig(VAULTS);

describe("keeping Vaultwarden in step with the file and Identity", () => {
  it("imports the people in the file's groups, with Identity ids, and their groups", async () => {
    const { fake, vw, identity } = setup();
    const { result } = await sync(vw, () => identity.people(), config);
    expect(result).toMatchObject({ ok: true, added: ["emily.clark@example.com"], removed: [], error: null });
    const imported = fake.calls.find((c) => c.path === "/api/public/organization/import")!;
    expect(imported.token).toBe("org-token");
    expect(imported.body).toMatchObject({ overwriteExisting: true });
    // Jonas is only in it-admins, which no vault of the file names.
    expect((imported.body as { members: Array<{ email: string }> }).members.map((m) => m.email)).not.toContain("jonas.berg@example.com");
    expect(fake.memberByEmail("emily.clark@example.com")).toMatchObject({ externalId: "p-emily", status: 1 });
    const finance = [...fake.groups.values()].find((g) => g.externalId === "finance")!;
    expect(
      [...fake.members.values()]
        .filter((m) => m.groups.includes(finance.id))
        .map((m) => m.email)
        .sort(),
    ).toEqual(["ali.yilmaz@example.com", "emily.clark@example.com"]);
  });

  it("gives each vault's collection the groups of the file, and reports vaults with no collection yet", async () => {
    const { fake, vw, identity } = setup();
    const { result } = await sync(vw, () => identity.people(), config);
    expect(result.vaults).toEqual(["finance", "office"]);
    expect(result.missing).toEqual(["sales"]);
    const byExt = (e: string) => [...fake.groups.values()].find((g) => g.externalId === e)!;
    expect(byExt("finance-leads").collections).toEqual([{ id: "col-finance", readOnly: false, hidePasswords: false, manage: true }]);
    expect(byExt("finance").collections).toEqual([{ id: "col-finance", readOnly: false, hidePasswords: false, manage: false }]);
    expect(byExt("everyone").collections).toEqual([{ id: "col-office", readOnly: true, hidePasswords: false, manage: false }]);
    // A collection the file does not name is left alone, and none is ever deleted.
    expect(fake.collections.size).toBe(3);
  });

  it("applies the policies and keeps account recovery off", async () => {
    const { fake, vw, identity } = setup();
    fake.policies.set(8, { enabled: true, data: { autoEnrollEnabled: true } });
    const { result } = await sync(vw, () => identity.people(), config);
    expect(result.policies).toEqual(["twoStepLogin", "masterPassword", "accountRecovery"]);
    expect(fake.policies.get(0)).toEqual({ enabled: true, data: null });
    expect(fake.policies.get(1)!.data).toMatchObject({ minLength: 14, minComplexity: 3, enforceOnLogin: false });
    expect(fake.policies.get(8)!.enabled).toBe(false);
  });

  it("changes nothing when Vaultwarden already matches", async () => {
    const { fake, vw, identity } = setup();
    await sync(vw, () => identity.people(), config);
    const before = fake.calls.length;
    const { result } = await sync(vw, () => identity.people(), config);
    expect(result).toMatchObject({ ok: true, added: [], removed: [], vaults: [], policies: [] });
    expect(fake.calls.slice(before).filter((c) => c.path.endsWith("bulk-access") || c.path.includes("/policies/"))).toEqual([]);
  });

  it("puts back access changed by hand, including members given a vault directly", async () => {
    const { fake, vw, identity } = setup();
    await sync(vw, () => identity.people(), config);
    const mark = fake.memberByEmail("mark.wilson@example.com")!;
    mark.collections.push({ id: "col-finance", readOnly: false, hidePasswords: false, manage: false });
    const { result } = await sync(vw, () => identity.people(), config);
    expect(result.vaults).toEqual(["finance"]);
    expect(mark.collections).toEqual([]);
  });

  it("removes at once someone Identity disabled, after showing what they could see", async () => {
    const { fake, vw, identity, directory } = setup();
    await sync(vw, () => identity.people(), config);
    directory.people.find((p) => p.id === "p-ali")!.status = "disabled";
    const seen: string[] = [];
    const { result } = await sync(vw, () => identity.people(), config, {
      beforeRemove: (removed, state) => {
        seen.push(...removed.map((m) => m.email));
        expect(state.items.length).toBe(6);
      },
    });
    expect(result.removed).toEqual(["ali.yilmaz@example.com"]);
    expect(seen).toEqual(["ali.yilmaz@example.com"]);
    expect(fake.memberByEmail("ali.yilmaz@example.com")).toBeUndefined();
  });

  it("leaves out someone whose leaving day has come, never removes owners or members added by hand", async () => {
    const { fake, vw, identity } = setup();
    fake.addMember("owner@example.com", { type: 0, externalId: "p-gone" });
    fake.addMember("auditor@example.com");
    const { result } = await sync(vw, () => identity.people(), config, { due: new Set(["mark.wilson@example.com"]) });
    expect(result.removed).toEqual(["mark.wilson@example.com"]);
    expect(result.notes[0]).toMatch(/owner@example.com is an owner/);
    expect(fake.memberByEmail("owner@example.com")).toBeDefined();
    expect(fake.memberByEmail("auditor@example.com")).toBeDefined();
  });

  it("removes nobody when Identity lists nobody, and says when groups are off in Vaultwarden", async () => {
    const { fake, vw } = setup();
    const empty = await sync(vw, async () => [], config);
    expect(empty.result).toMatchObject({ ok: false, error: expect.stringMatching(/Identity lists nobody/) });
    expect(fake.calls.some((c) => c.path === "/api/public/organization/import")).toBe(false);
    fake.state.features.groups = false;
    expect((await sync(vw, async () => [], config)).result.error).toMatch(/ORG_GROUPS_ENABLED/);
  });

  it("reports a Vaultwarden it cannot reach, and a wrong key", async () => {
    const { fake, vw, identity } = setup();
    fake.state.down = true;
    expect((await sync(vw, () => identity.people(), config)).result.error).toMatch(/cannot be reached/);
    fake.state.down = false;
    const { createVaultwarden } = await import("./vaultwarden.ts");
    const wrong = createVaultwarden({
      url: "http://vaultwarden",
      organizationId: "x",
      orgSecret: "x",
      serviceClientId: "user.x",
      serviceSecret: "x",
      fetch: fake.fetch,
    });
    expect((await sync(wrong, () => identity.people(), config)).result.error).toMatch(/service account's API key/);
  });
});
