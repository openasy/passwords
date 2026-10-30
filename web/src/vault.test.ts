// Unlocking against this product's /api/v1/vault as Vaultwarden answers through it, with an account built by Node's
// crypto. What the page sends is checked too: never the master password, only the hash Vaultwarden checks.
import { constants, privateDecrypt } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decryptText, symmetricKey } from "./crypto.ts";
import { EMAIL, ORG, PASSWORD, vaultServer as server } from "./test-vault.ts";
import { EVENT, TwoFactorRequired, unlock, VaultError } from "./vault.ts";

const settings = { email: EMAIL, organizationId: ORG, vaultwardenUrl: "https://vault.example.com", leakCheck: false, member: null };

describe("unlocking", () => {
  it("signs in with the master password hash only and decrypts items, cards and vault names in the browser", async () => {
    const s = server();
    const session = await unlock(PASSWORD, settings, { fetch: s.fetch });
    const bank = session.items.find((i) => i.id === "bank")!;
    expect(bank).toMatchObject({
      kind: "login",
      name: "Corporate banking",
      username: "acme-treasury",
      password: "hT9#vQ2m!xR4-Lp7w",
      totp: "JBSWY3DPEHPK3PXP",
      uris: ["https://business.bank.example"],
      history: 3,
      error: null,
    });
    expect(session.items.find((i) => i.id === "card")!.card).toMatchObject({ number: "4111111111114421", expiry: "07/2029" });
    expect(session.items.find((i) => i.id === "broken")!.error).toBeTruthy();
    expect(session.collections).toEqual([
      { id: "col-finance", organizationId: ORG, name: "Finance", externalId: "finance", readOnly: false, hidePasswords: false, manage: true },
    ]);
    expect(session.orgAdmin).toBe(true);
    // Nothing the page sent holds the master password.
    expect(s.sent.every((r) => !r.body.includes(PASSWORD) && !r.body.includes(encodeURIComponent(PASSWORD)))).toBe(true);
  });

  it("says when the password is wrong and when a second step is needed", async () => {
    await expect(unlock("wrong", settings, { fetch: server().fetch })).rejects.toThrow(new VaultError("Username or password is incorrect. Try again"));
    const s = server({ twoFactor: true });
    const asked = await unlock(PASSWORD, settings, { fetch: s.fetch }).catch((e) => e);
    expect(asked).toBeInstanceOf(TwoFactorRequired);
    expect(asked.providers).toEqual([0]);
    const session = await unlock(PASSWORD, settings, { fetch: s.fetch, twoFactor: { provider: 0, code: "123 456" } });
    expect(session.items.length).toBe(3);
  });

  it("renews Vaultwarden's token when it ends", async () => {
    const s = server();
    const session = await unlock(PASSWORD, settings, { fetch: s.fetch });
    s.expire();
    await session.reload();
    expect(s.sent.at(-1)!.vault).toBe("Bearer access-2");
  });

  it("confirms members by encrypting the organization's key to their public key", async () => {
    const s = server();
    const session = await unlock(PASSWORD, settings, { fetch: s.fetch });
    const r = await session.confirm(["m-1", "m-2"]);
    expect(r).toEqual({ confirmed: ["m-1"], failed: [{ id: "m-2", error: "This member has not set up their account yet." }] });
    const sent = JSON.parse(s.sent.find((x) => x.path === "/api/v1/vault/organization/confirm")!.body).keys[0];
    const key = privateDecrypt(
      { key: s.member.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" },
      Buffer.from(sent.key.slice(2), "base64"),
    );
    expect(key.equals(s.org)).toBe(true);
  });

  it("creates a vault with its name encrypted for the organization, and reports opened shared items", async () => {
    const s = server();
    const session = await unlock(PASSWORD, settings, { fetch: s.fetch });
    await session.createVault("sales", "Sales");
    const made = JSON.parse(s.sent.find((x) => x.path === "/api/v1/vault/organization/collections")!.body);
    expect(made).toMatchObject({ externalId: "sales", groups: [], users: [] });
    expect(await decryptText(made.name, await symmetricKey(new Uint8Array(s.org)))).toBe("Sales");
    session.report(
      EVENT.copiedPassword,
      session.items.find((i) => i.id === "bank")!,
    );
    session.report(
      EVENT.viewed,
      session.items.find((i) => i.id === "card")!,
    );
    await new Promise((r) => setTimeout(r, 0));
    const reported = s.sent.filter((x) => x.path === "/api/v1/vault/events").map((x) => JSON.parse(x.body)[0]);
    expect(reported).toEqual([{ type: 1111, cipherId: "bank", organizationId: ORG, date: expect.any(String) }]);
  });
});
