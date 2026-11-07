// Items written in the browser open again with the same keys, keep what the Bitwarden apps added, and move into a
// shared vault with the organization's key.
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { b64, decrypt, decryptText, encryptText, sha256, symmetricKey } from "./crypto.ts";
import { buildCipher, emptyDraft, generatePassword, shareCipher, type Draft, type Opened } from "./items.ts";
import { openItem } from "./vault.ts";

const keys = async () => {
  const userRaw = new Uint8Array(randomBytes(64));
  const orgRaw = new Uint8Array(randomBytes(64));
  return { user: await symmetricKey(userRaw), org: await symmetricKey(orgRaw) };
};
const login = (over: Partial<Draft> = {}): Draft => ({
  ...emptyDraft("login"),
  name: "Payroll provider",
  username: "finance@acme.example",
  password: "first-Pass-1234!",
  totp: "JBSWY3DPEHPK3PXP",
  uri: "https://payroll.example",
  notes: "Ask Emily before changing.",
  ...over,
});
/** As Vaultwarden answers: the record sent, with its id and dates. */
const stored = (cipher: Record<string, unknown>, id = "c-1"): Record<string, any> => ({
  ...cipher,
  id,
  revisionDate: "2026-11-01T10:00:00.000Z",
  creationDate: "2026-11-01T10:00:00.000Z",
  edit: true,
  viewPassword: true,
});

describe("writing items", () => {
  it("makes a new login with its own key, which opens again to the same values", async () => {
    const { user } = await keys();
    const cipher = await buildCipher({ draft: login(), userId: "u-1", vaultKey: user });
    expect(cipher).toMatchObject({ type: 1, organizationId: null, encryptedFor: "u-1", favorite: false, folderId: null });
    expect(String(cipher.key)).toMatch(/^2\./);
    // Nothing in plain text leaves the page.
    expect(JSON.stringify(cipher)).not.toMatch(/Payroll|finance@|first-Pass|JBSWY|payroll\.example|Emily/);
    const item = await openItem(stored(cipher), user);
    expect(item).toMatchObject({
      error: null,
      name: "Payroll provider",
      username: "finance@acme.example",
      password: "first-Pass-1234!",
      totp: "JBSWY3DPEHPK3PXP",
      uris: ["https://payroll.example"],
      notes: "Ask Emily before changing.",
      passwordRevisionDate: null,
    });
  });

  it("keeps the checksum the Bitwarden apps check next to each web address", async () => {
    const { user } = await keys();
    const cipher = await buildCipher({ draft: login(), userId: "u-1", vaultKey: user });
    const itemKey = await symmetricKey(new Uint8Array(await decrypt(String(cipher.key), user)));
    const uri = (cipher.login as { uris: Array<{ uri: string; uriChecksum: string }> }).uris[0]!;
    expect(await decryptText(uri.uriChecksum, itemKey)).toBe(b64.encode(await sha256(new TextEncoder().encode("https://payroll.example"))));
  });

  it("makes notes and cards", async () => {
    const { org } = await keys();
    const note = await buildCipher({
      draft: { ...emptyDraft("note"), name: "Wi-Fi", notes: "Office-5G / hunter2" },
      userId: "u-1",
      vaultKey: org,
      organizationId: "org-1",
    });
    expect(note).toMatchObject({ type: 2, organizationId: "org-1", secureNote: { type: 0 } });
    expect(await openItem(stored(note), org)).toMatchObject({ kind: "note", name: "Wi-Fi", notes: "Office-5G / hunter2" });
    const card = await buildCipher({
      draft: {
        ...emptyDraft("card"),
        name: "Travel card",
        card: { holder: "Acme Corp", brand: "Visa", number: "4111 1111 1111 4421", expMonth: "7", expYear: "2029", code: "123" },
      },
      userId: "u-1",
      vaultKey: org,
      organizationId: "org-1",
    });
    expect((await openItem(stored(card), org)).card).toEqual({
      holder: "Acme Corp",
      brand: "Visa",
      number: "4111111111114421",
      expiry: "07/2029",
      code: "123",
    });
  });

  it("refuses an item without a name", async () => {
    const { user } = await keys();
    await expect(buildCipher({ draft: login({ name: "  " }), userId: "u-1", vaultKey: user })).rejects.toThrow("needs a name");
  });

  it("changes only the form's fields and keeps what the apps added", async () => {
    const { user } = await keys();
    const first = stored(await buildCipher({ draft: login(), userId: "u-1", vaultKey: user }));
    const itemKey = await symmetricKey(new Uint8Array(await decrypt(String(first.key), user)));
    // What a Bitwarden app adds: a custom field, a passkey, a second address, a folder and a star.
    const passkey = { credentialId: await encryptText("cred", itemKey), rpId: await encryptText("payroll.example", itemKey) };
    const extra = {
      ...first,
      folderId: "folder-1",
      favorite: true,
      fields: [{ type: 0, name: await encryptText("Customer number", itemKey), value: await encryptText("88213", itemKey) }],
      login: {
        ...(first.login as object),
        fido2Credentials: [passkey],
        uris: [...(first.login as { uris: object[] }).uris, { uri: await encryptText("https://payroll.example/admin", itemKey), match: 3 }],
      },
      attachments: [{ id: "a-1", fileName: "2.x|y|z" }],
      object: "cipherDetails",
    };
    const before = await openItem(extra, user);
    const now = new Date("2026-11-07T12:00:00Z");
    const changed = await buildCipher({
      draft: login({ password: "second-Pass-5678!", uri: "https://payroll.example/login" }),
      userId: "u-1",
      previous: { opened: await reopen(extra, user), password: before.password, uri: before.uris[0]! },
      now,
    });
    expect(changed).toMatchObject({ folderId: "folder-1", favorite: true, key: first.key, lastKnownRevisionDate: first.revisionDate, encryptedFor: "u-1" });
    expect(changed.fields).toEqual(extra.fields);
    expect((changed.login as { fido2Credentials: unknown }).fido2Credentials).toEqual([passkey]);
    // Vaultwarden's answer fields are left out: they are not CipherData.
    expect(changed).not.toHaveProperty("attachments");
    expect(changed).not.toHaveProperty("object");
    const after = await openItem(stored(changed), user);
    expect(after).toMatchObject({
      password: "second-Pass-5678!",
      uris: ["https://payroll.example/login", "https://payroll.example/admin"],
      history: 1,
      passwordRevisionDate: now.toISOString(),
    });
    const history = (changed.passwordHistory as Array<{ password: string; lastUsedDate: string }>)[0]!;
    expect(await decryptText(history.password, itemKey)).toBe("first-Pass-1234!");
    expect(history.lastUsedDate).toBe(now.toISOString());
  });

  it("keeps the password's date and history when only the name changes", async () => {
    const { user } = await keys();
    const first = stored(await buildCipher({ draft: login(), userId: "u-1", vaultKey: user }));
    const before = await openItem(first, user);
    const changed = await buildCipher({
      draft: login({ name: "Payroll" }),
      userId: "u-1",
      previous: { opened: await reopen(first, user), password: before.password, uri: before.uris[0]! },
    });
    expect(changed.passwordHistory).toBeUndefined();
    expect((changed.login as { passwordRevisionDate: unknown }).passwordRevisionDate).toBeNull();
    expect((await openItem(stored(changed), user)).name).toBe("Payroll");
  });

  it("moves a personal item into a shared vault by encrypting its key with the organization's key", async () => {
    const { user, org } = await keys();
    const mine = stored(await buildCipher({ draft: login(), userId: "u-1", vaultKey: user }));
    const shared = await shareCipher(await reopen(mine, user), { userId: "u-1", organizationId: "org-1", orgKey: org });
    expect(shared).toMatchObject({ organizationId: "org-1", encryptedFor: "u-1", name: mine.name });
    expect(shared.key).not.toBe(mine.key);
    expect(await openItem(stored(shared), org)).toMatchObject({ error: null, name: "Payroll provider", password: "first-Pass-1234!" });
  });

  it("gives an old item without its own key one when it moves", async () => {
    const { user, org } = await keys();
    const old = {
      id: "old",
      type: 1,
      organizationId: null,
      name: await encryptText("Old router", user),
      login: { username: await encryptText("admin", user), password: await encryptText("r0uter!", user), uris: null },
      fields: [{ type: 1, name: await encryptText("PIN", user), value: await encryptText("0000", user) }],
      revisionDate: "2024-01-01T00:00:00Z",
    };
    const shared = await shareCipher(await reopen(old, user), { userId: "u-1", organizationId: "org-1", orgKey: org });
    const item = await openItem(stored(shared), org);
    expect(item).toMatchObject({ error: null, name: "Old router", username: "admin", password: "r0uter!" });
    const itemKey = await symmetricKey(new Uint8Array(await decrypt(String(shared.key), org)));
    expect(await decryptText((shared.fields as Array<{ value: string }>)[0]!.value, itemKey)).toBe("0000");
  });

  it("leaves items with attachments to the Bitwarden apps when they move", async () => {
    const { user, org } = await keys();
    const mine = { ...stored(await buildCipher({ draft: login(), userId: "u-1", vaultKey: user })), attachments: [{ id: "a-1" }] };
    await expect(shareCipher(await reopen(mine, user), { userId: "u-1", organizationId: "org-1", orgKey: org })).rejects.toThrow("Bitwarden app");
  });
});

describe("making passwords", () => {
  it("makes 20 characters with every kind, or the policy's length", () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword(null);
      expect(p).toHaveLength(20);
      expect(p).toMatch(/[A-Z]/);
      expect(p).toMatch(/[a-z]/);
      expect(p).toMatch(/[0-9]/);
      expect(p).toMatch(/[!@#$%^&*]/);
    }
    expect(generatePassword({ minLength: 32, useUpper: true, useLower: true, useNumbers: true, useSpecial: true })).toHaveLength(32);
  });
});

/** What openItem keeps beside an item, rebuilt for the tests: the record, its key and that key's bytes. */
async function reopen(raw: Record<string, any>, vaultKey: Awaited<ReturnType<typeof symmetricKey>>): Promise<Opened> {
  const itemKey = raw.key ? await decrypt(raw.key, vaultKey) : null;
  return { raw, key: itemKey ? await symmetricKey(itemKey) : vaultKey, itemKey };
}
