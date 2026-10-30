// Vaultwarden as the browser reaches it through /api/v1/vault, with an account built by Node's crypto, for the tests of
// the unlock and of the pages. Emily Clark's account: her own card, and the Finance vault with the corporate bank login.
import { constants, createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, publicEncrypt, randomBytes } from "node:crypto";

export const ORG = "org-1";
export const EMAIL = "emily.clark@example.com";
export const PASSWORD = "correct horse battery staple";
const ITERATIONS = 5000;

const aes = (key: Buffer, data: Buffer | string) => {
  const iv = randomBytes(16);
  const c = createCipheriv("aes-256-cbc", key.subarray(0, 32), iv);
  const ct = Buffer.concat([c.update(data), c.final()]);
  const mac = createHmac("sha256", key.subarray(32))
    .update(Buffer.concat([iv, ct]))
    .digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
};
const expand = (prk: Buffer, info: string) =>
  createHmac("sha256", prk)
    .update(Buffer.concat([Buffer.from(info), Buffer.from([1])]))
    .digest();

export function vaultServer({ twoFactor = false } = {}) {
  const master = pbkdf2Sync(PASSWORD, EMAIL, ITERATIONS, 32, "sha256");
  const hash = pbkdf2Sync(master, PASSWORD, 1, 32, "sha256").toString("base64");
  const user = randomBytes(64);
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const org = randomBytes(64);
  const itemKey = randomBytes(64);
  const member = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const sent: Array<{ path: string; body: string; vault: string | null }> = [];
  let expired = false;
  const json = (body: unknown, status = 200, type = "application/json") => new Response(JSON.stringify(body), { status, headers: { "content-type": type } });

  const fetch = (async (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers);
    const body = String(init.body ?? "");
    sent.push({ path, body, vault: headers.get("x-vault-authorization") });
    if (path === "/api/v1/vault/prelogin") return json({ kdf: 0, kdfIterations: ITERATIONS, kdfMemory: null, kdfParallelism: null });
    if (path === "/api/v1/vault/token") {
      const form = new URLSearchParams(body);
      if (form.get("grant_type") === "refresh_token") return json({ access_token: "access-2" });
      if (form.get("password") !== hash) return json({ message: "Username or password is incorrect. Try again" }, 400);
      if (twoFactor && form.get("two_factor_token") !== "123456")
        return json({ error: "invalid_grant", error_description: "Two factor required.", TwoFactorProviders: ["0"], TwoFactorProviders2: { "0": null } }, 400);
      const stretched = Buffer.concat([expand(master, "enc"), expand(master, "mac")]);
      return json({ access_token: "access-1", refresh_token: "refresh-1", Key: aes(stretched, user), PrivateKey: "ignored" });
    }
    const vault = headers.get("x-vault-authorization");
    if (vault !== "Bearer access-1" && vault !== "Bearer access-2") return json({ message: "Invalid claim" }, 401);
    if (path === "/api/v1/vault/sync") {
      if (expired && vault === "Bearer access-1") return json({ message: "Token expired" }, 401);
      return json({
        profile: {
          privateKey: aes(user, pair.privateKey.export({ type: "pkcs8", format: "der" })),
          organizations: [
            {
              id: ORG,
              type: 1,
              key: `4.${publicEncrypt({ key: pair.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, org).toString("base64")}`,
            },
          ],
        },
        ciphers: [
          {
            id: "bank",
            type: 1,
            organizationId: ORG,
            collectionIds: ["col-finance"],
            key: aes(org, itemKey),
            name: aes(itemKey, "Corporate banking"),
            notes: null,
            login: {
              username: aes(itemKey, "acme-treasury"),
              password: aes(itemKey, "hT9#vQ2m!xR4-Lp7w"),
              totp: aes(itemKey, "JBSWY3DPEHPK3PXP"),
              uris: [{ uri: aes(itemKey, "https://business.bank.example") }],
              passwordRevisionDate: "2026-03-14T10:00:00Z",
            },
            passwordHistory: [{ password: "x" }, { password: "y" }, { password: "z" }],
            revisionDate: "2026-03-14T10:00:00Z",
            creationDate: "2025-01-02T10:00:00Z",
            edit: true,
            viewPassword: true,
          },
          {
            id: "card",
            type: 3,
            organizationId: null,
            collectionIds: [],
            name: aes(user, "Company card, travel"),
            card: { number: aes(user, "4111111111114421"), expMonth: aes(user, "7"), expYear: aes(user, "2029") },
            revisionDate: "2026-07-01T00:00:00Z",
          },
          { id: "broken", type: 2, organizationId: ORG, collectionIds: [], name: "2.AAAA|AAAA|AAAA", revisionDate: "2026-07-01T00:00:00Z" },
        ],
        collections: [
          { id: "col-finance", organizationId: ORG, name: aes(org, "Finance"), externalId: "finance", readOnly: false, hidePasswords: false, manage: true },
        ],
      });
    }
    if (path === "/api/v1/vault/organization/public-keys")
      return json({
        data: [
          { id: "m-1", key: member.publicKey.export({ type: "spki", format: "der" }).toString("base64") },
          { id: "m-2", key: null },
        ],
      });
    if (path === "/api/v1/vault/organization/confirm")
      return json({ data: (JSON.parse(body).keys as Array<{ id: string }>).map((k) => ({ id: k.id, error: "" })) });
    if (path === "/api/v1/vault/organization/collections") return json({ id: "col-sales" });
    if (path === "/api/v1/vault/events") return new Response("{}", { headers: { "content-type": "application/json" } });
    return json({}, 404);
  }) as unknown as typeof globalThis.fetch;
  return {
    fetch,
    sent,
    org,
    member,
    expire: () => (expired = true),
  };
}
