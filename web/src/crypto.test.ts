// The client encryption against known values, then against an account built with Node's own crypto, a second and
// independent implementation of the same steps. The known values are from Bitwarden's client test suite
// (bitwarden/jslib, common/spec/web/services/webCryptoFunction.service.spec.ts) and RFC 9106.
import { argon2Sync, constants, createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, privateDecrypt, publicEncrypt, randomBytes } from "node:crypto";
import { argon2id } from "hash-wasm";
import { describe, expect, it } from "vitest";
import {
  b64,
  decrypt,
  decryptText,
  encryptText,
  hex,
  hkdfExpand,
  hmac,
  masterKey,
  masterPasswordHash,
  rsaDecrypt,
  rsaEncrypt,
  stretch,
  symmetricKey,
  userKey,
} from "./crypto.ts";

const utf8 = new TextEncoder();
const staticBytes = (n: number) => Uint8Array.from({ length: n }, (_, i) => i);

// From jslib's spec: an RSA-2048 key and "EncryptMe!" encrypted to it with OAEP-SHA1.
const RSA_PRIVATE =
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXRVrCX+2hfOQS8HzYUS2oc/jGVTZpv+/Ryuoh9d8ihYX9dd0cYh2tl6KWdFc88lPUH11Oxqy20Rk2e5r/RF6T9yM0Me3NPnaKt+hlhLtfoc0h86L" +
  "nhD56A9FDUfuI0dVnPcrwNv0YJIo94LwxtbqBULNvXl6wJ7WAbODrCQy5ZgMVg+iH+gGpwiqsZqHt+KuoHWcN53MSPDfaF4/YMB99U3TziJMOOJask1TEEnakMPln11PczNDazT17DXIxYrbPfutPdh6sLs6AQOajdZijfEvepgnOe7cQ7aeatiOJFrjTApK" +
  "PGxOVRzEMX4XS4xbyhH0QxQeB6l16l8C0uxIBAgMBAAECggEASaWfeVDA3cVzOPFSpvJm20OTE+R6uGOU+7vh36TX/POq92qBuwbd0h0oMD32FxsXywd2IxtBDUSiFM9699qufTVuM0Q3tZw6lHDTOVG08+tPdr8qSbMtw7PGFxN79fHLBxejjO4IrM9lapj" +
  "WpxEF+11x7r+wM+0xRZQ8sNFYG46aPfIaty4BGbL0I2DQ2y8I57iBCAy69eht59NLMm27fRWGJIWCuBIjlpfzET1j2HLXUIh5bTBNzqaN039WH49HczGE3mQKVEJZc/efk3HaVd0a1Sjzyn0QY+N1jtZN3jTRbuDWA1AknkX1LX/0tUhuS3/7C3ejHxjw4Dk" +
  "1ZLo5/QKBgQDIWvqFn0+IKRSu6Ua2hDsufIHHUNLelbfLUMmFthxabcUn4zlvIscJO00Tq/ezopSRRvbGiqnxjv/mYxucvOUBeZtlus0Q9RTACBtw9TGoNTmQbEunJ2FOSlqbQxkBBAjgGEppRPt30iGj/VjAhCATq2MYOa/X4dVR51BqQAFIEwKBgQDBSIf" +
  "TFKC/hDk6FKZlgwvupWYJyU9RkyfstPErZFmzoKhPkQ3YORo2oeAYmVUbS9I2iIYpYpYQJHX8jMuCbCz4ONxTCuSIXYQYUcUq4PglCKp31xBAE6TN8SvhfME9/MvuDssnQinAHuF0GDAhF646T3LLS1not6Vszv7brwSoGwKBgQC88v/8cGfi80ssQZeMnVv" +
  "q1UTXIeQcQnoY5lGHJl3K8mbS3TnXE6c9j417Fdz+rj8KWzBzwWXQB5pSPflWcdZO886Xu/mVGmy9RWgLuVFhXwCwsVEPjNX5ramRb0/vY0yzenUCninBsIxFSbIfrPtLUYCc4hpxr+sr2Mg/y6jpvQKBgBezMRRs3xkcuXepuI2R+BCXL1/b02IJTUf1F+1" +
  "eLLGd7YV0H+J3fgNc7gGWK51hOrF9JBZHBGeOUPlaukmPwiPdtQZpu4QNE3l37VlIpKTF30E6mb+BqR+nht3rUjarnMXgAoEZ18y6/KIjpSMpqC92Nnk/EBM9EYe6Cf4eA9ApAoGAeqEUg46UTlJySkBKURGpIs3v1kkf5I0X8DnOhwb+HPxNaiEdmO7ckm8" +
  "+tPVgppLcG0+tMdLjigFQiDUQk2y3WjyxP5ZvXu7U96jaJRI8PFMoE06WeVYcdIzrID2HvqH+w0UQJFrLJ/0Mn4stFAEzXKZBokBGnjFnTnKcs7nv/O8=";
const RSA_ENCRYPTED =
  "A1/p8BQzN9UrbdYxUY2Va5+kPLyfZXF9JsZrjeEXcaclsnHurdxVAJcnbEqYMP3UXV4YAS/mpf+Rxe6/X0WS1boQdA0MAHSgx95hIlAraZYpiMLLiJRKeo2u8YivCdTM9V5vuAEJwf9Tof/qFsFci3sApdbATkorCT" +
  "zFOIEPF2S1zgperEP23M01mr4dWVdYN18B32YF67xdJHMbFhp5dkQwv9CmscoWq7OE5HIfOb+JAh7BEZb+CmKhM3yWJvoR/D/5jcercUtK2o+XrzNrL4UQ7yLZcFz6Bfwb/j6ICYvqd/YJwXNE6dwlL57OfwJyCdw2rRYf0/qI00t9u8Iitw==";

describe("known values", () => {
  it("derives the master key with PBKDF2-SHA256 as Bitwarden's clients do", async () => {
    const pbkdf2 = { kdf: 0, iterations: 5000, memory: null, parallelism: null };
    expect(b64.encode(await masterKey("password", "user@example.com", pbkdf2))).toBe("pj9prw/OHPleXI6bRdmlaD+saJS4awrMiQsQiDjeu2I=");
    expect(b64.encode(await masterKey("pǻssword", "üser@example.com", pbkdf2))).toBe("yqvoFXgMRmHR3QPYr5pyR4uVuoHkltv9aHUP63p8n7I=");
    expect(b64.encode(await masterKey("😀password🙏", " User@Example.com ", pbkdf2))).toBe("ZdeOata6xoRpB4DLp8zHhXz5kLmkWtX5pd+TdRH8w8w=");
  });

  it("expands keys with HKDF-Expand-SHA256", async () => {
    const prk = b64.decode("F5h4KdYQnIVH4rKH0P9CZb1GrR4n16/sJrS0PsQEn0Y=");
    expect(b64.encode(await hkdfExpand(prk, "info", 32))).toBe("BnIqJlfnHm0e/2iB/15cbHyR19ARPIcWRp4oNS22CD8=");
    expect(b64.encode(await hkdfExpand(prk, "info", 64))).toBe("BnIqJlfnHm0e/2iB/15cbHyR19ARPIcWRp4oNS22CD9BV+/queOZenPNkDhmlVyL2WZ3OSU5+7ISNF5NhNfvZA==");
    await expect(hkdfExpand(b64.decode("criAmKtfzxanbgea5/kelQ=="), "info", 32)).rejects.toThrow("prk is too small.");
  });

  it("signs with HMAC-SHA256", async () => {
    expect(hex(await hmac(utf8.encode("secretkey"), utf8.encode("SignMe!!")))).toBe("6be3caa84922e12aaaaa2f16c40d44433bb081ef323db584eb616333ab4e874f");
  });

  it("decrypts AES-256-CBC", async () => {
    const key = await symmetricKey(staticBytes(32));
    expect(await decryptText(`0.${b64.encode(staticBytes(16))}|ByUF8vhyX4ddU9gcooznwA==`, key)).toBe("EncryptMe!");
  });

  it("decrypts RSA-OAEP-SHA1, the type 4 EncString of organization keys", async () => {
    expect(new TextDecoder().decode(await rsaDecrypt(`4.${RSA_ENCRYPTED}`, b64.decode(RSA_PRIVATE)))).toBe("EncryptMe!");
  });

  it("computes Argon2id as RFC 9106 and Node do", async () => {
    // RFC 9106, 5.3: the Argon2id test vector, through Node's implementation (hash-wasm takes no associated data).
    const rfc = argon2Sync("argon2id", {
      message: Buffer.alloc(32, 1),
      nonce: Buffer.alloc(16, 2),
      secret: Buffer.alloc(8, 3),
      associatedData: Buffer.alloc(12, 4),
      passes: 3,
      memory: 32,
      parallelism: 4,
      tagLength: 32,
    });
    expect(rfc.toString("hex")).toBe("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    // hash-wasm, which the browser runs, gives what Node gives.
    const params = { iterations: 2, memorySize: 65536, parallelism: 4, hashLength: 24 };
    const wasm = await argon2id({ password: "password", salt: "somesalt", ...params, outputType: "hex" });
    const node = argon2Sync("argon2id", { message: "password", nonce: "somesalt", passes: 2, memory: 65536, parallelism: 4, tagLength: 24 });
    expect(wasm).toBe(node.toString("hex"));
    expect(wasm).toBe("1758c6d82577fcdafec91b88b0f2b0d09f6be2cedc247054");
  });
});

/** An account as Vaultwarden stores it, made with Node's crypto: what the browser gets after signing in. */
function account(password: string, email: string, iterations: number) {
  const aes = (key: Buffer, data: Buffer) => {
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
  const master = pbkdf2Sync(password, email, iterations, 32, "sha256");
  const stretched = Buffer.concat([expand(master, "enc"), expand(master, "mac")]);
  const user = randomBytes(64);
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pkcs8 = pair.privateKey.export({ type: "pkcs8", format: "der" });
  const spki = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const org = randomBytes(64);
  const itemKey = randomBytes(64);
  return {
    master,
    hash: pbkdf2Sync(master, password, 1, 32, "sha256").toString("base64"),
    key: aes(stretched, user),
    privateKey: aes(user, pkcs8),
    publicKey: spki,
    pair,
    org,
    orgKey: `4.${publicEncrypt({ key: pair.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, org).toString("base64")}`,
    item: { key: aes(org, itemKey), name: aes(itemKey, Buffer.from("Corporate banking")) },
  };
}

describe("unlocking an account", () => {
  const a = account("correct horse battery staple", "emily.clark@example.com", 600000);

  it("derives the same master key and password hash as Node, and opens the user key", async () => {
    const mk = await masterKey("correct horse battery staple", "Emily.Clark@example.com", { kdf: 0, iterations: 600000, memory: null, parallelism: null });
    expect(b64.encode(mk)).toBe(a.master.toString("base64"));
    expect(await masterPasswordHash(mk, "correct horse battery staple")).toBe(a.hash);
    const uk = await userKey(a.key, mk);
    expect(uk.length).toBe(64);
    const pkcs8 = await decrypt(a.privateKey, await symmetricKey(uk));
    const org = await rsaDecrypt(a.orgKey, pkcs8);
    expect(b64.encode(org)).toBe(a.org.toString("base64"));
    const itemKey = await symmetricKey(await decrypt(a.item.key, await symmetricKey(org)));
    expect(await decryptText(a.item.name, itemKey)).toBe("Corporate banking");
  });

  it("refuses a wrong master password and a changed value", async () => {
    const wrong = await masterKey("wrong", "emily.clark@example.com", { kdf: 0, iterations: 5000, memory: null, parallelism: null });
    await expect(userKey(a.key, wrong)).rejects.toThrow("The master password is not right.");
    const [head, ct, mac] = a.item.name.split("|");
    const flipped = `${head}|${ct!.slice(0, -4)}AAA=|${mac}`;
    const key = await symmetricKey(new Uint8Array(await decrypt(a.item.key, await symmetricKey(new Uint8Array(a.org)))));
    await expect(decrypt(flipped, key)).rejects.toThrow(/MAC/);
  });

  it("derives the master key with Argon2id over the email's SHA-256, as Node does", async () => {
    const kdf = { kdf: 1, iterations: 3, memory: 16, parallelism: 2 };
    const mk = await masterKey("pass phrase", "Emily.Clark@example.com", kdf);
    const salt = await globalThis.crypto.subtle.digest("SHA-256", utf8.encode("emily.clark@example.com"));
    const node = argon2Sync("argon2id", { message: "pass phrase", nonce: Buffer.from(salt), passes: 3, memory: 16 * 1024, parallelism: 2, tagLength: 32 });
    expect(b64.encode(mk)).toBe(node.toString("base64"));
  });

  it("stretches the master key as Node's HMAC does", async () => {
    const key = await stretch(new Uint8Array(a.master));
    // The stretched key opens what Node encrypted with it: the user key.
    expect((await decrypt(a.key, key)).length).toBe(64);
  });

  it("encrypts a vault name the organization key opens, and gives the key to a member's public key", async () => {
    const org = await symmetricKey(new Uint8Array(a.org));
    const name = await encryptText("Finance", org);
    expect(name).toMatch(/^2\.[^|]+\|[^|]+\|[^|]+$/);
    expect(await decryptText(name, org)).toBe("Finance");
    const given = await rsaEncrypt(new Uint8Array(a.org), a.publicKey);
    const back = privateDecrypt({ key: a.pair.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1" }, Buffer.from(given.slice(2), "base64"));
    expect(back.equals(a.org)).toBe(true);
  });
});
