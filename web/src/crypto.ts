// Bitwarden's client encryption, as its documentation and security whitepaper describe it, with WebCrypto only (and
// hash-wasm for Argon2id). It runs in the person's browser and nowhere else: the master password, the master key, the
// user key, the private key and every decrypted item stay in this page's memory and are never sent anywhere.
//
//   master key        = PBKDF2-SHA256(password, email, iterations)  or  Argon2id(password, SHA-256(email), t, m, p)
//   master pass. hash = PBKDF2-SHA256(master key, password, 1)       what Vaultwarden checks at sign-in
//   stretched key     = HKDF-Expand-SHA256(master key, "enc", 32) ‖ HKDF-Expand-SHA256(master key, "mac", 32)
//   user key          = decrypt(stretched key, the account's Key)    64 bytes: AES-256 key ‖ HMAC-SHA256 key
//   private key       = decrypt(user key, the account's PrivateKey)  PKCS#8 RSA-2048
//   organization key  = RSA-OAEP-SHA1 decrypt(private key, the membership's key)
//   item key          = decrypt(user or organization key, the item's key), when the item has one
//
// EncStrings are "<type>.<base64>|...": type 2 is AES-256-CBC with HMAC-SHA256 over iv ‖ ciphertext, checked before
// anything is decrypted; type 0 is the old AES-256-CBC without a MAC; types 3 and 4 are RSA-OAEP with SHA-256 and SHA-1.
import { argon2id } from "hash-wasm";

const subtle = () => globalThis.crypto.subtle;
const utf8 = new TextEncoder();
const text = new TextDecoder();

export const b64 = {
  decode(s: string): Uint8Array<ArrayBuffer> {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
  encode(u: Uint8Array): string {
    let bin = "";
    for (let i = 0; i < u.length; i += 0x8000) bin += String.fromCharCode(...u.subarray(i, i + 0x8000));
    return btoa(bin);
  },
};

export const hex = (u: Uint8Array) => [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

export class CryptoError extends Error {}

/** Bitwarden's key derivation settings, as prelogin returns them. */
export interface Kdf {
  /** 0 PBKDF2-SHA256, 1 Argon2id. */
  kdf: number;
  iterations: number;
  /** Argon2id memory in MiB. */
  memory: number | null;
  parallelism: number | null;
}

export async function pbkdf2(
  password: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
  bytes = 32,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await subtle().importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle().deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, bytes * 8));
}

export async function sha256(data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await subtle().digest("SHA-256", data));
}

export async function hmac(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const k = await subtle().importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle().sign("HMAC", k, data));
}

/** HKDF's expand step only (RFC 5869, 2.3): Bitwarden stretches a key that is already uniform. */
export async function hkdfExpand(prk: Uint8Array<ArrayBuffer>, info: string, length: number): Promise<Uint8Array<ArrayBuffer>> {
  if (prk.length < 32) throw new CryptoError("prk is too small.");
  if (length > 255 * 32) throw new CryptoError("outputByteSize is too large.");
  const infoBytes = utf8.encode(info);
  const out = new Uint8Array(length);
  let previous = new Uint8Array(0);
  for (let i = 0, at = 0; at < length; i++) {
    const input = new Uint8Array(previous.length + infoBytes.length + 1);
    input.set(previous);
    input.set(infoBytes, previous.length);
    input[input.length - 1] = i + 1;
    previous = await hmac(prk, input);
    out.set(previous.subarray(0, Math.min(32, length - at)), at);
    at += 32;
  }
  return out;
}

/** The master key, from the master password and the person's email, the salt. */
export async function masterKey(password: string, email: string, kdf: Kdf): Promise<Uint8Array<ArrayBuffer>> {
  const salt = utf8.encode(email.trim().toLowerCase());
  if (kdf.kdf === 0) {
    if (kdf.iterations < 5000) throw new CryptoError("PBKDF2 needs at least 5000 iterations.");
    return pbkdf2(utf8.encode(password), salt, kdf.iterations);
  }
  if (kdf.kdf === 1) {
    if (!kdf.memory || !kdf.parallelism || kdf.iterations < 1) throw new CryptoError("Argon2id needs iterations, memory and parallelism.");
    const out = await argon2id({
      password: utf8.encode(password),
      salt: await sha256(salt),
      iterations: kdf.iterations,
      memorySize: kdf.memory * 1024,
      parallelism: kdf.parallelism,
      hashLength: 32,
      outputType: "binary",
    });
    return new Uint8Array(out);
  }
  throw new CryptoError(`Unknown key derivation ${kdf.kdf}.`);
}

/** What Vaultwarden checks at sign-in; it proves the password without giving the master key away. */
export async function masterPasswordHash(key: Uint8Array<ArrayBuffer>, password: string): Promise<string> {
  return b64.encode(await pbkdf2(key, utf8.encode(password), 1));
}

/** An AES-256-CBC key with its HMAC-SHA256 key, as WebCrypto keys that cannot be read back. */
export interface SymmetricKey {
  enc: CryptoKey;
  mac: CryptoKey | null;
}

/** 64 bytes are a key and its MAC key; 32 bytes are an old key without one. */
export async function symmetricKey(raw: Uint8Array<ArrayBuffer>, extractable = false): Promise<SymmetricKey> {
  if (raw.length !== 64 && raw.length !== 32) throw new CryptoError(`A key is 32 or 64 bytes, not ${raw.length}.`);
  const enc = await subtle().importKey("raw", raw.slice(0, 32), { name: "AES-CBC" }, extractable, ["encrypt", "decrypt"]);
  const mac = raw.length === 64 ? await subtle().importKey("raw", raw.slice(32), { name: "HMAC", hash: "SHA-256" }, extractable, ["sign", "verify"]) : null;
  return { enc, mac };
}

/** The key that decrypts the user key: the master key stretched to an encryption and a MAC key. */
export async function stretch(key: Uint8Array<ArrayBuffer>): Promise<SymmetricKey> {
  const raw = new Uint8Array(64);
  raw.set(await hkdfExpand(key, "enc", 32));
  raw.set(await hkdfExpand(key, "mac", 32), 32);
  return symmetricKey(raw);
}

export interface EncString {
  type: number;
  iv?: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
  mac?: Uint8Array<ArrayBuffer>;
}

export function parseEncString(s: string): EncString {
  const dot = s.indexOf(".");
  const type = dot > 0 ? Number(s.slice(0, dot)) : NaN;
  const parts = s.slice(dot + 1).split("|");
  if (type === 0 && parts.length >= 2) return { type, iv: b64.decode(parts[0]!), data: b64.decode(parts[1]!) };
  if (type === 2 && parts.length === 3) return { type, iv: b64.decode(parts[0]!), data: b64.decode(parts[1]!), mac: b64.decode(parts[2]!) };
  if ((type === 3 || type === 4 || type === 5 || type === 6) && parts.length >= 1) return { type, data: b64.decode(parts[0]!) };
  if (type === 7) throw new CryptoError("This item uses Bitwarden's newer encryption (COSE), which Passwords cannot open yet; use a Bitwarden app.");
  throw new CryptoError("Not an encrypted value Passwords knows.");
}

export async function decrypt(s: string, key: SymmetricKey): Promise<Uint8Array<ArrayBuffer>> {
  const e = parseEncString(s);
  if (e.type === 2) {
    if (!key.mac) throw new CryptoError("This value needs a key with a MAC.");
    const signed = new Uint8Array(e.iv!.length + e.data.length);
    signed.set(e.iv!);
    signed.set(e.data, e.iv!.length);
    // The MAC is checked before decrypting, so a value someone changed is refused, not decrypted.
    if (!(await subtle().verify("HMAC", key.mac, e.mac!, signed)))
      throw new CryptoError("The value does not match its MAC: it was changed or the key is wrong.");
  } else if (e.type !== 0) {
    throw new CryptoError(`A symmetric key cannot open a value of type ${e.type}.`);
  }
  try {
    return new Uint8Array(await subtle().decrypt({ name: "AES-CBC", iv: e.iv! }, key.enc, e.data));
  } catch {
    throw new CryptoError("The value cannot be decrypted with this key.");
  }
}

export const decryptText = async (s: string, key: SymmetricKey) => text.decode(await decrypt(s, key));

/** A type 2 EncString, with a random IV; used for the name of a vault an admin creates. */
export async function encrypt(data: Uint8Array<ArrayBuffer>, key: SymmetricKey): Promise<string> {
  if (!key.mac) throw new CryptoError("Encrypting needs a key with a MAC.");
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const ct = new Uint8Array(await subtle().encrypt({ name: "AES-CBC", iv }, key.enc, data));
  const signed = new Uint8Array(iv.length + ct.length);
  signed.set(iv);
  signed.set(ct, iv.length);
  const mac = new Uint8Array(await subtle().sign("HMAC", key.mac, signed));
  return `2.${b64.encode(iv)}|${b64.encode(ct)}|${b64.encode(mac)}`;
}

export const encryptText = (s: string, key: SymmetricKey) => encrypt(utf8.encode(s), key);

/** The person's private key, from its PKCS#8 bytes; it only ever decrypts. */
export async function privateKey(pkcs8: Uint8Array<ArrayBuffer>, hash: "SHA-1" | "SHA-256" = "SHA-1"): Promise<CryptoKey> {
  return subtle().importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash }, false, ["decrypt"]);
}

/** Decrypts an RSA EncString (type 4 or 6 with SHA-1, 3 or 5 with SHA-256) with the person's PKCS#8 private key. */
export async function rsaDecrypt(s: string, pkcs8: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const e = parseEncString(s);
  if (e.type < 3 || e.type > 6) throw new CryptoError(`A private key cannot open a value of type ${e.type}.`);
  const key = await privateKey(pkcs8, e.type === 3 || e.type === 5 ? "SHA-256" : "SHA-1");
  try {
    return new Uint8Array(await subtle().decrypt({ name: "RSA-OAEP" }, key, e.data));
  } catch {
    throw new CryptoError("The value cannot be decrypted with this private key.");
  }
}

/** Encrypts to a member's public key (SPKI, base64), as a type 4 EncString: how the organization key is given. */
export async function rsaEncrypt(data: Uint8Array<ArrayBuffer>, publicKeyB64: string): Promise<string> {
  const key = await subtle().importKey("spki", b64.decode(publicKeyB64), { name: "RSA-OAEP", hash: "SHA-1" }, false, ["encrypt"]);
  return `4.${b64.encode(new Uint8Array(await subtle().encrypt({ name: "RSA-OAEP" }, key, data)))}`;
}

/**
 * The user key from the account's encrypted Key: a type 2 Key is opened with the stretched master key, an old type 0
 * Key with the master key itself.
 */
export async function userKey(encryptedKey: string, master: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const type = parseEncString(encryptedKey).type;
  const key = type === 0 ? await symmetricKey(master) : await stretch(master);
  try {
    return await decrypt(encryptedKey, key);
  } catch {
    throw new CryptoError("The master password is not right.");
  }
}
