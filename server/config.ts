// The company's shared vaults, who may see or change each, and the organization's policies, from one YAML file
// (PASSWORDS_CONFIG). As with the install's other files, the file is the only way in: no screen or API route adds,
// changes or removes a vault, an access or a policy. It is applied whole or not at all, read again within a minute of a
// change, and a file with a mistake leaves the last good version in place.
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { parse } from "yaml";

/** What a group may do in a vault: read its items, also change them, or also manage the vault in the Bitwarden apps. */
export type Access = "read" | "edit" | "manage";
export const ACCESS: Access[] = ["read", "edit", "manage"];

export interface Vault {
  /** Stable, lowercase; the collection's external id in Vaultwarden, so a vault keeps its items when its name changes. */
  id: string;
  /** The name people see. Vaultwarden keeps it encrypted, so it is set from an admin's browser, never by the server. */
  name: string;
  /** Identity groups and what their members may do, in the order of the file. */
  access: Array<{ group: string; access: Access }>;
}

export interface MasterPasswordPolicy {
  minLength: number;
  /** 0 to 4, the score the Bitwarden apps compute; 0 for none. */
  minComplexity: number;
  requireUpper: boolean;
  requireLower: boolean;
  requireNumbers: boolean;
  requireSpecial: boolean;
}

export interface GeneratorPolicy {
  minLength: number;
  useUpper: boolean;
  useLower: boolean;
  useNumbers: boolean;
  useSpecial: boolean;
}

/** The organization policies Passwords keeps; each one the file leaves out is off. */
export interface Policies {
  /** Members must use two-step login in Vaultwarden. Turning it on revokes members who have none until they add it. */
  twoStepLogin: boolean;
  masterPassword: MasterPasswordPolicy | null;
  passwordGenerator: GeneratorPolicy | null;
  /** Members may not make Bitwarden Sends. */
  disableSend: boolean;
}

export interface PasswordsConfig {
  vaults: Vault[];
  policies: Policies;
}

const ID = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const TOP_KEYS = ["vaults", "policies"];
const VAULT_KEYS = ["id", "name", "access"];
const POLICY_KEYS = ["twoStepLogin", "masterPassword", "passwordGenerator", "disableSend"];
const MASTER_KEYS = ["minLength", "minComplexity", "requireUpper", "requireLower", "requireNumbers", "requireSpecial"];
const GENERATOR_KEYS = ["minLength", "useUpper", "useLower", "useNumbers", "useSpecial"];
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

export const NO_POLICIES: Policies = { twoStepLogin: false, masterPassword: null, passwordGenerator: null, disableSend: false };

function keys(v: Record<string, unknown>, allowed: string[], at: string, what: string) {
  const extra = Object.keys(v).filter((k) => !allowed.includes(k));
  if (extra.length) throw new Error(`${at}: unknown ${extra.join(", ")}; ${what} takes ${allowed.join(", ")}.`);
}

function bool(v: unknown, at: string): boolean {
  if (v === undefined) return false;
  if (typeof v !== "boolean") throw new Error(`${at} is true or false.`);
  return v;
}

function int(v: unknown, at: string, min: number, max: number, fallback: number): number {
  if (v === undefined) return fallback;
  if (!Number.isInteger(v) || (v as number) < min || (v as number) > max) throw new Error(`${at} is a whole number from ${min} to ${max}.`);
  return v as number;
}

function policies(v: unknown): Policies {
  if (v === undefined || v === null) return NO_POLICIES;
  if (!isObj(v)) throw new Error("policies must be a map, such as twoStepLogin: true.");
  if ("accountRecovery" in v)
    throw new Error("policies.accountRecovery cannot be set: Passwords keeps it off, so an admin never recovers a person's own vault.");
  keys(v, POLICY_KEYS, "policies", "it");
  const master = v.masterPassword;
  const gen = v.passwordGenerator;
  if (master !== undefined && master !== false && !isObj(master)) throw new Error("policies.masterPassword is a map, such as { minLength: 14 }, or false.");
  if (gen !== undefined && gen !== false && !isObj(gen)) throw new Error("policies.passwordGenerator is a map, such as { minLength: 20 }, or false.");
  if (isObj(master)) keys(master, MASTER_KEYS, "policies.masterPassword", "it");
  if (isObj(gen)) keys(gen, GENERATOR_KEYS, "policies.passwordGenerator", "it");
  return {
    twoStepLogin: bool(v.twoStepLogin, "policies.twoStepLogin"),
    masterPassword: isObj(master)
      ? {
          minLength: int(master.minLength, "policies.masterPassword.minLength", 8, 128, 12),
          minComplexity: int(master.minComplexity, "policies.masterPassword.minComplexity", 0, 4, 0),
          requireUpper: bool(master.requireUpper, "policies.masterPassword.requireUpper"),
          requireLower: bool(master.requireLower, "policies.masterPassword.requireLower"),
          requireNumbers: bool(master.requireNumbers, "policies.masterPassword.requireNumbers"),
          requireSpecial: bool(master.requireSpecial, "policies.masterPassword.requireSpecial"),
        }
      : null,
    passwordGenerator: isObj(gen)
      ? {
          minLength: int(gen.minLength, "policies.passwordGenerator.minLength", 5, 128, 14),
          useUpper: bool(gen.useUpper, "policies.passwordGenerator.useUpper"),
          useLower: bool(gen.useLower, "policies.passwordGenerator.useLower"),
          useNumbers: bool(gen.useNumbers, "policies.passwordGenerator.useNumbers"),
          useSpecial: bool(gen.useSpecial, "policies.passwordGenerator.useSpecial"),
        }
      : null,
    disableSend: bool(v.disableSend, "policies.disableSend"),
  };
}

/** Reads the file's text. Throws with the vault and field at fault, so one message says what to fix. */
export function parseConfig(text: string): PasswordsConfig {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (err) {
    throw new Error(`Not valid YAML: ${(err as Error).message.split("\n")[0]}`);
  }
  if (doc === null || doc === undefined) return { vaults: [], policies: NO_POLICIES };
  if (!isObj(doc)) throw new Error("The file holds vaults: and policies:, and nothing else.");
  keys(doc, TOP_KEYS, "The file", "it");
  const list = doc.vaults ?? [];
  if (!Array.isArray(list)) throw new Error("vaults must be a list.");
  if (list.length > 500) throw new Error("vaults holds at most 500 entries.");

  const ids = new Set<string>();
  const names = new Map<string, string>();
  const vaults = list.map((v: unknown, i): Vault => {
    const id = isObj(v) && typeof v.id === "string" ? v.id.trim() : "";
    if (!ID.test(id)) throw new Error(`vaults[${i}].id is required: lowercase letters, digits and dashes, such as finance.`);
    if (ids.has(id)) throw new Error(`vaults[${i}].id: ${id} is in the file twice.`);
    ids.add(id);
    const at = `vaults[${i}] (${id})`;
    const vault = v as Record<string, unknown>;
    keys(vault, VAULT_KEYS, at, "a vault");
    if (typeof vault.name !== "string" || !vault.name.trim() || vault.name.trim().length > 100)
      throw new Error(`${at}.name is required, up to 100 characters.`);
    const name = vault.name.trim();
    const was = names.get(name.toLowerCase());
    if (was) throw new Error(`${at}.name: ${name} is already the name of ${was}.`);
    names.set(name.toLowerCase(), id);
    const access = vault.access ?? {};
    if (!isObj(access)) throw new Error(`${at}.access is a map of Identity groups to read, edit or manage, such as { finance: edit }.`);
    if (Object.keys(access).length > 50) throw new Error(`${at}.access names at most 50 groups.`);
    return {
      id,
      name,
      access: Object.entries(access).map(([group, a]) => {
        if (!group.trim() || group.length > 128) throw new Error(`${at}.access: a group name is 1 to 128 characters.`);
        if (!ACCESS.includes(a as Access)) throw new Error(`${at}.access.${group} is read, edit or manage.`);
        return { group: group.trim(), access: a as Access };
      }),
    };
  });
  return { vaults, policies: policies(doc.policies) };
}

/** Every Identity group the file names, once, in the order they first appear. */
export function groupsOf(config: PasswordsConfig): string[] {
  return [...new Set(config.vaults.flatMap((v) => v.access.map((a) => a.group)))];
}

export interface ConfigFileState {
  path: string;
  /** When the file was last read and applied, or null if it never was. */
  appliedAt: string | null;
  vaults: number;
  groups: number;
  /** Why the file on disk is not what is applied; the last good version stays until it is fixed. */
  error: string | null;
}

/**
 * Reads the file now and whenever it changes (checked every `everyMs`, by size, time and content), and hands each new
 * version to `apply`. A file that cannot be read or parsed leaves the last good version in place. `stop()` ends the
 * polling.
 */
export function watchConfig(
  path: string,
  apply: (config: PasswordsConfig) => void,
  { everyMs = 60_000, onChange }: { everyMs?: number; onChange?: (state: ConfigFileState) => void } = {},
) {
  const state: ConfigFileState = { path, appliedAt: null, vaults: 0, groups: 0, error: null };
  let seen = "";
  const read = () => {
    let text: string;
    let stamp: string;
    try {
      const st = statSync(path);
      text = readFileSync(path, "utf8");
      stamp = `${st.size}:${st.mtimeMs}:${createHash("sha256").update(text).digest("hex")}`;
    } catch (err) {
      const error = `Cannot read ${path}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`;
      if (state.error !== error) ((state.error = error), onChange?.(state));
      return;
    }
    if (stamp === seen) return;
    seen = stamp;
    try {
      const config = parseConfig(text);
      apply(config);
      Object.assign(state, { appliedAt: new Date().toISOString(), vaults: config.vaults.length, groups: groupsOf(config).length, error: null });
    } catch (err) {
      state.error = (err as Error).message;
    }
    onChange?.(state);
  };
  read();
  const timer = setInterval(read, everyMs);
  timer.unref();
  return { state, read, stop: () => clearInterval(timer) };
}
