// Makes Vaultwarden's organization match the file and Identity:
//
// 1. Members and groups go in through the directory import: everyone Identity lists as active or invited and in a group
//    the file names is a member, each such group is a Vaultwarden group with those members, and, with
//    overwriteExisting, members Identity no longer lists that way are removed at once. Members added by hand in
//    Vaultwarden (no external id) and owners are never removed.
// 2. Each vault of the file is the collection whose external id is the vault's id. The groups that see it, and how, are
//    set from the file; members given it directly are taken off. A vault with no collection yet is reported: its name
//    must be encrypted with the organization's key, so an admin's browser creates it.
// 3. The policies the file sets are applied; account recovery is kept off.
//
// A collection is never deleted, and collections the file does not name are left alone.
import { groupsOf, type Access, type PasswordsConfig, type Policies } from "./config.ts";
import type { Person } from "./identity.ts";
import type { CollectionAccess, ImportPayload, Vaultwarden, VwCollection, VwGroup, VwItem, VwMember, VwPolicy } from "./vaultwarden.ts";

export interface SyncResult {
  at: string;
  ok: boolean;
  /** Emails that became members. */
  added: string[];
  /** Emails removed from the organization. */
  removed: string[];
  /** Vault ids whose access was set again. */
  vaults: string[];
  /** Vault ids that have no collection in Vaultwarden yet. */
  missing: string[];
  /** Policies turned on, off or changed, by name. */
  policies: string[];
  /** What was left as it is, and why. */
  notes: string[];
  error: string | null;
}

/** What Vaultwarden holds after a sync, kept for the pages until the next one. */
export interface OrgState {
  members: VwMember[];
  groups: VwGroup[];
  collections: VwCollection[];
  items: VwItem[];
  features: { email: string; groups: boolean; events: boolean };
}

/** Bitwarden policy types (Vaultwarden's OrgPolicyType). */
export const POLICY = { twoStepLogin: 0, masterPassword: 1, passwordGenerator: 2, disableSend: 6, accountRecovery: 8 } as const;

export function collectionAccess(group: string, access: Access): Omit<CollectionAccess, "id"> & { group: string } {
  return { group, readOnly: access === "read", hidePasswords: false, manage: access === "manage" };
}

const accessKey = (list: CollectionAccess[]) =>
  JSON.stringify(list.map((a) => [a.id, a.readOnly, a.hidePasswords, a.manage]).sort((x, y) => String(x[0]).localeCompare(String(y[0]))));

/** The policies as Vaultwarden stores them: type, whether on, and its data. */
export function wantedPolicies(p: Policies): Array<{ name: keyof typeof POLICY; type: number; enabled: boolean; data: Record<string, unknown> | null }> {
  return [
    { name: "twoStepLogin", type: POLICY.twoStepLogin, enabled: p.twoStepLogin, data: null },
    {
      name: "masterPassword",
      type: POLICY.masterPassword,
      enabled: !!p.masterPassword,
      data: p.masterPassword && { ...p.masterPassword, enforceOnLogin: false },
    },
    { name: "passwordGenerator", type: POLICY.passwordGenerator, enabled: !!p.passwordGenerator, data: p.passwordGenerator && { ...p.passwordGenerator } },
    { name: "disableSend", type: POLICY.disableSend, enabled: p.disableSend, data: null },
    { name: "accountRecovery", type: POLICY.accountRecovery, enabled: false, data: null },
  ];
}

function policyDiffers(have: VwPolicy | undefined, want: { enabled: boolean; data: Record<string, unknown> | null }): boolean {
  if (!want.enabled) return !!have?.enabled;
  if (!have?.enabled) return true;
  return Object.entries(want.data ?? {}).some(([k, v]) => have.data?.[k] !== v);
}

export interface SyncOptions {
  /** Emails whose planned leaving date has come: they are left out even while Identity still lists them. */
  due?: Set<string>;
  /** Called with the members about to be removed, while Vaultwarden still shows what they could see. */
  beforeRemove?: (removed: VwMember[], state: OrgState, people: Person[]) => void;
  now?: () => Date;
}

export async function sync(
  vw: Vaultwarden,
  people: () => Promise<Person[]>,
  config: PasswordsConfig,
  { due = new Set(), beforeRemove, now = () => new Date() }: SyncOptions = {},
): Promise<{ result: SyncResult; state: OrgState | null }> {
  const result: SyncResult = { at: now().toISOString(), ok: false, added: [], removed: [], vaults: [], missing: [], policies: [], notes: [], error: null };
  try {
    const features = await vw.features();
    if (!features.groups) throw new Error("Vaultwarden has groups turned off, so vault access cannot follow Identity: set ORG_GROUPS_ENABLED=true.");
    if (!features.events) result.notes.push("Vaultwarden has the event log turned off (ORG_EVENTS_ENABLED), so Activity and Leavers have no history.");

    const directory = await people();
    // An empty directory is far more likely a wrong token or URL than a company with nobody in it.
    if (!directory.length) throw new Error("Identity lists nobody, so no member was removed; check PASSWORDS_IDENTITY_URL and the token.");
    const groups = groupsOf(config);
    const wanted = directory.filter((p) => p.status !== "disabled" && !due.has(p.email) && p.groups.some((g) => groups.includes(g)));
    const wantedIds = new Set(wanted.map((p) => p.id));

    const before = await vw.members();
    const items = await vw.items();
    // Members the import knows by their Identity id, and members added by hand whose address Identity knows.
    const listed = new Map(directory.map((p) => [p.email, p]));
    const wantedEmails = new Set(wanted.map((p) => p.email));
    const removing = before.filter((m) =>
      m.email.toLowerCase() === features.email
        ? false
        : m.externalId
          ? !wantedIds.has(m.externalId)
          : listed.has(m.email.toLowerCase()) && !wantedEmails.has(m.email.toLowerCase()),
    );
    for (const m of removing.filter((x) => x.type === 0))
      result.notes.push(`${m.email} is an owner of the organization, which Passwords never removes; remove them in Vaultwarden if they left.`);
    // Without an external id only the service account can remove them, and an admin can remove users only.
    for (const m of removing.filter((x) => x.type !== 0 && x.type !== 2 && !x.externalId))
      result.notes.push(`${m.email} is an admin or manager added by hand; an owner removes them in Vaultwarden.`);
    const removed = removing.filter((m) => m.type !== 0 && (m.externalId || m.type === 2));
    if (removed.length)
      beforeRemove?.(removed, { members: before, groups: await vw.groups(), collections: await vw.collections(), items, features }, directory);

    const known = new Set(before.map((m) => m.email.toLowerCase()));
    const payload: ImportPayload = {
      members: wanted.map((p) => ({ email: p.email, externalId: p.id, deleted: false })),
      groups: groups.map((g) => ({ name: g, externalId: g, memberExternalIds: wanted.filter((p) => p.groups.includes(g)).map((p) => p.id) })),
      overwriteExisting: true,
    };
    await vw.importDirectory(payload);
    for (const m of removed.filter((x) => !x.externalId)) await vw.removeMember(m.id);
    result.added = wanted.filter((p) => !known.has(p.email)).map((p) => p.email);
    result.removed = removed.map((m) => m.email);

    const [members, vwGroups, collections] = await Promise.all([vw.members(), vw.groups(), vw.collections()]);
    const groupId = new Map(vwGroups.filter((g) => g.externalId).map((g) => [g.externalId!, g.id]));
    for (const vault of config.vaults) {
      const col = collections.find((c) => c.externalId === vault.id);
      if (!col) {
        result.missing.push(vault.id);
        continue;
      }
      const want: CollectionAccess[] = vault.access.flatMap((a) => {
        const id = groupId.get(a.group);
        if (!id) return (result.notes.push(`Group ${a.group} of vault ${vault.id} is not in Vaultwarden yet.`), []);
        const { group: _group, ...flags } = collectionAccess(a.group, a.access);
        return [{ id, ...flags }];
      });
      const have = vwGroups.flatMap((g) => g.collections.filter((c) => c.id === col.id).map((c) => ({ ...c, id: g.id })));
      const direct = members.some((m) => m.collections.some((c) => c.id === col.id));
      if (direct || accessKey(have) !== accessKey(want)) {
        await vw.setCollectionAccess(col.id, want);
        result.vaults.push(vault.id);
      }
    }

    const policies = await vw.policies();
    for (const p of wantedPolicies(config.policies)) {
      const have = policies.find((x) => x.type === p.type);
      if (!policyDiffers(have, p)) continue;
      await vw.setPolicy(p.type, p.enabled, p.enabled ? p.data : (have?.data ?? null));
      result.policies.push(p.name);
    }

    result.ok = true;
    return { result, state: { members: await vw.members(), groups: await vw.groups(), collections, items, features } };
  } catch (err) {
    result.error = (err as Error).message;
    return { result, state: null };
  }
}
