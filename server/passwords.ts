// What the routes call: the vaults from the file, keeping Vaultwarden in step with it and with Identity, the event log,
// the leavers, and the narrow pass-through a person's browser unlocks their vault through. Passwords keeps no item, no
// name of an item and no key: those stay encrypted in Vaultwarden and are read only in people's browsers.
import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { groupsOf, NO_POLICIES, type Access, type ConfigFileState, type PasswordsConfig } from "./config.ts";
import { IdentityError, type Identity, type Person } from "./identity.ts";
import { log } from "./log.ts";
import { sync, type OrgState, type SyncResult } from "./sync.ts";
import { VaultwardenError, type Vaultwarden, type VwMember } from "./vaultwarden.ts";

export type ProblemCode =
  "invalid-token" | "invalid-json" | "invalid-body" | "not-found" | "conflict" | "vault-server-unavailable" | "payload-too-large" | "internal-error";

export class PasswordsError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

/** Event types that mean a person looked at an item: viewed, showed a hidden field or copied it, or filled it in. */
export const OPENED = [1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1117];
const ACTIONS: Record<number, Action> = {
  1100: "added",
  1101: "changed",
  1102: "removed",
  1103: "changed",
  1104: "changed",
  1105: "moved",
  1106: "moved",
  1107: "opened",
  1108: "opened",
  1109: "opened",
  1110: "opened",
  1111: "copied",
  1112: "copied",
  1113: "copied",
  1114: "filled",
  1115: "removed",
  1116: "changed",
  1117: "opened",
};
export type Action = "opened" | "copied" | "filled" | "changed" | "added" | "moved" | "removed";

const DAY = 86_400_000;
/** Opened by a leaver within this many days: changed first. */
const RECENT_DAYS = 90;
/** How long the event log is kept here. */
const EVENT_DAYS = 365;

export interface VaultMember {
  name: string;
  email: string;
  access: Access;
  /** The group it comes from; the strongest one when there are several. */
  group: string;
}

export interface VaultRow {
  id: string;
  name: string;
  access: Array<{ group: string; access: Access }>;
  /** The collection in Vaultwarden, or null until an admin's browser creates it. */
  collectionId: string | null;
  members: VaultMember[];
}

export interface PasswordsOptions {
  /** The address the Bitwarden apps and Vaultwarden's own web vault are reached at. */
  vaultwardenUrl: string;
  /** The browser looks up leaked passwords at the k-anonymity range API of Have I Been Pwned. */
  leakCheck: boolean;
  clock?: () => number;
  fileState?: () => ConfigFileState | null;
}

const rank: Record<Access, number> = { read: 0, edit: 1, manage: 2 };
const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);

export function createPasswords(
  db: DatabaseSync,
  vw: Vaultwarden,
  identity: Identity | null,
  { vaultwardenUrl, leakCheck, clock = Date.now, fileState = () => null }: PasswordsOptions,
) {
  let config: PasswordsConfig = { vaults: [], policies: NO_POLICIES };
  let last: SyncResult | null = null;
  let state: OrgState | null = null;
  let people: Person[] = [];
  let running: Promise<SyncResult> | null = null;
  let again = false;

  const insertRun = db.prepare("INSERT INTO sync_runs (at, ok, added, removed, vaults, policies, error) VALUES (?, ?, ?, ?, ?, ?, ?)");
  const insertEvent = db.prepare(
    `INSERT OR IGNORE INTO events (key, date, type, actor_id, actor_email, actor_name, member_id, item_id, collection_id, device_type, ip)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const setting = (key: string) => (db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | undefined)?.value;
  const putSetting = (key: string, value: string) =>
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(key, value);

  /** Collection id to the file's vault id, for collections the file names. */
  const vaultOf = (collectionId: string) => state?.collections.find((c) => c.id === collectionId)?.externalId ?? null;
  const collectionOf = (vaultId: string) => state?.collections.find((c) => c.externalId === vaultId)?.id ?? null;

  /** Reads Vaultwarden's event log since the last read, a year back the first time, and forgets what is older. */
  async function pollEvents(members: VwMember[]): Promise<number> {
    const now = clock();
    const since = setting("events_since") ?? new Date(now - EVENT_DAYS * DAY).toISOString();
    const end = new Date(now).toISOString();
    const who = new Map(members.map((m) => [m.userId, m]));
    for (const l of db.prepare("SELECT user_id, email, name FROM leavers WHERE user_id IS NOT NULL").all() as Array<{
      user_id: string;
      email: string;
      name: string;
    }>)
      if (!who.has(l.user_id)) who.set(l.user_id, { email: l.email, name: l.name } as VwMember);
    let added = 0;
    let newest = since;
    let page = end;
    for (let i = 0; i < 1000; i++) {
      const r = await vw.events(since, page);
      for (const e of r.data) {
        const actor = e.actingUserId ? who.get(e.actingUserId) : undefined;
        const key = createHash("sha256")
          .update(JSON.stringify([e.date, e.type, e.actingUserId, e.cipherId, e.collectionId, e.groupId, e.organizationUserId, e.ipAddress]))
          .digest("hex");
        const res = insertEvent.run(
          key,
          e.date,
          e.type,
          e.actingUserId,
          actor?.email ?? null,
          actor?.name ?? null,
          e.organizationUserId,
          e.cipherId,
          e.collectionId,
          e.deviceType,
          e.ipAddress,
        );
        if (res.changes) {
          added++;
          // The same events go to the JSON log, for Audit or any log collector.
          if (e.cipherId) log("info", "vault event", { type: e.type, actor: actor?.email ?? e.actingUserId, item: e.cipherId, ip: e.ipAddress, at: e.date });
        }
        if (e.date > newest) newest = e.date;
      }
      // Vaultwarden pages newest first, 30 at a time; the next page ends at the last date of this one.
      if (!r.continuationToken || r.continuationToken === page) break;
      page = r.continuationToken;
    }
    putSetting("events_since", newest);
    db.prepare("DELETE FROM events WHERE date < ?").run(new Date(now - EVENT_DAYS * DAY).toISOString());
    return added;
  }

  /** The last time a member opened each item, by item id. */
  function lastOpened(userId: string | null): Map<string, string> {
    if (!userId) return new Map();
    const rows = db
      .prepare(`SELECT item_id, MAX(date) AS at FROM events WHERE actor_id = ? AND item_id IS NOT NULL AND type IN (${OPENED.join(",")}) GROUP BY item_id`)
      .all(userId) as Array<{ item_id: string; at: string }>;
    return new Map(rows.map((r) => [r.item_id, r.at]));
  }

  /** The collections a member sees, directly or through their groups. */
  function visibleCollections(m: VwMember, s: OrgState): Set<string> {
    const ids = new Set(m.collections.map((c) => c.id));
    for (const g of s.groups) if (m.groups.includes(g.id)) for (const c of g.collections) ids.add(c.id);
    return ids;
  }

  /** Writes what each removed member could see, before Vaultwarden forgets it. */
  function recordLeavers(removed: VwMember[], s: OrgState, directory: Person[]) {
    const at = new Date(clock()).toISOString();
    // Marks made while they were still a member are kept.
    const insertItem = db.prepare(
      `INSERT INTO leaver_items (leaver_id, item_id, collection_ids, last_opened) VALUES (?, ?, ?, ?)
       ON CONFLICT (leaver_id, item_id) DO UPDATE SET collection_ids = excluded.collection_ids, last_opened = excluded.last_opened`,
    );
    for (const m of removed) {
      const email = m.email.toLowerCase();
      const person = directory.find((p) => p.id === m.externalId);
      const planned = db.prepare("SELECT id FROM leavers WHERE email = ? AND left_at IS NULL ORDER BY id DESC LIMIT 1").get(email) as
        { id: number } | undefined;
      const reason = person?.status === "disabled" ? "disabled" : person ? "no-group" : "gone";
      const id = planned
        ? (db.prepare("UPDATE leavers SET left_at = ?, user_id = ? WHERE id = ?").run(at, m.userId, planned.id), planned.id)
        : Number(
            db
              .prepare("INSERT INTO leavers (email, name, user_id, left_at, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)")
              .run(email, person?.name ?? m.name ?? email, m.userId, at, reason, at).lastInsertRowid,
          );
      const seen = visibleCollections(m, s);
      const opened = lastOpened(m.userId);
      for (const item of s.items) {
        if (item.deletedDate || !item.collectionIds.some((c) => seen.has(c))) continue;
        insertItem.run(id, item.id, JSON.stringify(item.collectionIds.filter((c) => seen.has(c))), opened.get(item.id) ?? null);
      }
      db.prepare("DELETE FROM leaver_items WHERE leaver_id = ? AND collection_ids = '[]'").run(id);
      log("info", "removed from the organization", { email, reason, items: s.items.filter((i) => i.collectionIds.some((c) => seen.has(c))).length });
    }
  }

  /** Planned leavers whose day has come, so the sync leaves them out. */
  const due = () =>
    new Set(
      (
        db.prepare("SELECT email FROM leavers WHERE left_at IS NULL AND leaves_on IS NOT NULL AND leaves_on <= ?").all(day(clock())) as Array<{ email: string }>
      ).map((r) => r.email),
    );

  async function run(): Promise<SyncResult> {
    if (!identity) {
      const r: SyncResult = {
        at: new Date(clock()).toISOString(),
        ok: false,
        added: [],
        removed: [],
        vaults: [],
        missing: [],
        policies: [],
        notes: [],
        error: "Identity is not connected: set PASSWORDS_IDENTITY_URL and its token, so members and groups follow it.",
      };
      return r;
    }
    try {
      await pollEvents(state?.members ?? (await vw.members()));
    } catch (err) {
      log("warn", "event log not read; trying again at the next sync", { error: (err as Error).message });
    }
    const out = await sync(
      vw,
      async () => {
        people = await identity.people();
        return people;
      },
      config,
      { due: due(), beforeRemove: recordLeavers, now: () => new Date(clock()) },
    );
    if (out.state) {
      state = out.state;
      db.exec("BEGIN");
      try {
        db.exec("DELETE FROM items");
        const put = db.prepare("INSERT INTO items (id, type, collection_ids, revision_date, password_revision_date, deleted_date) VALUES (?, ?, ?, ?, ?, ?)");
        for (const i of state.items) put.run(i.id, i.type, JSON.stringify(i.collectionIds), i.revisionDate, i.passwordRevisionDate, i.deletedDate);
        db.exec("COMMIT");
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    }
    return out.result;
  }

  /** Brings Vaultwarden in step; a call while one runs makes it run once more after. */
  function syncNow(): Promise<SyncResult> {
    if (running) {
      again = true;
      return running;
    }
    running = run()
      .then((r) => {
        last = r;
        insertRun.run(r.at, r.ok ? 1 : 0, r.added.length, r.removed.length, r.vaults.length, r.policies.length, r.error);
        db.prepare("DELETE FROM sync_runs WHERE id NOT IN (SELECT id FROM sync_runs ORDER BY id DESC LIMIT 100)").run();
        if (r.ok && (r.added.length || r.removed.length || r.vaults.length || r.policies.length))
          log("info", "Vaultwarden updated from the file and Identity", { added: r.added, removed: r.removed, vaults: r.vaults, policies: r.policies });
        else if (!r.ok) log("warn", "Vaultwarden not updated; trying again in five minutes", { error: r.error });
        for (const note of r.notes) log("warn", "sync", { note });
        return r;
      })
      .finally(() => {
        running = null;
        if (again) ((again = false), void syncNow());
      });
    return running;
  }

  /** The people of a vault, from Identity's groups, each with the strongest access a group gives them. */
  function membersOf(access: Array<{ group: string; access: Access }>): VaultMember[] {
    const out = new Map<string, VaultMember>();
    for (const a of access)
      for (const p of people)
        if (p.status !== "disabled" && p.groups.includes(a.group)) {
          const was = out.get(p.email);
          if (!was || rank[a.access] > rank[was.access]) out.set(p.email, { name: p.name, email: p.email, access: a.access, group: a.group });
        }
    return [...out.values()].sort((x, y) => rank[y.access] - rank[x.access] || x.name.localeCompare(y.name));
  }

  function itemRow(id: string) {
    return db.prepare("SELECT type, collection_ids, password_revision_date, deleted_date FROM items WHERE id = ?").get(id) as
      { type: number; collection_ids: string; password_revision_date: string | null; deleted_date: string | null } | undefined;
  }

  return {
    /** Takes the file and starts bringing Vaultwarden in step; the promise is that sync. */
    setConfig(next: PasswordsConfig): Promise<SyncResult> {
      config = next;
      return syncNow();
    },
    config: () => config,
    syncNow,
    lastSync: () => last,
    pollEvents: () => pollEvents(state?.members ?? []),

    summary() {
      return {
        vaults: config.vaults.length,
        groups: groupsOf(config).length,
        members: state ? state.members.filter((m) => m.status === 2).length : null,
        waiting: state ? state.members.filter((m) => m.status === 1).length : null,
        // Owners and admins who are confirmed hold the organization's key, so they can open every shared vault. With
        // none left, the shared vaults cannot be opened again.
        // The service account is left out: its master password is not one a person keeps for this.
        keyHolders: state
          ? state.members.filter((m) => m.status === 2 && (m.type === 0 || m.type === 1) && m.email.toLowerCase() !== state!.features.email).length
          : null,
        missing: config.vaults.filter((v) => state && !collectionOf(v.id)).map((v) => v.id),
        policies: config.policies,
        file: fileState(),
        sync: last,
        identity: identity?.url ?? null,
        organizationId: vw.organizationId,
        vaultwardenUrl,
        leakCheck,
        features: state?.features ?? null,
      };
    },

    /** The file's vaults; a user sees the ones a group gives them, a viewer or more sees all of them. */
    vaults(email: string | null): VaultRow[] {
      return config.vaults
        .map((v) => ({ id: v.id, name: v.name, access: v.access, collectionId: collectionOf(v.id), members: membersOf(v.access) }))
        .filter((v) => email === null || v.members.some((m) => m.email === email.toLowerCase()));
    },

    /** Members who joined and wait for an admin's browser to give them the organization's key. */
    confirmations() {
      return (state?.members ?? []).filter((m) => m.status === 1).map((m) => ({ id: m.id, email: m.email, name: m.name ?? m.email }));
    },

    /** Item events of the log, newest first, optionally of one vault. */
    activity({ vault, limit = 200, before }: { vault?: string; limit?: number; before?: string }) {
      const collection = vault ? collectionOf(vault) : null;
      if (vault && !collection && !config.vaults.some((v) => v.id === vault))
        throw new PasswordsError(404, "not-found", `${vault} is not a vault of the file.`);
      const rows = db
        .prepare(
          `SELECT e.key, e.date, e.type, e.actor_email, e.actor_name, e.item_id, e.device_type, e.ip, i.collection_ids
           FROM events e LEFT JOIN items i ON i.id = e.item_id
           WHERE e.item_id IS NOT NULL AND e.date < ? ORDER BY e.date DESC LIMIT ?`,
        )
        .all(before ?? "9999", collection ? 5000 : Math.min(Math.max(limit, 1), 1000)) as Array<{
        key: string;
        date: string;
        type: number;
        actor_email: string | null;
        actor_name: string | null;
        item_id: string;
        device_type: number | null;
        ip: string | null;
        collection_ids: string | null;
      }>;
      return rows
        .map((r) => {
          const collections = r.collection_ids ? (JSON.parse(r.collection_ids) as string[]) : [];
          return {
            id: r.key,
            at: r.date,
            type: r.type,
            action: ACTIONS[r.type] ?? ("changed" as Action),
            actor: r.actor_email ? { email: r.actor_email, name: r.actor_name ?? r.actor_email } : null,
            itemId: r.item_id,
            vaults: collections.map((c) => vaultOf(c) ?? c),
            collections,
            deviceType: r.device_type,
            ip: r.ip,
          };
        })
        .filter((e) => !collection || e.collections.includes(collection))
        .slice(0, Math.min(Math.max(limit, 1), 1000));
    },

    /** Everyone who is leaving or left, with what they could see: the recently opened first. */
    leavers() {
      const now = clock();
      const rows = db.prepare("SELECT * FROM leavers ORDER BY COALESCE(left_at, leaves_on) DESC, id DESC").all() as Array<{
        id: number;
        email: string;
        name: string;
        user_id: string | null;
        leaves_on: string | null;
        left_at: string | null;
        reason: string;
        created_at: string;
      }>;
      return rows.map((l) => {
        let items: Array<{ item_id: string; collection_ids: string; last_opened: string | null; changed_at: string | null; changed_by: string | null }>;
        if (l.left_at) {
          items = db
            .prepare("SELECT item_id, collection_ids, last_opened, changed_at, changed_by FROM leaver_items WHERE leaver_id = ?")
            .all(l.id) as typeof items;
        } else {
          // Still a member: what they can see now.
          const m = state?.members.find((x) => x.email.toLowerCase() === l.email);
          const marks = new Map(
            (
              db.prepare("SELECT item_id, changed_at, changed_by FROM leaver_items WHERE leaver_id = ?").all(l.id) as Array<{
                item_id: string;
                changed_at: string | null;
                changed_by: string | null;
              }>
            ).map((x) => [x.item_id, x]),
          );
          const seen = m && state ? visibleCollections(m, state) : new Set<string>();
          const opened = lastOpened(m?.userId ?? null);
          items = (state?.items ?? [])
            .filter((i) => !i.deletedDate && i.collectionIds.some((c) => seen.has(c)))
            .map((i) => ({
              item_id: i.id,
              collection_ids: JSON.stringify(i.collectionIds.filter((c) => seen.has(c))),
              last_opened: opened.get(i.id) ?? null,
              changed_at: marks.get(i.id)?.changed_at ?? null,
              changed_by: marks.get(i.id)?.changed_by ?? null,
            }));
        }
        const list = items
          .map((x) => {
            const item = itemRow(x.item_id);
            // Changed by hand, or the password itself changed after the leaver was known.
            const changed = !!x.changed_at || !!(item?.password_revision_date && item.password_revision_date > l.created_at);
            const collections = JSON.parse(x.collection_ids) as string[];
            return {
              itemId: x.item_id,
              vaults: collections.map((c) => vaultOf(c) ?? c),
              lastOpened: x.last_opened,
              recent: !!x.last_opened && now - Date.parse(x.last_opened) < RECENT_DAYS * DAY,
              changed,
              changedBy: x.changed_by,
              deleted: !!item?.deleted_date,
            };
          })
          .sort((a, b) => Number(b.recent) - Number(a.recent) || (b.lastOpened ?? "").localeCompare(a.lastOpened ?? "") || a.itemId.localeCompare(b.itemId));
        return {
          id: l.id,
          email: l.email,
          name: l.name,
          reason: l.reason as "planned" | "disabled" | "no-group" | "gone",
          leavesOn: l.leaves_on,
          leftAt: l.left_at,
          items: list,
          changed: list.filter((i) => i.changed).length,
        };
      });
    },

    /** An editor plans someone's last day: they are removed from the organization on that day. */
    planLeaver(body: unknown, by: string) {
      const b = body as { email?: unknown; leavesOn?: unknown } | null;
      const email = typeof b?.email === "string" ? b.email.trim().toLowerCase() : "";
      const leavesOn = typeof b?.leavesOn === "string" ? b.leavesOn : "";
      if (!/^\d{4}-\d{2}-\d{2}$/.test(leavesOn) || Number.isNaN(Date.parse(leavesOn)))
        throw new PasswordsError(422, "invalid-body", "leavesOn is the last day, such as 2026-11-30.");
      const m = state?.members.find((x) => x.email.toLowerCase() === email);
      const person = people.find((p) => p.email === email);
      if (!m && !person) throw new PasswordsError(422, "invalid-body", `${email || "email"} is not a member of the organization.`);
      if (db.prepare("SELECT 1 FROM leavers WHERE email = ? AND left_at IS NULL").get(email))
        throw new PasswordsError(409, "conflict", `${email} already has a leaving date; cancel it first.`);
      const id = db
        .prepare("INSERT INTO leavers (email, name, user_id, leaves_on, reason, created_at, created_by) VALUES (?, ?, ?, ?, 'planned', ?, ?)")
        .run(email, person?.name ?? m?.name ?? email, m?.userId ?? null, leavesOn, new Date(clock()).toISOString(), by).lastInsertRowid;
      log("info", "leaver planned", { email, leavesOn, by });
      if (leavesOn <= day(clock())) void syncNow();
      return this.leavers().find((l) => l.id === Number(id))!;
    },

    cancelLeaver(id: number, by: string) {
      const row = db.prepare("SELECT email, left_at FROM leavers WHERE id = ?").get(id) as { email: string; left_at: string | null } | undefined;
      if (!row) throw new PasswordsError(404, "not-found", "No such leaver.");
      if (row.left_at) throw new PasswordsError(409, "conflict", `${row.email} has already been removed; add them back in Identity's groups.`);
      db.prepare("DELETE FROM leavers WHERE id = ?").run(id);
      log("info", "leaver cancelled", { email: row.email, by });
    },

    /** Marks an item a leaver could see as changed, or not. */
    markChanged(id: number, itemId: string, body: unknown, by: string) {
      const changed = (body as { changed?: unknown } | null)?.changed;
      if (typeof changed !== "boolean") throw new PasswordsError(422, "invalid-body", "changed is true or false.");
      const leaver = this.leavers().find((l) => l.id === id);
      if (!leaver) throw new PasswordsError(404, "not-found", "No such leaver.");
      const item = leaver.items.find((i) => i.itemId === itemId);
      if (!item) throw new PasswordsError(404, "not-found", "That item is not one the leaver could see.");
      const at = changed ? new Date(clock()).toISOString() : null;
      db.prepare(
        `INSERT INTO leaver_items (leaver_id, item_id, collection_ids, changed_at, changed_by) VALUES (?, ?, '[]', ?, ?)
         ON CONFLICT (leaver_id, item_id) DO UPDATE SET changed_at = excluded.changed_at, changed_by = excluded.changed_by`,
      ).run(id, itemId, at, changed ? by : null);
      return this.leavers()
        .find((l) => l.id === id)!
        .items.find((i) => i.itemId === itemId)!;
    },

    /** What a person's browser needs to unlock: where to ask, which organization, and whether to look up leaks. */
    vaultSettings(email: string) {
      const m = state?.members.find((x) => x.email.toLowerCase() === email.toLowerCase());
      return {
        email: email.toLowerCase(),
        organizationId: vw.organizationId,
        vaultwardenUrl,
        leakCheck,
        member: m ? { id: m.id, status: m.status, type: m.type } : null,
      };
    },

    /** Vaultwarden's failures as a problem the page can show; other errors go up as they are. */
    async server<T>(work: () => Promise<T>): Promise<T> {
      try {
        return await work();
      } catch (err) {
        if (err instanceof VaultwardenError || err instanceof IdentityError) {
          log("warn", "Vaultwarden call failed", { error: err.message });
          throw new PasswordsError(502, "vault-server-unavailable", "Vaultwarden did not answer; try again in a moment.");
        }
        throw err;
      }
    },

    gauges() {
      return {
        vaults: config.vaults.length,
        members: state ? state.members.filter((m) => m.status === 2).length : 0,
        waiting: state ? state.members.filter((m) => m.status === 1).length : 0,
        syncOk: last ? last.ok : null,
        leaving: (db.prepare("SELECT COUNT(*) AS n FROM leavers WHERE left_at IS NULL").get() as { n: number }).n,
      };
    },
  };
}

export type Passwords = ReturnType<typeof createPasswords>;
