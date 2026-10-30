import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones. The vaults themselves are in
// Vaultwarden, encrypted; this file holds sign-in (from @openasy/auth), the history of syncs, the organization's event
// log, where each item is (never what it holds), and the leavers with what they could see.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- Each time Vaultwarden was brought in step with the file and Identity, and what changed. The last 100 are kept.
   CREATE TABLE sync_runs (
     id INTEGER PRIMARY KEY,
     at TEXT NOT NULL,
     ok INTEGER NOT NULL,
     added INTEGER NOT NULL,
     removed INTEGER NOT NULL,
     vaults INTEGER NOT NULL,
     policies INTEGER NOT NULL,
     error TEXT
   );
   -- The organization's event log as Vaultwarden records it, kept a year. The actor's name is the one at the time.
   CREATE TABLE events (
     key TEXT PRIMARY KEY,
     date TEXT NOT NULL,
     type INTEGER NOT NULL,
     actor_id TEXT,
     actor_email TEXT,
     actor_name TEXT,
     member_id TEXT,
     item_id TEXT,
     collection_id TEXT,
     device_type INTEGER,
     ip TEXT
   );
   CREATE INDEX events_date ON events (date);
   CREATE INDEX events_actor_item ON events (actor_id, item_id);
   -- Which collections each organization item is in and when it changed; its content stays encrypted in Vaultwarden.
   CREATE TABLE items (
     id TEXT PRIMARY KEY,
     type INTEGER NOT NULL,
     collection_ids TEXT NOT NULL,
     revision_date TEXT NOT NULL,
     password_revision_date TEXT,
     deleted_date TEXT
   );
   -- People who leave: planned by an editor with a date, or found by a sync when Identity disabled them or they left
   -- every group of the file. left_at is set when they were removed from the organization.
   CREATE TABLE leavers (
     id INTEGER PRIMARY KEY,
     email TEXT NOT NULL,
     name TEXT NOT NULL,
     user_id TEXT,
     leaves_on TEXT,
     left_at TEXT,
     reason TEXT NOT NULL,
     created_at TEXT NOT NULL,
     created_by TEXT
   );
   -- What a leaver could see when they were removed, and which of it someone marked as changed.
   CREATE TABLE leaver_items (
     leaver_id INTEGER NOT NULL REFERENCES leavers (id) ON DELETE CASCADE,
     item_id TEXT NOT NULL,
     collection_ids TEXT NOT NULL,
     last_opened TEXT,
     changed_at TEXT,
     changed_by TEXT,
     PRIMARY KEY (leaver_id, item_id)
   )`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
