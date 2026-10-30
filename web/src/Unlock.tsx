// The unlocked vault, held in this page's memory only, and the screen that unlocks it. It locks itself after fifteen
// minutes without a key press or a click, and when the page is left.
import { Button, Callout, EmptyState, Panel, TextField } from "@openasy/ui";
import { useAuth } from "@openasy/auth/react";
import { KeyRound, Lock, ShieldCheck } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ApiError, type Call, type Vault, type VaultSettings } from "./api.ts";
import { useT } from "./i18n.ts";
import { SessionEnded, TwoFactorRequired, unlock, type Collection, type Item, type Session } from "./vault.ts";

const IDLE_MS = 15 * 60_000;

interface VaultState {
  settings: VaultSettings | null;
  settingsError: string | null;
  session: Session | null;
  /** The file's vaults this person may see, with their groups and people. */
  vaults: Vault[];
  /** Every shared item an owner or admin can open, else the shared items of this person's own sync. */
  shared: Item[] | null;
  /** Breach counts by item id, once the Health page looked them up in this unlocked session. */
  leaks: Map<string, number> | null;
  setLeaks: (l: Map<string, number> | null) => void;
  /** Counts reloads of the session, which keeps its identity, so what depends on it is worked out again. */
  version: number;
  setSession: (s: Session | null) => void;
  /** Reads the vault and the file's vaults again, after a change. */
  refresh: () => Promise<void>;
  lock: () => void;
}

const VaultContext = createContext<VaultState | null>(null);

export function useVault(): VaultState {
  const v = useContext(VaultContext);
  if (!v) throw new Error("useVault outside VaultProvider");
  return v;
}

export function VaultProvider({ call, children }: { call: Call; children: ReactNode }) {
  const { expired } = useAuth();
  const [settings, setSettings] = useState<VaultSettings | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [session, setSessionState] = useState<Session | null>(null);
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [shared, setShared] = useState<Item[] | null>(null);
  const [version, setVersion] = useState(0);
  const [leaks, setLeaks] = useState<Map<string, number> | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  const lock = useCallback(() => {
    setSessionState(null);
    setShared(null);
    setLeaks(null);
  }, []);

  useEffect(() => {
    void call<VaultSettings>("/api/v1/vault/settings").then(setSettings, (e: Error) => setSettingsError(e instanceof ApiError ? e.message : String(e)));
    void call<{ vaults: Vault[] }>("/api/v1/vaults").then(
      (r) => setVaults(r.vaults),
      () => {},
    );
  }, [call]);

  const loadShared = useCallback(
    async (s: Session) => {
      try {
        setShared(await s.organizationItems());
      } catch (e) {
        if (e instanceof SessionEnded) expired();
        setShared(s.items.filter((i) => i.organizationId));
      }
    },
    [expired],
  );

  const setSession = useCallback(
    (s: Session | null) => {
      setSessionState(s);
      if (s) void loadShared(s);
      else setShared(null);
    },
    [loadShared],
  );

  const refresh = useCallback(async () => {
    void call<{ vaults: Vault[] }>("/api/v1/vaults").then(
      (r) => setVaults(r.vaults),
      () => {},
    );
    if (!session) return;
    try {
      await session.reload();
      await loadShared(session);
      setVersion((v) => v + 1);
    } catch (e) {
      if (e instanceof SessionEnded) expired();
      lock();
    }
  }, [call, session, loadShared, expired, lock]);

  // Locks after a while without activity, and when the page is left.
  useEffect(() => {
    if (!session) return;
    const reset = () => {
      clearTimeout(timer.current);
      timer.current = setTimeout(lock, IDLE_MS);
    };
    reset();
    const events = ["keydown", "pointerdown"] as const;
    for (const e of events) window.addEventListener(e, reset);
    window.addEventListener("pagehide", lock);
    return () => {
      clearTimeout(timer.current);
      for (const e of events) window.removeEventListener(e, reset);
      window.removeEventListener("pagehide", lock);
    };
  }, [session, lock]);

  const value = useMemo(
    () => ({ settings, settingsError, session, vaults, shared, leaks, setLeaks, version, setSession, refresh, lock }),
    [settings, settingsError, session, vaults, shared, leaks, version, setSession, refresh, lock],
  );
  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

/** The unlock form: the master password, and a two-step code when the account asks for one. */
export function UnlockPanel({ reason }: { reason?: string }) {
  const t = useT();
  const { expired } = useAuth();
  const { settings, setSession } = useVault();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [providers, setProviders] = useState<number[] | null>(null);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!settings) return;
    setBusy(true);
    setError(undefined);
    try {
      const s = await unlock(password, settings, providers ? { twoFactor: { provider: 0, code } } : {});
      setPassword("");
      setSession(s);
    } catch (e) {
      if (e instanceof SessionEnded) expired();
      else if (e instanceof TwoFactorRequired) {
        if (!e.providers.includes(0)) setError(t("unlock.twoStepApp"));
        else if (providers) setError(t("unlock.wrongCode"));
        setProviders(e.providers);
      } else setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="pw-unlock">
      <Panel
        title={
          <span className="flex items-center gap-2">
            <Lock aria-hidden className="size-4" /> {t("unlock.title")}
          </span>
        }
        description={reason ?? t("unlock.description")}
      >
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          {settings && <p className="m-0 text-sm text-fg-muted">{t("unlock.as", { email: settings.email })}</p>}
          <TextField
            label={t("unlock.password")}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          {providers && (
            <TextField
              label={t("unlock.code")}
              hint={t("unlock.codeHint")}
              inputMode="numeric"
              autoComplete="one-time-code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              mono
            />
          )}
          {error && <p className="m-0 text-sm text-danger">{error}</p>}
          <div>
            <Button type="submit" variant="primary" icon={<KeyRound />} loading={busy} disabled={!password || !settings}>
              {t("unlock.unlock")}
            </Button>
          </div>
          <p className="m-0 flex items-start gap-1.5 text-xs text-fg-muted">
            <ShieldCheck aria-hidden className="mt-0.5 size-3.5 shrink-0" />
            {t("unlock.e2e")}
          </p>
        </form>
      </Panel>
    </div>
  );
}

/** Shows its children once the vault is unlocked, and the unlock form before. */
export function RequireUnlock({ children, reason }: { children: ReactNode; reason?: string }) {
  const t = useT();
  const { settings, settingsError, session } = useVault();
  if (settingsError) return <EmptyState title={t("unlock.unavailable")}>{settingsError}</EmptyState>;
  if (!settings) return <p className="text-sm text-fg-muted">{t("common.loading")}</p>;
  if (!session)
    return (
      <>
        {!settings.member && (
          <Callout tone="info" title={t("unlock.noAccount")} className="mb-3">
            {t("unlock.noAccountDetail", { url: settings.vaultwardenUrl })}
          </Callout>
        )}
        {settings.member && settings.member.status < 2 && (
          <Callout tone="info" title={t("unlock.waiting")} className="mb-3">
            {t("unlock.waitingDetail")}
          </Callout>
        )}
        <UnlockPanel reason={reason} />
      </>
    );
  return <>{children}</>;
}

/** The name of a vault: the file's name for its vaults, the decrypted collection name for others. */
export function useVaultNames(): (idOrCollection: string) => string {
  const { vaults, session } = useVault();
  // A reload gives the session new lists, so these change with it.
  const collections = session?.collections;
  return useCallback(
    (key: string) =>
      vaults.find((v) => v.id === key)?.name ??
      collections?.find((c) => c.id === key || c.externalId === key)?.name ??
      vaults.find((v) => v.collectionId === key)?.name ??
      key,
    [vaults, collections],
  );
}

/** Items this browser can open, by id: the person's own and, for owners and admins, every shared one. */
export function useItems(): Map<string, Item> {
  const { session, shared } = useVault();
  const items = session?.items;
  return useMemo(() => new Map([...(shared ?? []), ...(items ?? [])].map((i) => [i.id, i])), [items, shared]);
}

/** The vault id of the file for a collection, when the file names it. */
export const fileVaultOf = (c: Collection | undefined, vaults: Vault[]) =>
  c ? vaults.find((v) => v.collectionId === c.id || v.id === c.externalId) : undefined;
