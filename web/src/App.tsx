import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  EmptyState,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  StatusBadge,
  toLocale,
  usePath,
  useAgo,
  useLocalePreference,
  useThemePreference,
  type Colophon,
  type Column,
  type ProductId,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import { FolderLock, HeartPulse, History, KeyRound, LogIn, LogOut, RefreshCw, Server, UserMinus, UserRound, Users } from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ActivityPage } from "./Activity.tsx";
import { api, MfaSetupRequired, Unauthorized, type Call, type ConfigFile, type ProductLink, type Summary, type SyncResult, type Vault } from "./api.ts";
import { HealthPage } from "./Health.tsx";
import { useT, type T, setViewerLocale } from "./i18n.ts";
import { LeaversPage } from "./Leavers.tsx";
import { VaultProvider } from "./Unlock.tsx";
import { VaultsPage } from "./Vaults.tsx";

const PAGES = ["vaults", "health", "leavers", "activity", "server", "account", "members", "signin", "tokens"] as const;
type Page = (typeof PAGES)[number];
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = [...PAGES];
function parseRoute(path: string): Page {
  const page = path.replace(/^\//, "").split("/")[0] ?? "";
  return (PAGES as readonly string[]).includes(page) ? (page as Page) : "vaults";
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi(): Call {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}

export function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap text-fg pw-wrap">{children}</pre>;
}

// ---------------------------------------------------------------- Password server

function FileCallout({ file, t }: { file: ConfigFile; t: T }) {
  if (!file?.error) return null;
  return (
    <Callout tone="warning" title={t("file.error")} className="mb-3">
      <span className="pw-wrap">{file.error}</span>
    </Callout>
  );
}

function SyncPanel({ call, sync, onSynced }: { call: Call; sync: SyncResult | null; onSynced: () => void }) {
  const t = useT();
  const ago = useAgo();
  const { can } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function run() {
    setBusy(true);
    setError(undefined);
    try {
      await call<SyncResult>("/api/v1/sync", { method: "POST" });
      onSynced();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Panel
      title={t("sync.title")}
      description={t("sync.description")}
      actions={
        can("admin") && (
          <Button size="sm" icon={<RefreshCw />} loading={busy} onClick={() => void run()}>
            {t("sync.now")}
          </Button>
        )
      }
    >
      {error && <p className="m-0 mb-2 text-sm text-danger">{error}</p>}
      {!sync ? (
        <p className="m-0 text-sm text-fg-muted">{t("sync.never")}</p>
      ) : sync.ok ? (
        <div className="flex flex-col gap-1 text-sm">
          <span>
            <StatusBadge tone="success">{t("sync.ok")}</StatusBadge> <span className="text-fg-muted">{ago(sync.at)}</span>
          </span>
          {(sync.added.length > 0 || sync.removed.length > 0 || sync.vaults.length > 0 || sync.policies.length > 0) && (
            <span className="text-xs text-fg-muted">
              {t("sync.changed", { added: sync.added.length, removed: sync.removed.length, vaults: sync.vaults.length, policies: sync.policies.length })}
            </span>
          )}
          {sync.notes.map((n) => (
            <span key={n} className="text-xs text-warning pw-wrap">
              {n}
            </span>
          ))}
        </div>
      ) : (
        <div className="flex flex-col gap-1 text-sm">
          <span>
            <StatusBadge tone="danger">{t("sync.failed")}</StatusBadge> <span className="text-fg-muted">{ago(sync.at)}</span>
          </span>
          <span className="text-fg-muted pw-wrap">{sync.error}</span>
        </div>
      )}
    </Panel>
  );
}

/** The file's vaults, policies and the organization's state, read-only: everything here changes in the file. */
function ServerPage({ call }: { call: Call }) {
  const t = useT();
  const [summary, setSummary] = useState<Summary>();
  const [vaults, setVaults] = useState<Vault[]>();
  const load = useCallback(() => {
    void call<Summary>("/api/v1/summary").then(setSummary, () => {});
    void call<{ vaults: Vault[] }>("/api/v1/vaults").then(
      (r) => setVaults(r.vaults),
      () => {},
    );
  }, [call]);
  useEffect(load, [load]);

  const columns: Column<Vault>[] = [
    { id: "name", header: t("server.vault"), cell: (v) => <span className="font-medium">{v.name}</span>, sortValue: (v) => v.name },
    { id: "id", header: t("server.id"), cell: (v) => <span className="font-mono text-xs">{v.id}</span> },
    {
      id: "access",
      header: t("server.access"),
      cell: (v) => (
        <span className="flex flex-wrap gap-1">
          {v.access.map((a) => (
            <Badge key={a.group} tone={a.access === "manage" ? "info" : "neutral"}>
              {t(`access.${a.access}Group`, { group: a.group })}
            </Badge>
          ))}
        </span>
      ),
    },
    { id: "people", header: t("server.people"), align: "right", cell: (v) => v.members.length, sortValue: (v) => v.members.length },
    {
      id: "state",
      header: t("server.state"),
      cell: (v) =>
        v.collectionId ? (
          <StatusBadge tone="success">{t("server.inVaultwarden")}</StatusBadge>
        ) : (
          <StatusBadge tone="warning">{t("server.missing")}</StatusBadge>
        ),
    },
  ];
  const p = summary?.policies;
  const policy = (on: boolean, label: string, detail?: string) => (
    <li className="flex items-center justify-between gap-2 py-1">
      <span>
        {label}
        {on && detail && <span className="block text-xs text-fg-muted">{detail}</span>}
      </span>
      {on ? <StatusBadge tone="success">{t("server.on")}</StatusBadge> : <Badge>{t("server.off")}</Badge>}
    </li>
  );

  return (
    <>
      <PageHeader title={t("server.title")} description={t("server.description")} />
      <FileCallout file={summary?.file ?? null} t={t} />
      {summary && summary.keyHolders !== null && summary.keyHolders < 2 && (
        <Callout tone="warning" title={t("server.fewKeyHolders", { count: summary.keyHolders })} className="mb-3">
          {t("server.fewKeyHoldersDetail")}
        </Callout>
      )}
      {summary && !summary.identity && (
        <Callout tone="warning" title={t("server.noIdentity")} className="mb-3">
          {t("server.noIdentityDetail")}
        </Callout>
      )}
      {summary && (
        <KpiGrid className="pw-gap-below">
          <KpiCard label={t("server.vaults")} value={summary.vaults} icon={FolderLock} />
          <KpiCard label={t("server.members")} value={summary.members ?? "–"} icon={Users} />
          <KpiCard label={t("server.waiting")} value={summary.waiting ?? "–"} icon={UserRound} tone={summary.waiting ? "warning" : undefined} />
          <KpiCard
            label={t("server.keyHolders")}
            value={summary.keyHolders ?? "–"}
            icon={KeyRound}
            tone={summary.keyHolders !== null && summary.keyHolders < 2 ? "warning" : undefined}
          />
        </KpiGrid>
      )}
      <div className="pw-side">
        <Panel title={t("server.inFile")} description={summary?.file ? t("server.fileAt", { path: summary.file.path }) : undefined} flush>
          <DataTable label={t("server.inFile")} columns={columns} rows={vaults ?? []} getRowId={(v) => v.id} loading={!vaults} empty={t("server.noVaults")} />
        </Panel>
        <div className="flex flex-col gap-4">
          <SyncPanel call={call} sync={summary?.sync ?? null} onSynced={load} />
          {p && (
            <Panel title={t("server.policies")} description={t("server.changedInFile")}>
              <ul className="m-0 list-none p-0 text-sm">
                {policy(p.twoStepLogin, t("policy.twoStepLogin"))}
                {policy(
                  !!p.masterPassword,
                  t("policy.masterPassword"),
                  p.masterPassword ? t("policy.minLength", { count: p.masterPassword.minLength }) : undefined,
                )}
                {policy(
                  !!p.passwordGenerator,
                  t("policy.passwordGenerator"),
                  p.passwordGenerator ? t("policy.minLength", { count: p.passwordGenerator.minLength }) : undefined,
                )}
                {policy(p.disableSend, t("policy.disableSend"))}
                {policy(false, t("policy.accountRecovery"), undefined)}
              </ul>
              <p className="m-0 mt-2 text-xs text-fg-muted">{t("policy.recoveryNote")}</p>
            </Panel>
          )}
          {summary && (
            <Panel title={t("server.connections")}>
              <dl className="pw-settings m-0 text-sm">
                <dt className="text-fg-muted">{t("server.apps")}</dt>
                <dd className="m-0 font-mono text-xs pw-wrap">{summary.vaultwardenUrl}</dd>
                <dt className="text-fg-muted">{t("server.identity")}</dt>
                <dd className="m-0 font-mono text-xs pw-wrap">{summary.identity ?? "–"}</dd>
                <dt className="text-fg-muted">{t("server.leakCheck")}</dt>
                <dd className="m-0">{summary.leakCheck ? t("server.on") : t("server.off")}</dd>
                <dt className="text-fg-muted">{t("server.eventLog")}</dt>
                <dd className="m-0">{summary.features ? (summary.features.events ? t("server.on") : t("server.off")) : "–"}</dd>
              </dl>
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settings.adminsOnly")}>{t("settings.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settings.${page}`)}
        description={t(`settings.${page}Detail`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settings.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product({ about }: { about: Colophon }) {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const page = parseRoute(usePath());
  const call = useApi();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);

  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "passwords" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const manager = can("viewer");
  const nav = [
    { id: "vaults", label: msg("nav.vaults"), icon: FolderLock },
    { id: "health", label: msg("nav.health"), icon: HeartPulse },
    ...(manager
      ? [
          { id: "leavers", label: msg("nav.leavers"), icon: UserMinus },
          { id: "activity", label: msg("nav.activity"), icon: History },
        ]
      : []),
  ];
  const footerNav = [
    ...(manager ? [{ id: "server", label: msg("nav.server"), icon: Server }] : []),
    ...(can("admin")
      ? [
          { id: "members", label: msg("nav.members"), icon: Users },
          { id: "signin", label: msg("nav.signIn"), icon: LogIn },
          { id: "tokens", label: msg("nav.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("nav.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const managersOnly = (node: ReactNode) => (manager ? node : <EmptyState title={msg("settings.adminsOnly")}>{msg("settings.askAnAdmin")}</EmptyState>);

  return (
    <VaultProvider call={call}>
      <AppShell
        product="passwords"
        about={about}
        nav={nav}
        activeNav={page}
        onNavigate={(id) => navigate(`/${id}`)}
        connectedProducts={products.map((p) => p.id)}
        onSwitchProduct={(id) => {
          const to = products.find((p) => p.id === id);
          if (to) window.location.assign(to.url);
        }}
        footerNav={account.settings(footerNav)}
        user={{ name: me.user.name, role: roleName, ...account.user }}
        theme={theme}
        onThemeChange={setTheme}
        onLanguageChange={(code) => setLocale(toLocale(code))}
      >
        {page === "vaults" ? (
          <VaultsPage call={call} />
        ) : page === "health" ? (
          <HealthPage />
        ) : page === "leavers" ? (
          managersOnly(<LeaversPage call={call} />)
        ) : page === "activity" ? (
          managersOnly(<ActivityPage call={call} />)
        ) : page === "server" ? (
          managersOnly(<ServerPage call={call} />)
        ) : (
          <SettingsPage page={page} />
        )}
      </AppShell>
    </VaultProvider>
  );
}

/** The whole UI; `about` is the build's colophon, which main.tsx gets from Vite. */
export function App({ about }: { about: Colophon }) {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  setViewerLocale(locale);
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Passwords">
        <Product about={about} />
      </AuthGate>
    </BrandProvider>
  );
}
