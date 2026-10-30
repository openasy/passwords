// A person's vaults: their own and the shared ones their groups give them, one open with its items, decrypted in this
// browser. Items are added and changed in the Bitwarden apps or Vaultwarden's web vault; this page reads them, shows
// and copies a password, and makes the two-step code.
import { Avatar, Badge, Button, Callout, DataTable, IconButton, PageHeader, Panel, SearchInput, Tabs, cn, type Column, type Tone } from "@openasy/ui";
import { useAuth } from "@openasy/auth/react";
import { Copy, CreditCard, ExternalLink, Eye, EyeOff, FileText, IdCard, KeyRound, Lock, Plus, ShieldCheck, Users } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { Call, Confirmation, Vault, VaultEvent } from "./api.ts";
import { useDate } from "./format.ts";
import { strength } from "./health.ts";
import { useT } from "./i18n.ts";
import { parseTotp, totp } from "./totp.ts";
import { RequireUnlock, useVault } from "./Unlock.tsx";
import { EVENT, type Collection, type Item, type Kind } from "./vault.ts";

const KIND_ICON = { login: KeyRound, card: CreditCard, note: FileText, identity: IdCard, other: FileText } as const;
const STRENGTH_TONE: Record<string, Tone> = { strong: "success", fair: "warning", weak: "danger" };

/** Copies a value and clears the clipboard 30 seconds later, as the Bitwarden apps do. */
async function copy(value: string) {
  await navigator.clipboard.writeText(value);
  setTimeout(() => void navigator.clipboard.writeText("").catch(() => {}), 30_000);
}

/** The live two-step code of an item. */
function useTotp(secret: string | null) {
  const spec = useMemo(() => parseTotp(secret), [secret]);
  const [now, setNow] = useState(() => ({ code: "", remaining: 0 }));
  useEffect(() => {
    if (!spec) return;
    let alive = true;
    const tick = () => void totp(spec, Date.now()).then((c) => alive && setNow(c));
    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [spec]);
  return spec ? now : null;
}

function ItemDetail({ item, lastOpened }: { item: Item; lastOpened: VaultEvent | undefined }) {
  const t = useT();
  const date = useDate();
  const { session, settings } = useVault();
  const [shown, setShown] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const code = useTotp(item.totp);
  const Icon = KIND_ICON[item.kind];

  async function copyValue(label: string, value: string, event?: number) {
    try {
      await copy(value);
      setCopied(label);
      if (event) session?.report(event, item);
    } catch {
      setCopied(null);
    }
  }
  const field = (label: string, value: string | null, opts: { secret?: boolean; mono?: boolean; event?: number; showEvent?: number } = {}) =>
    value ? (
      <div className="flex flex-col gap-0.5">
        <span className="text-2xs text-fg-muted">{label}</span>
        <span className="flex items-center gap-1 rounded-md bg-canvas px-2 py-1">
          <span className={cn("min-w-0 grow truncate text-sm text-fg", (opts.mono || opts.secret) && "font-mono")}>
            {opts.secret && !shown ? "•".repeat(14) : value}
          </span>
          {opts.secret && item.viewPassword && (
            <IconButton
              label={shown ? t("item.hide", { field: label.toLowerCase() }) : t("item.show", { field: label.toLowerCase() })}
              size="xs"
              onClick={() => {
                if (!shown && opts.showEvent) session?.report(opts.showEvent, item);
                setShown((s) => !s);
              }}
            >
              {shown ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
            </IconButton>
          )}
          {(!opts.secret || item.viewPassword) && (
            <IconButton label={t("item.copy", { field: label.toLowerCase() })} size="xs" onClick={() => void copyValue(label, value, opts.event)}>
              <Copy className="size-3.5" />
            </IconButton>
          )}
        </span>
      </div>
    ) : null;
  const webVault = (path: string) => window.open(`${settings!.vaultwardenUrl}/#${path}`, "_blank", "noopener,noreferrer");

  return (
    <Panel aria-label={t("item.region")}>
      <div className="flex flex-col gap-3">
        <div className="flex items-start gap-2.5">
          <span className="grid size-9 shrink-0 place-items-center rounded-md bg-subtle text-fg-muted">
            <Icon aria-hidden className="size-4" />
          </span>
          <span className="flex min-w-0 flex-col">
            <span className="truncate text-base font-semibold text-fg">{item.name || t("item.unnamed")}</span>
            {item.uris[0] && <span className="truncate text-xs text-fg-muted">{item.uris[0].replace(/^https?:\/\//, "")}</span>}
          </span>
        </div>
        {item.error && <p className="m-0 text-sm text-danger">{item.error}</p>}
        {item.kind === "note" ? (
          item.notes && <p className="m-0 rounded-md bg-canvas px-2.5 py-2 text-sm whitespace-pre-wrap text-fg">{item.notes}</p>
        ) : item.kind === "card" && item.card ? (
          <>
            {field(t("item.holder"), item.card.holder)}
            {field(t("item.number"), item.card.number, { secret: true, event: EVENT.copiedPassword, showEvent: EVENT.cardNumberShown })}
            {field(t("item.expiry"), item.card.expiry, { mono: true })}
            {field(t("item.cardCode"), item.card.code, { secret: true, event: EVENT.copiedCardCode, showEvent: EVENT.cardCodeShown })}
          </>
        ) : (
          <>
            {field(t("item.username"), item.username, { mono: true })}
            {field(t("item.password"), item.password, { secret: true, event: EVENT.copiedPassword, showEvent: EVENT.passwordShown })}
            {code && (
              <div className="flex flex-col gap-0.5">
                <span className="text-2xs text-fg-muted">{t("item.totp")}</span>
                <span className="flex items-center gap-2 rounded-md bg-canvas px-2 py-1">
                  <span className="grow font-mono text-sm text-fg pw-code">{code.code.replace(/^(\d{3})(\d{3})$/, "$1 $2")}</span>
                  <span className="text-2xs text-fg-muted tabular-nums">{t("item.seconds", { count: code.remaining })}</span>
                  <IconButton
                    label={t("item.copy", { field: t("item.totp").toLowerCase() })}
                    size="xs"
                    onClick={() => void copyValue(t("item.totp"), code.code)}
                  >
                    <Copy className="size-3.5" />
                  </IconButton>
                </span>
              </div>
            )}
          </>
        )}
        {copied && (
          <p role="status" className="m-0 text-xs text-success">
            {t("item.copied", { field: copied })}
          </p>
        )}
        {item.kind !== "note" && item.notes && <p className="m-0 text-xs whitespace-pre-wrap text-fg-muted">{item.notes}</p>}
        <dl className="pw-meta m-0 border-t border-line pt-2.5 text-xs">
          <dt className="text-fg-muted">{t("item.changed")}</dt>
          <dd className="m-0 text-fg">{date(item.passwordRevisionDate ?? item.revisionDate)}</dd>
          {lastOpened && (
            <>
              <dt className="text-fg-muted">{t("item.lastOpened")}</dt>
              <dd className="m-0 text-fg">{t("item.openedBy", { name: lastOpened.actor?.name ?? "–", when: date(lastOpened.at, true) })}</dd>
            </>
          )}
          <dt className="text-fg-muted">{t("item.history")}</dt>
          <dd className="m-0 text-fg">{item.history ? t("item.earlier", { count: item.history }) : t("item.none")}</dd>
        </dl>
        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" icon={<ExternalLink />} onClick={() => webVault(`/vault?itemId=${encodeURIComponent(item.id)}`)} disabled={!item.edit}>
            {t("item.edit")}
          </Button>
          {!item.organizationId && (
            <Button size="sm" variant="ghost" onClick={() => webVault(`/vault?itemId=${encodeURIComponent(item.id)}`)}>
              {t("item.move")}
            </Button>
          )}
        </div>
        <p className="m-0 text-2xs text-fg-muted">{t("item.editsInApps")}</p>
      </div>
    </Panel>
  );
}

/** For admins who hold the organization's key: people to confirm, vaults of the file to create, names to match. */
function AdminCallouts({ call }: { call: Call }) {
  const t = useT();
  const { session, vaults, refresh } = useVault();
  const [waiting, setWaiting] = useState<Confirmation[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string>();
  const load = useCallback(
    () =>
      void call<{ members: Confirmation[] }>("/api/v1/confirmations").then(
        (r) => setWaiting(r.members),
        () => {},
      ),
    [call],
  );
  useEffect(load, [load]);
  if (!session?.orgAdmin) return null;

  const run = async (key: string, work: () => Promise<unknown>) => {
    setBusy(key);
    setError(undefined);
    try {
      await work();
      await refresh();
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };
  const missing = vaults.filter((v) => !v.collectionId);
  const renamed = vaults.flatMap((v) => {
    const c = session.collections.find((x) => x.id === v.collectionId);
    return c && c.name !== v.name ? [{ vault: v, collection: c }] : [];
  });

  return (
    <div className="flex flex-col gap-2.5 pw-gap-below">
      {error && (
        <Callout tone="danger" title={t("admin.failed")} onDismiss={() => setError(undefined)}>
          {error}
        </Callout>
      )}
      {waiting.length > 0 && (
        <Callout
          tone="info"
          title={t("admin.waiting", { count: waiting.length })}
          action={
            <Button
              size="sm"
              variant="primary"
              loading={busy === "confirm"}
              onClick={() => void run("confirm", () => session.confirm(waiting.map((w) => w.id)))}
            >
              {t("admin.confirm")}
            </Button>
          }
        >
          {t("admin.waitingDetail", { names: waiting.map((w) => w.name).join(", ") })}
        </Callout>
      )}
      {missing.map((v) => (
        <Callout
          key={v.id}
          tone="warning"
          title={t("admin.missing", { name: v.name })}
          action={
            <Button size="sm" loading={busy === v.id} onClick={() => void run(v.id, () => session.createVault(v.id, v.name))}>
              {t("admin.create")}
            </Button>
          }
        >
          {t("admin.missingDetail")}
        </Callout>
      ))}
      {renamed.map(({ vault, collection }) => (
        <Callout
          key={vault.id}
          tone="info"
          title={t("admin.renamed", { name: collection.name, file: vault.name })}
          action={
            <Button
              size="sm"
              loading={busy === `rename-${vault.id}`}
              onClick={() => void run(`rename-${vault.id}`, () => session.renameVault(collection.id, vault.id, vault.name))}
            >
              {t("admin.rename")}
            </Button>
          }
        />
      ))}
    </div>
  );
}

const can = (c: Collection | undefined) => (!c ? "manage" : c.manage ? "manage" : c.readOnly ? "read" : "edit");

function VaultsView({ call }: { call: Call }) {
  const t = useT();
  const date = useDate();
  const { can: role } = useAuth();
  const { session, settings, vaults, leaks, lock } = useVault();
  const items = session!.items.filter((i) => !i.deleted);
  const collections = [...session!.collections].sort((a, b) => a.name.localeCompare(b.name));
  const [open, setOpen] = useState<string>(collections[0]?.id ?? "personal");
  const [tab, setTab] = useState<"items" | "members" | "activity">("items");
  const [query, setQuery] = useState("");
  const [active, setActive] = useState<string | null>(null);
  const [events, setEvents] = useState<VaultEvent[]>([]);

  const collection = collections.find((c) => c.id === open);
  const fileVault: Vault | undefined = collection && vaults.find((v) => v.collectionId === collection.id || v.id === collection.externalId);
  const inVault = items.filter((i) => (open === "personal" ? !i.organizationId : i.collectionIds.includes(open)));
  const q = query.trim().toLowerCase();
  const rows = inVault.filter((i) => !q || `${i.name} ${i.username ?? ""} ${i.uris.join(" ")}`.toLowerCase().includes(q));
  const current = inVault.find((i) => i.id === active) ?? rows[0];
  const reused = useMemo(() => {
    const n = new Map<string, number>();
    for (const i of items) if (i.password) n.set(i.password, (n.get(i.password) ?? 0) + 1);
    return n;
  }, [items]);

  useEffect(() => {
    if (!fileVault || !role("viewer")) return setEvents([]);
    void call<{ events: VaultEvent[] }>(`/api/v1/activity?vault=${encodeURIComponent(fileVault.id)}&limit=200`).then(
      (r) => setEvents(r.events),
      () => setEvents([]),
    );
  }, [call, fileVault, role]);

  const cols: Column<Item>[] = [
    {
      id: "name",
      header: t("items.name"),
      width: "38%",
      sortValue: (i) => i.name,
      cell: (i) => {
        const Icon = KIND_ICON[i.kind as Kind];
        return (
          <span className="flex min-w-0 items-center gap-2">
            <Icon aria-hidden className="size-3.5 shrink-0 text-fg-muted" />
            <span className="flex min-w-0 flex-col">
              <span className="truncate font-medium">{i.name || t("item.unnamed")}</span>
              <span className="truncate text-2xs text-fg-muted">
                {i.kind === "note" ? t("items.note") : i.kind === "card" ? (i.card?.brand ?? t("items.card")) : (i.username ?? "")}
              </span>
            </span>
          </span>
        );
      },
    },
    {
      id: "health",
      header: t("items.health"),
      sortValue: (i) =>
        !i.password
          ? 9
          : leaks?.get(i.id)
            ? 0
            : strength(i.password) === "weak"
              ? 1
              : (reused.get(i.password) ?? 0) > 1
                ? 2
                : strength(i.password) === "fair"
                  ? 3
                  : 4,
      cell: (i) => {
        if (!i.password) return <span className="text-xs text-fg-muted">–</span>;
        const s = strength(i.password);
        const times = (reused.get(i.password) ?? 0) - 1;
        return (
          <span className="flex flex-wrap gap-1">
            {leaks?.get(i.id) ? <Badge tone="danger">{t("issue.leaked")}</Badge> : <Badge tone={STRENGTH_TONE[s]}>{t(`strength.${s}`)}</Badge>}
            {times > 0 && <Badge tone="warning">{t("items.reused", { count: times })}</Badge>}
          </span>
        );
      },
    },
    {
      id: "changed",
      header: t("items.changed"),
      sortValue: (i) => i.passwordRevisionDate ?? i.revisionDate,
      cell: (i) => <span className="text-xs whitespace-nowrap">{date(i.passwordRevisionDate ?? i.revisionDate)}</span>,
    },
    {
      id: "totp",
      header: t("items.twoStep"),
      align: "center",
      cell: (i) => (parseTotp(i.totp) ? <ShieldCheck aria-label={t("items.hasTwoStep")} className="mx-auto size-3.5 text-success" /> : null),
    },
  ];

  const access = can(collection);
  const lastOpened = current
    ? events.find((e) => e.itemId === current.id && (e.action === "opened" || e.action === "copied" || e.action === "filled"))
    : undefined;
  const webVault = (path: string) => window.open(`${settings!.vaultwardenUrl}/#${path}`, "_blank", "noopener,noreferrer");

  return (
    <>
      <PageHeader
        title={t("vaults.title")}
        description={t("vaults.description")}
        actions={
          <>
            <Button icon={<Lock />} variant="ghost" onClick={lock}>
              {t("vaults.lock")}
            </Button>
            <Button onClick={() => webVault("/tools/import")}>{t("vaults.import")}</Button>
            <Button variant="primary" icon={<Plus />} onClick={() => webVault("/vault")}>
              {t("vaults.newItem")}
            </Button>
          </>
        }
      />
      {role("admin") && <AdminCallouts call={call} />}
      <div className="pw-vaults">
        <Panel flush aria-label={t("vaults.yours")}>
          <ul className="m-0 flex list-none flex-col p-0 py-1">
            {[{ id: "personal", name: t("vaults.mine"), shared: false }, ...collections.map((c) => ({ id: c.id, name: c.name, shared: true }))].map((x) => (
              <li key={x.id}>
                <button
                  type="button"
                  onClick={() => (setOpen(x.id), setActive(null), setTab("items"))}
                  aria-current={x.id === open ? "true" : undefined}
                  className={cn(
                    "flex w-full items-center gap-2 border-0 bg-transparent px-3 py-1.5 text-left",
                    x.id === open ? "bg-accent-soft text-accent-text" : "text-fg hover:bg-canvas",
                  )}
                >
                  {x.shared ? <Users aria-hidden className="size-3.5 shrink-0" /> : <Lock aria-hidden className="size-3.5 shrink-0" />}
                  <span className="min-w-0 grow truncate text-sm font-medium">{x.name}</span>
                  <span className="text-2xs text-fg-muted tabular-nums">
                    {items.filter((i) => (x.id === "personal" ? !i.organizationId : i.collectionIds.includes(x.id))).length}
                  </span>
                </button>
              </li>
            ))}
          </ul>
          <p className="m-0 border-t border-line px-3 py-2 text-2xs text-fg-muted">{t("vaults.fromGroups")}</p>
        </Panel>

        <Panel flush aria-label={t("vaults.vault", { name: collection?.name ?? t("vaults.mine") })}>
          <div className="flex flex-wrap items-center justify-between gap-2 px-3 pt-2.5">
            <span className="flex min-w-0 flex-col">
              <span className="text-base font-semibold text-fg">{collection?.name ?? t("vaults.mine")}</span>
              <span className="text-xs text-fg-muted">
                {collection
                  ? fileVault
                    ? t("vaults.sharedBy", {
                        groups: fileVault.access.map((a) => a.group).join(", "),
                        count: fileVault.members.length,
                        access: t(`access.you.${access}`),
                      })
                    : t("vaults.notInFile", { access: t(`access.you.${access}`) })
                  : t("vaults.onlyYou")}
              </span>
            </span>
            <SearchInput
              label={t("vaults.search")}
              placeholder={t("vaults.searchHint")}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="pw-search"
            />
          </div>
          <div className="px-3">
            <Tabs
              label={t("vaults.tabs")}
              value={tab}
              onChange={setTab}
              items={[
                { value: "items", label: t("vaults.items"), count: inVault.length },
                ...(fileVault ? [{ value: "members" as const, label: t("vaults.members"), count: fileVault.members.length }] : []),
                ...(fileVault && role("viewer") ? [{ value: "activity" as const, label: t("vaults.activity") }] : []),
              ]}
              className="border-b-0"
            />
          </div>
          <div className="border-t border-line">
            {tab === "items" && (
              <DataTable
                label={t("vaults.items")}
                columns={cols}
                rows={rows}
                getRowId={(i) => i.id}
                onRowClick={(i) => setActive(i.id)}
                activeRowId={current?.id}
                defaultSort={{ id: "name", direction: "asc" }}
                minWidth={560}
                empty={q ? t("vaults.noMatch") : t("vaults.empty")}
              />
            )}
            {tab === "members" && fileVault && (
              <ul aria-label={t("vaults.members")} className="m-0 flex list-none flex-col p-0">
                {fileVault.members.map((m) => (
                  <li key={m.email} className="flex items-center justify-between gap-2 border-b border-subtle px-3 py-2 last:border-0">
                    <span className="flex min-w-0 items-center gap-2">
                      <Avatar name={m.name} size="sm" />
                      <span className="flex min-w-0 flex-col">
                        <span className="truncate text-sm font-medium text-fg">{m.email === session!.email ? t("vaults.you", { name: m.name }) : m.name}</span>
                        <span className="truncate text-2xs text-fg-muted">{t("vaults.group", { group: m.group })}</span>
                      </span>
                    </span>
                    <Badge tone={m.access === "manage" ? "info" : "neutral"}>{t(`access.${m.access}`)}</Badge>
                  </li>
                ))}
                <li className="px-3 py-2 text-xs text-fg-muted">{t("vaults.membersChange")}</li>
              </ul>
            )}
            {tab === "activity" && (
              <ul aria-label={t("vaults.activity")} className="m-0 flex list-none flex-col p-0">
                {events.length === 0 && <li className="px-3 py-2 text-sm text-fg-muted">{t("activity.none")}</li>}
                {events.slice(0, 50).map((e) => (
                  <li key={e.id} className="flex items-center gap-2 border-b border-subtle px-3 py-2 text-sm last:border-0">
                    <Avatar name={e.actor?.name ?? "?"} size="sm" />
                    <span className="min-w-0 grow truncate">
                      {t(`activity.line.${e.action}`, {
                        name: e.actor?.name ?? t("activity.someone"),
                        item: items.find((i) => i.id === e.itemId)?.name ?? t("activity.anItem"),
                      })}
                    </span>
                    <span className="shrink-0 text-xs text-fg-muted">{date(e.at, true)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>

        {current ? (
          <ItemDetail key={current.id} item={current} lastOpened={lastOpened} />
        ) : (
          <Panel>{<p className="m-0 text-sm text-fg-muted">{t("vaults.pick")}</p>}</Panel>
        )}
      </div>
    </>
  );
}

export function VaultsPage({ call }: { call: Call }) {
  return (
    <RequireUnlock>
      <VaultsView call={call} />
    </RequireUnlock>
  );
}
