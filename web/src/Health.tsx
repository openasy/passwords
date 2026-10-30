// Leaked, weak, reused and old passwords in the shared vaults, by team, worked out in this browser from the items it
// decrypted. A person sees the shared vaults they are in; an owner or admin of the organization sees all of them.
// Personal vaults are not listed here: their health shows on the Vaults page, to their owner only.
import { Avatar, Callout, DataTable, KpiCard, KpiGrid, PageHeader, Panel, StatusBadge, Tabs, cn, type Column, type Tone } from "@openasy/ui";
import { useEffect, useMemo, useState } from "react";
import { useDate } from "./format.ts";
import { findings, leaks as lookUpLeaks, score, type Finding, type Issue } from "./health.ts";
import { useT } from "./i18n.ts";
import { RequireUnlock, useVault, useVaultNames } from "./Unlock.tsx";

const TONE: Record<Issue, Tone> = { leaked: "danger", weak: "danger", reused: "warning", old: "warning" };
const ORDER: Issue[] = ["leaked", "weak", "reused", "old"];

interface Row extends Finding {
  id: string;
  name: string;
  vault: string;
  managers: string[];
}

function HealthView() {
  const t = useT();
  const date = useDate();
  const { session, settings, shared, vaults, leaks, setLeaks } = useVault();
  const vaultName = useVaultNames();
  const [issue, setIssue] = useState<"all" | Issue>("all");
  const [leakError, setLeakError] = useState<string>();
  // Read once when the page opens; "not changed in two years" does not move while it is open.
  const [now] = useState(() => Date.now());
  const items = useMemo(() => (shared ?? []).filter((i) => !i.deleted && i.organizationId === session!.organizationId), [shared, session]);
  const checked = useMemo(
    () => items.filter((i) => i.kind === "login").map((i) => ({ id: i.id, password: i.password, changedAt: i.passwordRevisionDate ?? i.creationDate })),
    [items],
  );

  useEffect(() => {
    if (!settings?.leakCheck || leaks || !checked.length) return;
    let alive = true;
    lookUpLeaks(checked).then(
      (found) => alive && setLeaks(found),
      (e: Error) => alive && setLeakError(e.message),
    );
    return () => {
      alive = false;
    };
  }, [settings, leaks, checked, setLeaks]);

  const found = useMemo(() => findings(checked, { now, leaks: leaks ?? undefined }), [checked, leaks, now]);
  const rows: Row[] = found.map((f, n) => {
    const item = items.find((i) => i.id === f.itemId)!;
    const collection = item.collectionIds[0];
    const fileVault = vaults.find((v) => v.collectionId === collection);
    return {
      ...f,
      id: `${f.itemId}-${f.issue}-${n}`,
      name: item.name || t("item.unnamed"),
      vault: collection ? vaultName(collection) : "–",
      managers: fileVault?.members.filter((m) => m.access === "manage").map((m) => m.name) ?? [],
    };
  });
  const count = (i: Issue) => found.filter((f) => f.issue === i).length;
  const shown = rows.filter((r) => issue === "all" || r.issue === issue);
  const teams = [...new Set(items.flatMap((i) => i.collectionIds))]
    .map((c) => {
      const ids = items.filter((i) => i.collectionIds.includes(c) && i.kind === "login").map((i) => i.id);
      return { id: c, name: vaultName(c), items: ids.length, score: score(ids, found) };
    })
    .filter((x) => x.items > 0)
    .sort((a, b) => a.name.localeCompare(b.name));

  const why = (r: Row) =>
    r.issue === "leaked"
      ? t("why.leaked", { count: Number(r.detail) })
      : r.issue === "weak"
        ? t("why.weak", { count: Number(r.detail) })
        : r.issue === "reused"
          ? t("why.reused", { count: Number(r.detail) })
          : t("why.old", { date: date(String(r.detail)) });

  const cols: Column<Row>[] = [
    { id: "item", header: t("health.item"), width: "26%", sortValue: (r) => r.name, cell: (r) => <span className="truncate font-medium">{r.name}</span> },
    { id: "vault", header: t("health.vault"), sortValue: (r) => r.vault, cell: (r) => <span className="text-xs">{r.vault}</span> },
    {
      id: "issue",
      header: t("health.problem"),
      sortValue: (r) => ORDER.indexOf(r.issue),
      cell: (r) => <StatusBadge tone={TONE[r.issue]}>{t(`issue.${r.issue}`)}</StatusBadge>,
    },
    { id: "detail", header: t("health.why"), width: "28%", cell: (r) => <span className="block truncate text-xs text-fg-muted">{why(r)}</span> },
    {
      id: "owner",
      header: t("health.manager"),
      cell: (r) =>
        r.managers[0] ? (
          <span className="flex items-center gap-1.5">
            <Avatar name={r.managers[0]} size="sm" />
            <span className="truncate text-xs">
              {r.managers.length > 1 ? t("health.andMore", { name: r.managers[0], count: r.managers.length - 1 }) : r.managers[0]}
            </span>
          </span>
        ) : (
          <span className="text-xs text-fg-muted">–</span>
        ),
    },
  ];

  return (
    <>
      <PageHeader title={t("health.title")} description={settings?.leakCheck ? t("health.description") : t("health.descriptionNoLeaks")} />
      {leakError && (
        <Callout tone="warning" title={t("health.leakFailed")} className="mb-3">
          {leakError}
        </Callout>
      )}
      {!session!.orgAdmin && <p className="m-0 mb-3 text-xs text-fg-muted">{t("health.yourVaults")}</p>}
      <KpiGrid minWidth={170}>
        <KpiCard
          label={t("issue.leaked")}
          value={settings?.leakCheck ? (leaks ? String(count("leaked")) : "…") : "–"}
          tone={count("leaked") ? "danger" : undefined}
        />
        <KpiCard label={t("issue.weak")} value={String(count("weak"))} tone={count("weak") ? "danger" : undefined} />
        <KpiCard label={t("issue.reused")} value={String(count("reused"))} />
        <KpiCard label={t("issue.old")} value={String(count("old"))} />
      </KpiGrid>
      <div className="pw-side pw-gap-above">
        <Panel flush>
          <div className="px-3 pt-2">
            <Tabs
              label={t("health.problem")}
              value={issue}
              onChange={setIssue}
              items={[
                { value: "all" as const, label: t("health.all"), count: found.length },
                ...ORDER.map((i) => ({ value: i, label: t(`issue.${i}`), count: count(i) })),
              ]}
              className="border-b-0"
            />
          </div>
          <div className="border-t border-line">
            <DataTable
              label={t("health.problems")}
              columns={cols}
              rows={shown}
              getRowId={(r) => r.id}
              defaultSort={{ id: "issue", direction: "asc" }}
              minWidth={720}
              loading={shared === null}
              empty={t("health.none")}
            />
          </div>
        </Panel>
        <Panel title={t("health.byTeam")} description={t("health.byTeamDetail")} className="self-start">
          <ul aria-label={t("health.byTeam")} className="m-0 flex list-none flex-col gap-2.5 p-0">
            {teams.map((x) => (
              <li key={x.id} className="flex flex-col gap-1">
                <span className="flex items-baseline justify-between text-sm">
                  <span className="font-medium text-fg">{x.name}</span>
                  <span className="font-mono text-xs text-fg-muted tabular-nums">{t("health.scoreOf", { score: x.score, count: x.items })}</span>
                </span>
                <span aria-hidden className="h-1.5 overflow-hidden rounded-full bg-subtle">
                  <span
                    className={cn("block h-full rounded-full", x.score >= 80 ? "bg-success" : x.score >= 65 ? "bg-warning" : "bg-danger")}
                    style={{ width: `${x.score}%` }}
                  />
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </>
  );
}

export function HealthPage() {
  const t = useT();
  return (
    <RequireUnlock reason={t("health.unlock")}>
      <HealthView />
    </RequireUnlock>
  );
}
