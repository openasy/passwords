// Who opened, copied or changed which shared item, and from where, from Vaultwarden's event log. What people do in
// their own vault is not in it. The item names are decrypted in this browser.
import { Avatar, Badge, DataTable, PageHeader, Panel, StatusBadge, Tabs, type Column, type Tone } from "@openasy/ui";
import { useEffect, useState } from "react";
import type { Action, Call, Leaver, VaultEvent } from "./api.ts";
import { deviceName, useDate } from "./format.ts";
import { useT } from "./i18n.ts";
import { RequireUnlock, useItems, useVault, useVaultNames } from "./Unlock.tsx";

const TONE: Record<Action, Tone> = {
  opened: "neutral",
  copied: "neutral",
  filled: "neutral",
  changed: "info",
  added: "success",
  moved: "info",
  removed: "danger",
};

function ActivityView({ call }: { call: Call }) {
  const t = useT();
  const date = useDate();
  const items = useItems();
  const vaultName = useVaultNames();
  const { vaults } = useVault();
  const [events, setEvents] = useState<VaultEvent[]>();
  const [leaving, setLeaving] = useState<Set<string>>(new Set());
  const [vault, setVault] = useState("all");

  useEffect(() => {
    void call<{ events: VaultEvent[] }>("/api/v1/activity?limit=1000").then(
      (r) => setEvents(r.events),
      () => setEvents([]),
    );
    void call<{ leavers: Leaver[] }>("/api/v1/leavers").then(
      (r) => setLeaving(new Set(r.leavers.map((l) => l.email))),
      () => {},
    );
  }, [call]);

  const rows = (events ?? []).filter((e) => vault === "all" || e.vaults.includes(vault));
  const cols: Column<VaultEvent>[] = [
    {
      id: "when",
      header: t("activity.when"),
      width: "130px",
      sortValue: (e) => e.at,
      cell: (e) => <span className="text-xs whitespace-nowrap">{date(e.at, true)}</span>,
    },
    {
      id: "who",
      header: t("activity.who"),
      sortValue: (e) => e.actor?.name ?? "",
      cell: (e) => (
        <span className="flex items-center gap-1.5">
          <Avatar name={e.actor?.name ?? "?"} size="sm" />
          <span className="truncate">{e.actor?.name ?? t("activity.someone")}</span>
          {e.actor && leaving.has(e.actor.email) && <Badge tone="warning">{t("activity.leaving")}</Badge>}
        </span>
      ),
    },
    { id: "what", header: t("activity.did"), cell: (e) => <StatusBadge tone={TONE[e.action]}>{t(`action.${e.action}`)}</StatusBadge> },
    {
      id: "item",
      header: t("activity.item"),
      width: "24%",
      cell: (e) => <span className="truncate font-medium">{items.get(e.itemId)?.name || t("activity.anItem")}</span>,
    },
    { id: "vault", header: t("activity.vault"), cell: (e) => <span className="text-xs">{e.vaults.map(vaultName).join(", ") || "–"}</span> },
    {
      id: "from",
      header: t("activity.from"),
      width: "22%",
      cell: (e) => <span className="block truncate text-xs text-fg-muted">{[deviceName(e.deviceType), e.ip].filter(Boolean).join(", ")}</span>,
    },
  ];

  return (
    <>
      <PageHeader title={t("activity.title")} description={t("activity.description")} />
      <Panel flush>
        <div className="px-3 pt-2">
          <Tabs
            label={t("activity.vault")}
            value={vault}
            onChange={setVault}
            items={[
              { value: "all", label: t("activity.allVaults"), count: events?.length ?? 0 },
              ...vaults.map((v) => ({ value: v.id, label: v.name, count: (events ?? []).filter((e) => e.vaults.includes(v.id)).length })),
            ]}
            className="border-b-0"
          />
        </div>
        <div className="border-t border-line">
          <DataTable
            label={t("activity.title")}
            columns={cols}
            rows={rows}
            getRowId={(e) => e.id}
            minWidth={860}
            loading={!events}
            empty={t("activity.none")}
            pageSize={50}
          />
        </div>
      </Panel>
    </>
  );
}

export function ActivityPage({ call }: { call: Call }) {
  const t = useT();
  return (
    <RequireUnlock reason={t("activity.unlock")}>
      <ActivityView call={call} />
    </RequireUnlock>
  );
}
