// What someone who leaves could see, so it is changed before or right after they go. Passwords learns of a leaver from
// Identity, when it disables them or they leave every group of the file, or from an editor who sets their last day
// here; either way they are removed from the organization at once, and the shared items they could see are listed,
// the recently opened first. The item names are decrypted in this browser.
import {
  Avatar,
  Badge,
  Button,
  Callout,
  Checkbox,
  DataTable,
  Dialog,
  EmptyState,
  PageHeader,
  Panel,
  StatusBadge,
  TextField,
  cn,
  type Column,
} from "@openasy/ui";
import { useAuth } from "@openasy/auth/react";
import { UserMinus } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import type { Call, Leaver, LeaverItem } from "./api.ts";
import { useDate } from "./format.ts";
import { useT } from "./i18n.ts";
import { RequireUnlock, useItems, useVaultNames } from "./Unlock.tsx";

function LeaversView({ call }: { call: Call }) {
  const t = useT();
  const date = useDate();
  const { can } = useAuth();
  const items = useItems();
  const vaultName = useVaultNames();
  const [leavers, setLeavers] = useState<Leaver[]>();
  const [selected, setSelected] = useState<number | null>(null);
  const [error, setError] = useState<string>();
  const [planning, setPlanning] = useState(false);
  const [email, setEmail] = useState("");
  const [leavesOn, setLeavesOn] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(
    () =>
      void call<{ leavers: Leaver[] }>("/api/v1/leavers").then(
        (r) => setLeavers(r.leavers),
        (e: Error) => setError(e.message),
      ),
    [call],
  );
  useEffect(load, [load]);

  const editor = can("editor");
  const current =
    leavers?.find((l) => l.id === selected) ?? leavers?.find((l) => !l.leftAt) ?? leavers?.find((l) => l.changed < l.items.length) ?? leavers?.[0];
  const earlier = (leavers ?? []).filter((l) => l !== current);

  async function mark(x: LeaverItem) {
    if (!current) return;
    try {
      const updated = await call<LeaverItem>(`/api/v1/leavers/${current.id}/items/${encodeURIComponent(x.itemId)}`, {
        method: "PUT",
        body: JSON.stringify({ changed: !x.changed }),
      });
      setLeavers((ls) =>
        ls?.map((l) =>
          l.id !== current.id
            ? l
            : {
                ...l,
                items: l.items.map((i) => (i.itemId === x.itemId ? updated : i)),
                changed: l.items.filter((i) => (i.itemId === x.itemId ? updated.changed : i.changed)).length,
              },
        ),
      );
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function plan() {
    setBusy(true);
    setError(undefined);
    try {
      const made = await call<Leaver>("/api/v1/leavers", { method: "POST", body: JSON.stringify({ email, leavesOn }) });
      setPlanning(false);
      setEmail("");
      setLeavesOn("");
      setSelected(made.id);
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function cancel(l: Leaver) {
    try {
      await call(`/api/v1/leavers/${l.id}`, { method: "DELETE" });
      setSelected(null);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  const first = current?.name.split(" ")[0] ?? "";
  const cols: Column<LeaverItem>[] = [
    {
      id: "changed",
      header: t("leavers.changed"),
      width: "92px",
      cell: (x) => (
        <Checkbox
          label={<span className="sr-only">{t("leavers.changedItem", { name: items.get(x.itemId)?.name ?? x.itemId })}</span>}
          checked={x.changed}
          disabled={!editor}
          onChange={() => void mark(x)}
        />
      ),
    },
    {
      id: "item",
      header: t("leavers.item"),
      width: "34%",
      sortValue: (x) => items.get(x.itemId)?.name ?? "",
      cell: (x) => {
        const item = items.get(x.itemId);
        return item ? (
          <span className={cn("font-medium", x.changed && "text-fg-muted line-through")}>{item.name || t("item.unnamed")}</span>
        ) : (
          <span className="text-xs text-fg-muted">{x.deleted ? t("leavers.deleted") : t("leavers.cannotOpen")}</span>
        );
      },
    },
    {
      id: "vault",
      header: t("leavers.vault"),
      sortValue: (x) => x.vaults.map(vaultName).join(", "),
      cell: (x) => <span className="text-xs">{x.vaults.map(vaultName).join(", ")}</span>,
    },
    {
      id: "opened",
      header: t("leavers.lastOpenedBy", { name: first }),
      sortValue: (x) => (x.recent ? `0${x.lastOpened}` : `1${x.lastOpened ?? ""}`),
      cell: (x) => (
        <span className="flex items-center gap-1.5 text-xs">
          {x.lastOpened ? date(x.lastOpened) : t("leavers.never")}
          {x.recent && !x.changed && <Badge tone="warning">{t("leavers.changeFirst")}</Badge>}
        </span>
      ),
    },
  ];

  const vaultsOf = current ? [...new Set(current.items.flatMap((i) => i.vaults))].map(vaultName) : [];

  return (
    <>
      <PageHeader
        title={t("leavers.title")}
        description={t("leavers.description")}
        actions={
          editor && (
            <Button variant="primary" icon={<UserMinus />} onClick={() => setPlanning(true)}>
              {t("leavers.plan")}
            </Button>
          )
        }
      />
      {error && (
        <Callout tone="danger" title={t("leavers.failed")} onDismiss={() => setError(undefined)} className="mb-3">
          {error}
        </Callout>
      )}
      {leavers && leavers.length === 0 ? (
        <EmptyState icon={<UserMinus />} title={t("leavers.none")}>
          {t("leavers.noneDetail")}
        </EmptyState>
      ) : (
        <div className="pw-side">
          <div className="flex flex-col gap-2.5">
            {current && (
              <Callout
                tone={current.leftAt ? "info" : "warning"}
                title={
                  current.leftAt
                    ? t("leavers.left", { name: current.name, date: date(current.leftAt) })
                    : t("leavers.leaves", { name: current.name, date: date(current.leavesOn) })
                }
                action={
                  editor &&
                  !current.leftAt && (
                    <Button size="sm" variant="ghost" onClick={() => void cancel(current)}>
                      {t("leavers.cancel")}
                    </Button>
                  )
                }
              >
                {t(`leavers.reason.${current.reason}`, { name: first })}{" "}
                {t("leavers.couldSee", { name: first, count: current.items.length, vaults: vaultsOf.join(", ") || "–" })}
              </Callout>
            )}
            {current && (
              <Panel
                title={t("leavers.whatTheySaw", { name: current.name })}
                actions={
                  <Badge tone={current.changed === current.items.length ? "success" : "neutral"} mono>
                    {t("leavers.progress", { done: current.changed, count: current.items.length })}
                  </Badge>
                }
                flush
              >
                <DataTable
                  label={t("leavers.toChange")}
                  columns={cols}
                  rows={current.items}
                  getRowId={(x) => x.itemId}
                  defaultSort={{ id: "opened", direction: "asc" }}
                  minWidth={620}
                  empty={t("leavers.nothing")}
                />
              </Panel>
            )}
          </div>
          <Panel title={t("leavers.earlier")} flush className="self-start">
            <ul aria-label={t("leavers.earlier")} className="m-0 flex list-none flex-col p-0">
              {earlier.length === 0 && <li className="px-3 py-2 text-sm text-fg-muted">{t("leavers.noEarlier")}</li>}
              {earlier.map((l) => (
                <li key={l.id} className="border-b border-subtle last:border-0">
                  <button
                    type="button"
                    onClick={() => setSelected(l.id)}
                    className="flex w-full items-center justify-between gap-2 border-0 bg-transparent px-3 py-2 text-start hover:bg-canvas"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <Avatar name={l.name} size="sm" />
                      <span className="flex min-w-0 flex-col">
                        <span className="truncate text-sm font-medium text-fg">{l.name}</span>
                        <span className="text-2xs text-fg-muted">
                          {l.leftAt ? t("leavers.leftOn", { date: date(l.leftAt) }) : t("leavers.leavesOn", { date: date(l.leavesOn) })}
                        </span>
                      </span>
                    </span>
                    <StatusBadge tone={l.changed === l.items.length ? "success" : "warning"}>
                      {t("leavers.progress", { done: l.changed, count: l.items.length })}
                    </StatusBadge>
                  </button>
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      )}
      <Dialog
        open={planning}
        onOpenChange={setPlanning}
        title={t("leavers.plan")}
        description={t("leavers.planDetail")}
        onSubmit={(e) => {
          e.preventDefault();
          void plan();
        }}
        footer={
          <>
            <Button type="button" variant="secondary" onClick={() => setPlanning(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="primary" loading={busy} disabled={!email.trim() || !leavesOn}>
              {t("leavers.planSave")}
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-3">
          <TextField label={t("leavers.email")} type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <TextField label={t("leavers.lastDay")} type="date" value={leavesOn} onChange={(e) => setLeavesOn(e.target.value)} />
        </div>
      </Dialog>
    </>
  );
}

export function LeaversPage({ call }: { call: Call }) {
  const t = useT();
  return (
    <RequireUnlock reason={t("leavers.unlock")}>
      <LeaversView call={call} />
    </RequireUnlock>
  );
}
