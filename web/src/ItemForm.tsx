// Adding, changing, moving and removing an item, over the Vaults page. What is typed here is encrypted in this browser
// (items.ts) before it is sent; the form's values live in this page's memory only.
import { Badge, Button, Callout, Dialog, IconButton, SegmentedControl, SelectField, TextField, type Tone } from "@openasy/ui";
import { Eye, EyeOff, RefreshCw } from "lucide-react";
import { useId, useState, type FormEvent } from "react";
import { strength } from "./health.ts";
import { useT } from "./i18n.ts";
import { emptyDraft, generatePassword, type Draft, type EditableKind } from "./items.ts";
import { parseTotp } from "./totp.ts";
import { useVault } from "./Unlock.tsx";
import { SessionEnded, type Collection, type Item } from "./vault.ts";

const STRENGTH_TONE: Record<string, Tone> = { strong: "success", fair: "warning", weak: "danger" };

/** The collections a person may add items to: edit or manage, not read only. */
export const writable = (collections: Collection[]) => collections.filter((c) => !c.readOnly);

function draftOf(item: Item): Draft {
  const [month, year] = item.card?.expiry?.split("/") ?? [];
  return {
    kind: item.kind as EditableKind,
    name: item.name,
    notes: item.notes ?? "",
    username: item.username ?? "",
    password: item.password ?? "",
    totp: item.totp ?? "",
    uri: item.uris[0] ?? "",
    card: {
      holder: item.card?.holder ?? "",
      brand: item.card?.brand ?? "",
      number: item.card?.number ?? "",
      expMonth: month ? String(Number(month)) : "",
      expYear: year ?? "",
      code: item.card?.code ?? "",
    },
  };
}

/** Runs a change and turns its failure into the message to show; a session that ended signs out. */
function useWork(onDone: () => void) {
  const { refresh } = useVault();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(undefined);
    try {
      await work();
      await refresh();
      onDone();
    } catch (e) {
      if (e instanceof SessionEnded) return void (await refresh());
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run, clear: () => setError(undefined) };
}

function Notes({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const t = useT();
  const id = useId();
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium text-fg">
        {t("form.notes")}
      </label>
      <textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="pw-notes w-full rounded-md border border-line-strong bg-surface px-2.5 py-1.5 text-sm text-fg"
      />
    </div>
  );
}

export interface ItemDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The item to change; without it, a new item. */
  item?: Item;
  /** For a new item: the vault that is open, "personal" or a collection id. */
  vault?: string;
  onSaved?: () => void;
}

export function ItemDialog({ open, onOpenChange, item, vault = "personal", onSaved }: ItemDialogProps) {
  const t = useT();
  const { session, settings } = useVault();
  const targets = writable(session?.collections ?? []);
  const [draft, setDraft] = useState<Draft>(() => (item ? draftOf(item) : emptyDraft()));
  const [target, setTarget] = useState(() => (vault !== "personal" && targets.some((c) => c.id === vault) ? vault : "personal"));
  const [shown, setShown] = useState(!item);
  const [nameError, setNameError] = useState<string>();
  const work = useWork(() => {
    onOpenChange(false);
    onSaved?.();
  });
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }));
  const setCard = (patch: Partial<Draft["card"]>) => setDraft((d) => ({ ...d, card: { ...d.card, ...patch } }));
  const s = draft.password ? strength(draft.password) : null;
  const totpBad = draft.kind === "login" && draft.totp.trim() !== "" && !parseTotp(draft.totp.trim());

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!draft.name.trim()) return setNameError(t("form.nameNeeded"));
    if (totpBad || !session) return;
    void work.run(() => (item ? session.updateItem(item, draft) : session.addItem(draft, target === "personal" ? null : target)));
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={item ? t("form.editTitle", { name: item.name || t("item.unnamed") }) : t("form.newTitle")}
      description={t("form.e2e")}
      onSubmit={submit}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" loading={work.busy}>
            {item ? t("form.save") : t("form.add")}
          </Button>
        </>
      }
    >
      {work.error && (
        <Callout tone="danger" title={t("form.failed")} onDismiss={work.clear}>
          {work.error}
        </Callout>
      )}
      {!item && (
        <>
          <SegmentedControl
            className="pw-self-start"
            label={t("form.kind")}
            value={draft.kind}
            onChange={(kind) => set({ kind })}
            options={(["login", "note", "card"] as const).map((k) => ({ value: k, label: t(`form.kinds.${k}`) }))}
          />
          <SelectField
            label={t("form.vault")}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            options={[{ value: "personal", label: t("vaults.mine") }, ...targets.map((c) => ({ value: c.id, label: c.name }))]}
          />
        </>
      )}
      <TextField
        label={t("form.name")}
        value={draft.name}
        onChange={(e) => (set({ name: e.target.value }), setNameError(undefined))}
        error={nameError}
        required
      />
      {draft.kind === "login" && (
        <>
          <TextField label={t("item.username")} value={draft.username} onChange={(e) => set({ username: e.target.value })} mono autoComplete="off" />
          <TextField
            label={t("item.password")}
            type={shown ? "text" : "password"}
            value={draft.password}
            onChange={(e) => set({ password: e.target.value })}
            mono
            autoComplete="new-password"
            hint={
              s ? (
                <span className="flex items-center gap-1.5">
                  <Badge tone={STRENGTH_TONE[s]}>{t(`strength.${s}`)}</Badge>
                  {item?.password && draft.password !== item.password && t("form.keptInHistory")}
                </span>
              ) : undefined
            }
            adornment={
              <span className="flex items-center gap-0.5">
                <IconButton
                  type="button"
                  size="xs"
                  label={shown ? t("item.hide", { field: t("item.password").toLowerCase() }) : t("item.show", { field: t("item.password").toLowerCase() })}
                  onClick={() => setShown((v) => !v)}
                >
                  {shown ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                </IconButton>
                <IconButton
                  type="button"
                  size="xs"
                  label={t("form.generate")}
                  onClick={() => (set({ password: generatePassword(settings?.generator ?? null) }), setShown(true))}
                >
                  <RefreshCw className="size-3.5" />
                </IconButton>
              </span>
            }
          />
          <TextField
            label={t("form.totp")}
            value={draft.totp}
            onChange={(e) => set({ totp: e.target.value })}
            mono
            autoComplete="off"
            hint={t("form.totpHint")}
            error={totpBad ? t("form.totpBad") : undefined}
          />
          <TextField label={t("form.uri")} value={draft.uri} onChange={(e) => set({ uri: e.target.value })} placeholder="https://" type="url" />
          {item && item.uris.length > 1 && <p className="m-0 text-xs text-fg-muted">{t("form.moreUris", { count: item.uris.length - 1 })}</p>}
        </>
      )}
      {draft.kind === "card" && (
        <>
          <TextField label={t("item.holder")} value={draft.card.holder} onChange={(e) => setCard({ holder: e.target.value })} autoComplete="off" />
          <TextField
            label={t("item.number")}
            value={draft.card.number}
            onChange={(e) => setCard({ number: e.target.value })}
            mono
            inputMode="numeric"
            autoComplete="off"
          />
          <div className="pw-row">
            <TextField
              label={t("form.expMonth")}
              value={draft.card.expMonth}
              onChange={(e) => setCard({ expMonth: e.target.value })}
              inputMode="numeric"
              placeholder="7"
            />
            <TextField
              label={t("form.expYear")}
              value={draft.card.expYear}
              onChange={(e) => setCard({ expYear: e.target.value })}
              inputMode="numeric"
              placeholder="2029"
            />
            <TextField label={t("item.cardCode")} value={draft.card.code} onChange={(e) => setCard({ code: e.target.value })} mono inputMode="numeric" />
          </div>
          <TextField label={t("form.brand")} value={draft.card.brand} onChange={(e) => setCard({ brand: e.target.value })} placeholder="Visa" />
        </>
      )}
      <Notes value={draft.notes} onChange={(notes) => set({ notes })} />
    </Dialog>
  );
}

/** Moves a personal item into a shared vault the person may add to. */
export function MoveDialog({ open, onOpenChange, item }: { open: boolean; onOpenChange: (open: boolean) => void; item: Item }) {
  const t = useT();
  const { session } = useVault();
  const targets = writable(session?.collections ?? []);
  const [target, setTarget] = useState(targets[0]?.id ?? "");
  const work = useWork(() => onOpenChange(false));
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("form.moveTitle", { name: item.name || t("item.unnamed") })}
      description={t("form.moveDetail")}
      onSubmit={(e) => {
        e.preventDefault();
        if (session && target) void work.run(() => session.moveItem(item, target));
      }}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" loading={work.busy} disabled={!target}>
            {t("form.move")}
          </Button>
        </>
      }
    >
      {work.error && (
        <Callout tone="danger" title={t("form.failed")} onDismiss={work.clear}>
          {work.error}
        </Callout>
      )}
      {targets.length ? (
        <SelectField
          label={t("form.vault")}
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          options={targets.map((c) => ({ value: c.id, label: c.name }))}
        />
      ) : (
        <p className="m-0 text-sm text-fg-muted">{t("form.noTargets")}</p>
      )}
    </Dialog>
  );
}

/** Puts an item in the trash, after asking. */
export function DeleteDialog({ open, onOpenChange, item }: { open: boolean; onOpenChange: (open: boolean) => void; item: Item }) {
  const t = useT();
  const { session } = useVault();
  const work = useWork(() => onOpenChange(false));
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      size="sm"
      title={t("form.deleteTitle", { name: item.name || t("item.unnamed") })}
      description={item.organizationId ? t("form.deleteShared") : t("form.deleteMine")}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" loading={work.busy} onClick={() => session && void work.run(() => session.deleteItem(item))}>
            {t("form.delete")}
          </Button>
        </>
      }
    >
      {work.error && (
        <Callout tone="danger" title={t("form.failed")} onDismiss={work.clear}>
          {work.error}
        </Callout>
      )}
    </Dialog>
  );
}
