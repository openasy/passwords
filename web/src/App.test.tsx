// @vitest-environment jsdom
// The pages in a browser: signed in as Emily Clark, who unlocks her vault and goes through each page. The API answers
// as the server does, and /api/v1/vault as Vaultwarden does through it, with a real encrypted account.
import { webcrypto } from "node:crypto";
import { TextDecoder, TextEncoder } from "node:util";
import { navigate, type Colophon } from "@openasy/ui";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { App } from "./App.tsx";
import { EMAIL, ORG, PASSWORD, vaultServer } from "./test-vault.ts";

// jsdom's own encoder and crypto make arrays of another realm, which Node's WebCrypto refuses.
Object.assign(globalThis, { TextEncoder, TextDecoder });
Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;
window.matchMedia ??= ((query: string) => ({
  matches: false,
  media: query,
  addEventListener() {},
  removeEventListener() {},
  addListener() {},
  removeListener() {},
  onchange: null,
  dispatchEvent: () => false,
})) as unknown as typeof window.matchMedia;

const vault = vaultServer();
const now = "2026-11-04T09:00:00.000Z";
const finance = { id: "finance", name: "Finance", access: [{ group: "finance", access: "edit" }], collectionId: "col-finance" };
const API: Record<string, unknown> = {
  "/api/v1/auth/me": {
    user: {
      id: "u1",
      email: EMAIL,
      name: "Emily Clark",
      role: "admin",
      status: "active",
      createdAt: now,
      lastSignInAt: now,
      mfa: { totp: true, passkeys: 0 },
      providers: [],
    },
    session: { id: "s1", method: "password", mfa: true, factor: "totp" },
    passwordManagedBy: null,
    mfaSetupRequired: false,
    hasPassword: true,
    passkeys: [],
    recoveryCodesLeft: 10,
    managedBy: null,
    preferences: { name: "Emily Clark", theme: null, locale: "en" },
  },
  "/api/v1/auth/methods": { passwords: true, providers: [], setup: false, brand: {} },
  "/api/v1/auth/me/preferences": { name: "Emily Clark", theme: null, locale: "en" },
  "/api/v1/products": { products: [] },
  "/api/v1/vault/settings": {
    email: EMAIL,
    organizationId: ORG,
    vaultwardenUrl: "https://vault.example.com",
    leakCheck: false,
    member: { id: "m0", status: 2, type: 1 },
    generator: { minLength: 24, useUpper: true, useLower: true, useNumbers: true, useSpecial: true },
  },
  "/api/v1/vaults": {
    vaults: [
      { ...finance, members: [{ name: "Emily Clark", email: EMAIL, access: "edit", group: "finance" }] },
      { id: "sales", name: "Sales", access: [{ group: "sales", access: "edit" }], collectionId: null, members: [] },
    ],
    file: null,
  },
  "/api/v1/confirmations": { members: [{ id: "m-1", email: "ali.yilmaz@example.com", name: "Ali Yılmaz" }] },
  "/api/v1/activity": {
    events: [
      {
        id: "e1",
        at: "2026-11-04T09:12:00Z",
        type: 1111,
        action: "copied",
        actor: { email: "mark.wilson@example.com", name: "Mark Wilson" },
        itemId: "bank",
        vaults: ["finance"],
        collections: ["col-finance"],
        deviceType: 3,
        ip: "203.0.113.7",
      },
    ],
  },
  "/api/v1/leavers": {
    leavers: [
      {
        id: 1,
        email: "mark.wilson@example.com",
        name: "Mark Wilson",
        reason: "planned",
        leavesOn: "2026-11-30",
        leftAt: null,
        items: [{ itemId: "bank", vaults: ["finance"], lastOpened: "2026-11-04T09:12:00Z", recent: true, changed: false, changedBy: null, deleted: false }],
        changed: 0,
      },
    ],
  },
  "/api/v1/summary": {
    vaults: 2,
    groups: 2,
    members: 4,
    waiting: 1,
    keyHolders: 1,
    missing: ["sales"],
    policies: { twoStepLogin: true, masterPassword: { minLength: 14, minComplexity: 3 }, passwordGenerator: null, disableSend: false },
    file: { path: "/config/passwords.yaml", appliedAt: now, vaults: 2, groups: 2, error: null },
    sync: { at: now, ok: true, added: [], removed: [], vaults: [], missing: ["sales"], policies: [], notes: [], error: null },
    identity: "https://id.example.com",
    organizationId: ORG,
    vaultwardenUrl: "https://vault.example.com",
    leakCheck: false,
    features: { email: "passwords-service@example.com", groups: true, events: true },
  },
};

const fetchMock = (async (input: string | URL | Request, init?: RequestInit) => {
  const path = String(input).split("?")[0]!;
  if (path.startsWith("/api/v1/vault/") && path !== "/api/v1/vault/settings") return vault.fetch(path, init);
  if (path in API) return new Response(JSON.stringify(API[path]), { headers: { "content-type": "application/json" } });
  return new Response(JSON.stringify({ code: "not-found", detail: path }), { status: 404, headers: { "content-type": "application/problem+json" } });
}) as typeof fetch;
globalThis.fetch = fetchMock;
window.fetch = fetchMock;

const root = document.createElement("div");
document.body.append(root);
const app = createRoot(root);

/** Waits until the page shows a text. */
async function see(text: string | RegExp, timeout = 15_000) {
  const start = Date.now();
  for (;;) {
    const body = document.body.textContent ?? "";
    if (typeof text === "string" ? body.includes(text) : text.test(body)) return;
    if (Date.now() - start > timeout) throw new Error(`Never saw ${text}. The page shows: ${body.slice(0, 600)}`);
    await act(() => new Promise((r) => setTimeout(r, 20)));
  }
}

function type(input: HTMLInputElement, value: string) {
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

beforeAll(async () => {
  window.history.replaceState(null, "", "/vaults");
  await act(async () =>
    app.render(
      <App
        about={{ version: "test", license: "AGPL-3.0-only", repository: "https://github.com/openasy/passwords", libraries: [], openasy: [] } satisfies Colophon}
      />,
    ),
  );
});
afterAll(() => act(() => app.unmount()));

describe("the pages", () => {
  it("unlock the vault in the browser and show the shared vault with its item", async () => {
    await see("Unlock your vault");
    const password = document.querySelector<HTMLInputElement>('input[type="password"]')!;
    await act(async () => type(password, PASSWORD));
    await act(async () => password.form!.requestSubmit());
    await see("Corporate banking");
    expect(document.body.textContent).toContain("acme-treasury");
    // The password stays hidden until asked for.
    expect(document.body.textContent).not.toContain("hT9#vQ2m!xR4-Lp7w");
    const show = [...document.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Show password")!;
    await act(async () => show.click());
    expect(document.body.textContent).toContain("hT9#vQ2m!xR4-Lp7w");
    // Admin tasks: a person to confirm and a vault of the file to create.
    await see("1 person waits to be confirmed");
    await see("Sales is not on the password server yet");
  });

  // Encrypting in the page takes a few seconds on a shared CI runner, so this one gets 30.
  it("add an item to the open shared vault, encrypted before it leaves the page, then change and remove it", async () => {
    const button = (name: string) =>
      [...document.querySelectorAll("button")].find((b) => (b.textContent ?? b.getAttribute("aria-label")) === name || b.getAttribute("aria-label") === name)!;
    // In the open dialog when there is one: the item's own page behind it has labels of the same name.
    const field = (label: string) => {
      const scope = document.querySelector('[role="dialog"]') ?? document;
      const l = [...scope.querySelectorAll("label")].find((x) => x.textContent === label)!;
      return document.getElementById(l.htmlFor) as HTMLInputElement;
    };
    await act(async () =>
      [...document.querySelectorAll<HTMLButtonElement>('[aria-label="Your vaults"] button')].find((b) => b.textContent?.startsWith("Finance"))!.click(),
    );
    await act(async () => button("New item").click());
    await see("Encrypted in this browser before it is saved");
    expect(field("Vault").value).toBe("col-finance");
    await act(async () => type(field("Name"), "Payroll provider"));
    await act(async () => type(field("User name"), "finance@acme.example"));
    await act(async () => button("Make a strong password").click());
    const made = field("Password").value;
    // The file's generator policy asks for 24 characters.
    expect(made).toHaveLength(24);
    await act(async () => field("Name").form!.requestSubmit());
    await see("Payroll provider");
    const sent = vault.sent.find((r) => r.path === "/api/v1/vault/items")!;
    expect(JSON.parse(sent.body)).toMatchObject({ collectionIds: ["col-finance"], cipher: { organizationId: ORG, encryptedFor: "user-emily", type: 1 } });
    expect(sent.body).not.toContain("Payroll");
    expect(sent.body).not.toContain(made);

    // Changing the password keeps the old one in the item's history.
    await act(async () => [...document.querySelectorAll("tr")].find((r) => r.textContent?.includes("Payroll provider"))!.click());
    await act(async () => button("Edit").click());
    await see("Change Payroll provider");
    await act(async () => type(field("Password"), "a-New-password-2026!"));
    await see("The old password is kept in the item's history.");
    await act(async () => field("Name").form!.requestSubmit());
    await see("1 earlier password");
    expect(vault.written[0]!.passwordHistory).toHaveLength(1);

    await act(async () => button("Put in the trash").click());
    await see("Put Payroll provider in the trash?");
    await act(async () =>
      [...document.querySelectorAll('[role="dialog"] button')]
        .find((b) => b.textContent === "Put in the trash")!
        .dispatchEvent(new MouseEvent("click", { bubbles: true })),
    );
    for (let i = 0; i < 100 && (document.body.textContent ?? "").includes("Payroll provider"); i++) await act(() => new Promise((r) => setTimeout(r, 20)));
    expect(document.body.textContent).not.toContain("Payroll provider");
  }, 30_000);

  it("show Health, Leavers, Activity and the password server", async () => {
    await act(async () => navigate("/health"));
    await see("By team");
    await act(async () => navigate("/leavers"));
    await see(/Mark Wilson leaves on/);
    await see("Change first");
    await act(async () => navigate("/activity"));
    await see("Firefox extension, 203.0.113.7");
    await act(async () => navigate("/server"));
    await see("Only 1 person can open every shared vault");
    await see("Account recovery");
  });
});
