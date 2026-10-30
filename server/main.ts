import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { watchConfig } from "./config.ts";
import { openDb } from "./db.ts";
import { createIdentity } from "./identity.ts";
import { log } from "./log.ts";
import { createPasswords } from "./passwords.ts";
import { parseProducts } from "./products.ts";
import { createVaultwarden } from "./vaultwarden.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.PASSWORDS_DB ?? "/data/passwords.db";
const configPath = process.env.PASSWORDS_CONFIG?.trim() || "/config/passwords.yaml";
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.PASSWORDS_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.PASSWORDS_METRICS_PORT ? Number(process.env.PASSWORDS_METRICS_PORT) : undefined;

// The address people open Passwords at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.PASSWORDS_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const vaultwardenUrl = process.env.PASSWORDS_VAULTWARDEN_URL?.trim() || "http://vaultwarden:80";
// The address the Bitwarden apps are pointed at; shown to people, never called by the server.
const vaultwardenPublicUrl = (process.env.PASSWORDS_VAULTWARDEN_PUBLIC_URL?.trim() || vaultwardenUrl).replace(/\/$/, "");
const organizationId = process.env.PASSWORDS_ORGANIZATION_ID?.trim() ?? "";
const serviceClientId = process.env.PASSWORDS_SERVICE_CLIENT_ID?.trim() ?? "";
if (!organizationId) throw new Error("PASSWORDS_ORGANIZATION_ID is missing: the id of the company's organization in Vaultwarden.");
if (!serviceClientId.startsWith("user.")) throw new Error("PASSWORDS_SERVICE_CLIENT_ID is missing: the service account's API key client_id, user.<uuid>.");

/** A secret from the environment, or from its mounted file. */
function secret(env: string, file: string, required: boolean): string {
  const path = process.env[`${env}_FILE`] ?? file;
  const value = process.env[env] ?? (existsSync(path) ? readFileSync(path, "utf8").trim() : "");
  if (!value && required) throw new Error(`${env} is missing: mount it at ${path} or set ${env}.`);
  return value;
}
const orgSecret = secret("PASSWORDS_ORGANIZATION_SECRET", "/run/secrets/vaultwarden-org-key", true);
const serviceSecret = secret("PASSWORDS_SERVICE_SECRET", "/run/secrets/vaultwarden-service-key", true);
const identityUrl = process.env.PASSWORDS_IDENTITY_URL?.trim() ?? "";
const identityToken = secret("PASSWORDS_IDENTITY_TOKEN", "/run/secrets/identity-token", false);

const db = openDb(dbPath);
const secretsKeyFile = process.env.PASSWORDS_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
let started: ReturnType<typeof createPasswords> | undefined;
const auth = createAuth({
  db,
  product: "passwords",
  productName: "OpenAsy Passwords",
  origin: publicUrl,
  // Locally the same Passwords is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.PASSWORDS_PASSWORD_SIGN_IN !== "false",
  // Everyone with a vault signs in to open it; only some of them manage Passwords.
  users: true,
  oidc: oidcFromEnv(process.env, "PASSWORDS_"),
  secretsKey: readSecretsKey(secretsKeyFile),
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens. A sign-in also brings the person's
  // groups in step soon, so a change in Identity reaches their vaults without waiting five minutes.
  onEvent: (event) => {
    log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event });
    if (event.type === "sign-in") void started?.syncNow();
  },
});
const vaultwarden = createVaultwarden({ url: vaultwardenUrl, organizationId, orgSecret, serviceClientId, serviceSecret });
const identity = identityUrl && identityToken ? createIdentity({ url: identityUrl, token: identityToken }) : null;
if (!identity) log("warn", "Identity is not connected: set PASSWORDS_IDENTITY_URL and PASSWORDS_IDENTITY_TOKEN, so members and groups follow it");
const leakCheck = process.env.PASSWORDS_LEAK_CHECK !== "false";
let file: ReturnType<typeof watchConfig> | undefined;
const passwords = createPasswords(db, vaultwarden, identity, { vaultwardenUrl: vaultwardenPublicUrl, leakCheck, fileState: () => file?.state ?? null });
started = passwords;
// The vaults come from the file and only from it; a file with a mistake keeps the last good one in place.
file = watchConfig(configPath, (config) => void passwords.setConfig(config), {
  onChange: (state) =>
    state.error
      ? log("warn", "vaults file not applied: the last good version stays until it is fixed", { file: state.path, error: state.error })
      : log("info", "vaults file applied", { file: state.path, vaults: state.vaults, groups: state.groups }),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });
const server = createServer(
  createApp({
    db,
    passwords,
    vaultwarden,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(passwords, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () =>
  log("info", "passwords started", {
    version,
    port,
    db: dbPath,
    config: configPath,
    vaultwarden: vaultwardenUrl,
    identity: identityUrl || null,
    leakCheck,
    headless,
  }),
);
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "PASSWORDS_PUBLIC_URL is not https: browsers will not keep secure cookies, allow passkeys or WebCrypto. Put Passwords behind TLS (ADR 0026)", {
    url: publicUrl,
  });
}
if (auth.secretsInClear)
  log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", { file: secretsKeyFile });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

const timers: NodeJS.Timeout[] = [
  setInterval(() => auth.purge(), 5 * 60_000),
  // People who left Identity's groups are removed, changes made in Vaultwarden by hand are put back, and the event log
  // is read.
  setInterval(() => void passwords.syncNow(), 5 * 60_000),
];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  file?.stop();
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
