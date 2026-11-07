# passwords

[![CI](https://github.com/openasy/passwords/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/passwords/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Passwords product: a password manager for the team, in your install. Each
person has a vault and each team shared ones, on [Vaultwarden](https://github.com/dani-garcia/vaultwarden), the
open-source server the official Bitwarden apps and browser extensions work with. Which Identity group sees which shared
vault is set in a file; someone who leaves loses access at once, with a list of what they could see.

```
passwords.yaml ──▶ passwords ── directory import, admin API ──▶ Vaultwarden ◀── Bitwarden apps, browser extensions
Identity groups ──▶   │  ▲                                          ▲
                      │  └── people's groups and who left           │
          browser ────┴── /api/v1/vault, passed on as it is ────────┘
   (keys and items decrypted here, and only here)
```

## End-to-end encryption

Vaultwarden keeps every vault encrypted with keys that only people's devices hold, as Bitwarden does. Passwords keeps
that rule: its server never sees a master password, a master key, a user key, the organization's key or a decrypted
item or name. In Passwords' pages, the browser does what the Bitwarden web vault does, with WebCrypto
(`web/src/crypto.ts`): it derives the master key (PBKDF2-SHA256 or Argon2id) and the master password hash, signs in to
Vaultwarden with the hash, opens the user key, the private key, the organization's key and the items, and holds them in
the page's memory only. Locking, leaving the page or 15 minutes without use forgets them. Requests go through
`/api/v1/vault`, which passes them to Vaultwarden as they are and logs neither bodies nor query strings; it always
signs in as the signed-in person, so nobody can try someone else's master password through it.

What the server does see, and keeps: who is a member of the organization, the groups, which item is in which vault and
when it changed (never its content), and Vaultwarden's event log (who opened or changed which item id, from which device
type and address).

Health, the names in Activity and Leavers, and the vault names are decrypted in the browser of the person looking.

## The vaults file

The shared vaults, who may see or change each, and the policies are set in `/config/passwords.yaml`
(`PASSWORDS_CONFIG`):

```yaml
vaults:
  - id: finance
    name: Finance
    access:
      finance-leads: manage
      finance: edit
  - id: office
    name: Office
    access: { everyone: read }
policies:
  twoStepLogin: true
  masterPassword: { minLength: 14, minComplexity: 3 }
```

The file is the only way in: no screen and no API route adds, changes or removes a vault, an access or a policy, so it
can live in git and be reviewed like code. It is read at start and again within a minute of a change, and applied
whole or not at all. A file with a mistake leaves the last good version in place, and the log and the Password server
page say which vault and field to fix.

| Field | | |
| --- | --- | --- |
| `vaults[].id` | required | Lowercase letters, digits and dashes. The collection's external id in Vaultwarden: keep it when you rename |
| `vaults[].name` | required | What people see |
| `vaults[].access` | | Identity group names, each `read` (see and use the items), `edit` (also add and change them) or `manage` (also manage the vault in the Bitwarden apps) |
| `policies.twoStepLogin` | `false` | Members must use two-step login in Vaultwarden; those without it are shut out of the shared vaults until they add it |
| `policies.masterPassword` | off | `minLength` (8 to 128), `minComplexity` (0 to 4), `requireUpper`, `requireLower`, `requireNumbers`, `requireSpecial` |
| `policies.passwordGenerator` | off | `minLength`, `useUpper`, `useLower`, `useNumbers`, `useSpecial` |
| `policies.disableSend` | `false` | Members may not make Bitwarden Sends |

Account recovery cannot be set: Passwords keeps that policy off (see Recovery).

## How Vaultwarden is kept in step

After every change of the file, every five minutes, and when someone signs in to Passwords, Passwords:

1. Reads Identity's directory (`GET /api/v1/people`, with an API token that has the viewer role there).
2. Sends Vaultwarden the members and groups through the import Bitwarden's Directory Connector uses
   (`POST /api/public/organization/import`, with the organization's API key): everyone Identity lists as active or
   invited and in a group the file names is a member, each such group is a Vaultwarden group with those members, and
   members Identity disabled, or who left every group of the file, are removed. Identity's person id is the member's
   external id, the group name the group's.
3. Gives each vault's collection the file's groups (`POST /api/organizations/<org>/collections/bulk-access`, with a
   service account that is an admin of the organization). Access someone changed by hand in Vaultwarden is put back,
   and members given a vault directly are taken off it.
4. Applies the policies (`PUT /api/organizations/<org>/policies/<type>`), and turns account recovery off if it is on.
5. Reads the event log (`GET /api/organizations/<org>/events`) and which item is in which collection
   (`GET /api/ciphers/organization-details`, keeping only ids and dates).

A vault of the file with no collection yet is reported, and an owner or admin of the organization creates it from the
Vaults page: its name is encrypted with the organization's key, which only their browser holds. Passwords never deletes
a collection, and leaves collections the file does not name alone. It never removes an owner of the organization, nor
an admin added by hand; the sync says so instead.

## Leavers

When Identity disables someone, or they leave every group of the file, the next sync, within five minutes, removes
them from the organization. Before it does, Passwords writes down every shared item they could see and when they last
opened, copied or filled in each one, from the event log. The Leavers page lists them, the ones opened in the last 90
days first, so they are changed that afternoon. An item counts as changed when someone ticks it, or when its password
changes after the person left.

An editor can also plan someone's last day on the Leavers page, such as Mark Wilson on 30 November: until then the
page shows what they can see, and on that day they are removed even while Identity still lists them.

## Recovery

The site promises that an admin can recover a company vault, never a person's personal one. With Vaultwarden that
holds as follows:

- **A person's own vault:** only Vaultwarden's account recovery policy (admin password reset) would let an admin into
  it, and Passwords keeps it off and refuses it in the file. Emergency access remains each person's own choice in the
  Bitwarden apps.
- **A company vault:** every confirmed owner and admin of the organization holds its key, so any of them can open
  every shared vault and confirm new members. If they all lose their master password, the shared vaults cannot be
  opened again; the Password server page warns while fewer than two people hold the key. Vaultwarden has no other way
  back, by design.

## Run

Passwords needs Identity, or another OpenID Connect provider, for people's sign-in to Vaultwarden, and Identity's
directory for the groups.

1. **Keys and secrets for Passwords**

   ```bash
   openssl rand -hex 32 > openasy-kek
   ```

2. **Vaultwarden's sign-in through Identity.** In Identity, under Applications, add Another application named
   Vaultwarden with the redirect URI `https://vault.example.com/identity/connect/oidc-signin` (your
   `VAULTWARDEN_DOMAIN`), and save the client secret it shows in `vaultwarden-sso-secret`. Vaultwarden 1.35.0 and
   later sign in through OIDC; the variables are in `compose.yaml` (`SSO_ENABLED`, `SSO_AUTHORITY`, `SSO_CLIENT_ID`,
   `SSO_CLIENT_SECRET_FILE`). `SSO_ONLY` stays `false`: the master password encrypts the vault, and Passwords' pages
   unlock with it.

3. **Start Vaultwarden and make the organization.** Put a TLS proxy in front of it at `VAULTWARDEN_DOMAIN` (port
   8081 here), then:

   ```bash
   VAULTWARDEN_DOMAIN=https://vault.example.com VAULTWARDEN_ORG_CREATOR=you@example.com docker compose up -d vaultwarden
   ```

   Open the web vault, sign in with Identity as `VAULTWARDEN_ORG_CREATOR`, set your master password and create the
   company's organization. Its id is in the address of its pages (`/#/organizations/<id>`).

4. **The organization's API key.** In the organization's settings, View API key. The client_id is
   `organization.<id>`; save the client_secret in `vaultwarden-org-key`.

5. **The service account.** In the organization's Members, invite an address of its own, such as
   `passwords-service@example.com`. Register it in the web vault (invited addresses may, with sign-ups off) with a long
   master password kept in your password manager, then confirm it and make it an **Admin**. Signed in as it, under
   Account settings, Security, Keys, View API key: put the client_id (`user.<uuid>`) in `PASSWORDS_SERVICE_CLIENT_ID`
   and save the client_secret in `vaultwarden-service-key`. Passwords never uses its master password; it is left out
   when Passwords counts who holds the organization's key.

6. **Identity's directory.** In Identity, under Settings, API tokens, make a token with the viewer role and save it
   in `identity-token`.

7. **Start Passwords**

   ```bash
   $EDITOR config/passwords.yaml   # your vaults, by Identity group
   export PASSWORDS_ORGANIZATION_ID=<id> PASSWORDS_SERVICE_CLIENT_ID=user.<uuid> IDENTITY_URL=https://id.example.com
   docker compose up -d passwords
   docker compose logs passwords | grep 'no owner yet'
   ```

   Open the link from the log once to create the owner account; there is no default password (ADR 0013). Passwords is
   on http://localhost:8080; put it behind TLS, which the browser also needs for WebCrypto. Everyone with a vault signs
   in with Identity: set `OPENASY_OIDC_*` with `OPENASY_OIDC_DEFAULT_ROLE=user`, and map the people who manage
   Passwords to viewer, editor or admin.

8. **The first sync** imports the members and groups. The Vaults page then shows an owner or admin of the organization
   the vaults to create and the people to confirm. People join by signing in to the web vault through Identity once and
   setting their master password; without SMTP in Vaultwarden that also accepts their invitation, with SMTP they
   accept the emailed one. An owner or admin then confirms them from the Vaults page: their browser encrypts the
   organization's key to each person's public key.

Back up Vaultwarden's volume: it holds every vault, encrypted. Passwords' volume holds sign-in, the event log and the
leavers; `openasy-kek` encrypts sign-in secrets in it (ADR 0021): keep it apart from the volume and with your backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `PASSWORDS_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `PASSWORDS_CONFIG` | `/config/passwords.yaml` | The vaults file |
| `PASSWORDS_VAULTWARDEN_URL` | `http://vaultwarden:80` | Where Passwords reaches Vaultwarden |
| `PASSWORDS_VAULTWARDEN_PUBLIC_URL` | `PASSWORDS_VAULTWARDEN_URL` | Where the Bitwarden apps reach it; shown to people |
| `PASSWORDS_ORGANIZATION_ID` | required | The company's organization in Vaultwarden |
| `PASSWORDS_ORGANIZATION_SECRET_FILE` | `/run/secrets/vaultwarden-org-key` | The organization API key's client_secret, or `PASSWORDS_ORGANIZATION_SECRET` |
| `PASSWORDS_SERVICE_CLIENT_ID` | required | The service account's API key client_id, `user.<uuid>` |
| `PASSWORDS_SERVICE_SECRET_FILE` | `/run/secrets/vaultwarden-service-key` | Its client_secret, or `PASSWORDS_SERVICE_SECRET` |
| `PASSWORDS_IDENTITY_URL` | | Identity's address; without it, members and groups do not follow Identity |
| `PASSWORDS_IDENTITY_TOKEN_FILE` | `/run/secrets/identity-token` | An Identity API token with the viewer role, or `PASSWORDS_IDENTITY_TOKEN` |
| `PASSWORDS_LEAK_CHECK` | `true` | `false`: Health does not look leaked passwords up (see below) |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `PASSWORDS_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `PASSWORDS_DB` | `/data/passwords.db` | SQLite file (WAL), on the `/data` volume |
| `PASSWORDS_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `PASSWORDS_HEADLESS` | `false` | `true` serves only the API |
| `PASSWORDS_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`. The pages
allow scripts from this server only (and WebAssembly, for Argon2id).

## The pages

- **Vaults:** a person's own vault and the shared ones their groups give them, one open with its items, health badges
  and the item: show and copy the password (the clipboard is cleared after 30 seconds), the live two-step code, when
  it changed and its earlier passwords. Members of a vault come from Identity's groups. Logins, secure notes and cards
  are added, changed, moved from a person's own vault into a shared one and put in the trash here (see Writing items);
  identities, SSH keys and imports open Vaultwarden's web vault.
- **Health:** leaked, weak, reused and not-changed-in-two-years passwords in the shared vaults, by team. Leaks are
  looked up with the k-anonymity range API of Have I Been Pwned: the browser sends the first five characters of the
  password's SHA-1 to `api.pwnedpasswords.com`, with padding, and compares the rest itself. No password and no full
  hash leaves the browser; the five characters do leave the install. Set `PASSWORDS_LEAK_CHECK=false` to keep every
  request inside it.
- **Leavers:** see above.
- **Activity:** who opened, copied, filled in, changed, added, moved or removed which shared item, from which device
  type and address, from Vaultwarden's event log. Kept a year, and written to the JSON log as it is read.
- **Password server:** the vaults, groups and policies of the file, read-only, the syncs, and who holds the key.

## Writing items

What is typed in an item's form is encrypted in the browser before it is sent, the way the Bitwarden clients do it
(`web/src/items.ts`), and `/api/v1/vault/items` passes it to Vaultwarden as it is:

- A new item gets its own 64-byte key, encrypted with the key of the vault it goes in: the person's user key, or the
  organization's key for a shared vault. Every web address also gets the checksum the apps check.
- A changed item keeps its key, and only the form's fields are encrypted again. Its custom fields, passkeys,
  attachments, folder, favourite and archive state are sent back as they came, so nothing a Bitwarden app added is
  lost. A changed password goes into the item's history (the last five), and its date moves.
- Each change carries the date of the copy it was made from, and Vaultwarden refuses it when the item changed
  elsewhere since: the page then says to reload, rather than overwriting someone else's change.
- Moving a personal item into a shared vault encrypts its key again with the organization's key. An item with
  attachments is moved in a Bitwarden app, which moves the files too.
- New passwords are made in the browser with at least 20 characters of every kind, or the vaults file's
  `passwordGenerator.minLength` when it is longer.

Vaultwarden decides who may write: a vault given as `read` refuses new and changed items, and an item can only be
written by someone who may edit it. This server only checks that an item stays in the person's own vault or the
company's organization.

## Roles

Users open their own vault and the shared ones their groups give them, and see Health for those. Viewers also see
Leavers, Activity and the Password server page; editors also plan leaving dates and tick changed items; admins also
sync on request, manage members and API tokens (ADR 0003), and, when they are also an owner or admin of the
organization in Vaultwarden, confirm members and create vaults from their browser. API tokens never open a vault.

## Tested against a running Vaultwarden

`npm run e2e` (`e2e/run.sh`, also in CI) starts the Vaultwarden that `compose.yaml` pins, over TLS, and goes through
the first start above with its API: the owner's account and the organization, its API key, the service account made
an admin with its own key. Then Passwords' server and its pages' own code, run as the browser runs it, do the rest
against it, and the official Bitwarden CLI checks the result on the same accounts:

- the first sync imports Identity's people and groups, invites people without an account and leaves the owner alone;
- the generator policy reaches Vaultwarden as the apps read it;
- the owner creates the file's vaults from the page and they get the file's groups, with the right access each;
- the owner confirms the people waiting, from the page;
- someone with an Argon2id account unlocks, and sees an `edit` vault and a `read` one as such;
- items are added to a shared and a personal vault, a `read` vault refuses one, a changed password goes into the
  history, a change from a stale copy is refused, and a personal item moves into a shared vault;
- the Bitwarden CLI opens all of that, and the pages open items the CLI made, keep their custom fields and stars when
  they change them, and the CLI sees an item the page put in the trash;
- Activity names who added and changed which item, and someone Identity disables leaves at the next sync with what
  they could see.

The other tests run against a Vaultwarden in memory (`server/fake-vaultwarden.ts`) written from Vaultwarden 1.37.4's
source. What is not tested yet: signing in to Vaultwarden through Identity (SSO), and the Bitwarden desktop and phone
apps and browser extensions themselves (they share their encryption with the CLI).

## Coming next

Two-step login by email or passkey at unlock (an authenticator app works today), the fingerprint phrase when
confirming members, and sending the leavers list to vault managers by email.

## Develop

```bash
npm install
npm test        # the vaults file, the sync, leavers and activity, the pass-through, the browser's crypto and items, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
npm run e2e     # against a real Vaultwarden in Docker, with the Bitwarden CLI (needs Docker)
```

## Licence

AGPL-3.0 (ADR 0008). Vaultwarden is AGPL-3.0 too; Passwords uses only its open-source features and does not use
Bitwarden's SDK.
