import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { groupsOf, parseConfig, watchConfig } from "./config.ts";
import { VAULTS } from "./test-app.ts";

describe("the vaults file", () => {
  it("reads vaults with their groups and the policies", () => {
    const config = parseConfig(VAULTS);
    expect(config.vaults[0]).toEqual({
      id: "finance",
      name: "Finance",
      access: [
        { group: "finance-leads", access: "manage" },
        { group: "finance", access: "edit" },
      ],
    });
    expect(groupsOf(config)).toEqual(["finance-leads", "finance", "sales", "everyone"]);
    expect(config.policies).toEqual({
      twoStepLogin: true,
      masterPassword: { minLength: 14, minComplexity: 3, requireUpper: false, requireLower: false, requireNumbers: false, requireSpecial: false },
      passwordGenerator: null,
      disableSend: false,
    });
    expect(parseConfig("")).toEqual({ vaults: [], policies: { twoStepLogin: false, masterPassword: null, passwordGenerator: null, disableSend: false } });
  });

  it.each([
    ["groups: []", "The file: unknown groups; it takes vaults, policies."],
    ["vaults: {}", "vaults must be a list."],
    ["vaults:\n  - name: Finance", "vaults[0].id is required: lowercase letters, digits and dashes, such as finance."],
    ["vaults:\n  - { id: a, name: A }\n  - { id: a, name: B }", "vaults[1].id: a is in the file twice."],
    ["vaults:\n  - { id: a, name: A }\n  - { id: b, name: a }", "vaults[1] (b).name: a is already the name of a."],
    ["vaults:\n  - { id: a }", "vaults[0] (a).name is required, up to 100 characters."],
    ["vaults:\n  - { id: a, name: A, members: [] }", "vaults[0] (a): unknown members; a vault takes id, name, access."],
    [
      "vaults:\n  - { id: a, name: A, access: [finance] }",
      "vaults[0] (a).access is a map of Identity groups to read, edit or manage, such as { finance: edit }.",
    ],
    ["vaults:\n  - { id: a, name: A, access: { finance: write } }", "vaults[0] (a).access.finance is read, edit or manage."],
    ["policies: { accountRecovery: true }", "policies.accountRecovery cannot be set: Passwords keeps it off, so an admin never recovers a person's own vault."],
    ["policies: { vaultTimeout: 5 }", "policies: unknown vaultTimeout; it takes twoStepLogin, masterPassword, passwordGenerator, disableSend."],
    ["policies: { twoStepLogin: yes please }", "policies.twoStepLogin is true or false."],
    ["policies: { masterPassword: { minLength: 4 } }", "policies.masterPassword.minLength is a whole number from 8 to 128."],
  ])("refuses %j", (text, message) => {
    expect(() => parseConfig(text)).toThrow(message);
  });

  it("keeps the last good version when the file breaks, and applies the fix", () => {
    const path = join(mkdtempSync(join(tmpdir(), "passwords-config-")), "passwords.yaml");
    writeFileSync(path, VAULTS);
    const applied: number[] = [];
    const file = watchConfig(path, (c) => void applied.push(c.vaults.length), { everyMs: 3_600_000 });
    expect(file.state).toMatchObject({ vaults: 3, groups: 4, error: null });
    writeFileSync(path, "vaults: [");
    file.read();
    expect(file.state.error).toMatch(/^Not valid YAML/);
    expect(file.state.vaults).toBe(3);
    writeFileSync(path, "vaults:\n  - { id: it, name: IT, access: { it-admins: manage } }\n");
    file.read();
    expect(file.state).toMatchObject({ vaults: 1, groups: 1, error: null });
    expect(applied).toEqual([3, 1]);
    file.stop();
  });
});
