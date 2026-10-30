import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { findings, leaks, RANGE_API, score, strength } from "./health.ts";
import { parseTotp, totp } from "./totp.ts";

describe("password strength", () => {
  it.each([
    ["Summer2025", "weak"],
    ["password1!", "weak"],
    ["aaaaaaaaaaaa", "weak"],
    ["short1!", "weak"],
    ["Acme2026!tax", "fair"],
    ["Broker!2024", "fair"],
    ["alllowercaseletters", "fair"],
    ["hT9#vQ2m!xR4-Lp7w", "strong"],
    ["q8$Fz!2nWc@e7Uy", "strong"],
  ])("rates %s as %s", (password, expected) => {
    expect(strength(password)).toBe(expected);
  });
});

describe("findings", () => {
  const now = Date.parse("2026-11-04T09:00:00Z");
  const items = [
    { id: "payroll", password: "Summer2025", changedAt: "2025-09-09T00:00:00Z" },
    { id: "webinar", password: "Summer2025", changedAt: "2026-01-10T00:00:00Z" },
    { id: "switch", password: "hT9#vQ2m!xR4-Lp7w", changedAt: "2024-02-14T00:00:00Z" },
    { id: "bank", password: "q8$Fz!2nWc@e7Uy", changedAt: "2026-10-20T00:00:00Z" },
    { id: "note", password: null, changedAt: "2020-01-01T00:00:00Z" },
  ];

  it("finds weak, reused and old passwords, and leaks it was told about", () => {
    const found = findings(items, { now, leaks: new Map([["bank", 3]]) });
    expect(found.map((f) => [f.itemId, f.issue, f.detail])).toEqual([
      ["payroll", "weak", 10],
      ["payroll", "reused", 1],
      ["webinar", "weak", 10],
      ["webinar", "reused", 1],
      ["switch", "old", "2024-02-14T00:00:00Z"],
      ["bank", "leaked", 3],
    ]);
    expect(score(["payroll", "webinar", "switch", "bank", "note"], found)).toBe(20);
    expect(score([], found)).toBe(100);
  });

  it("asks the range API with five characters of the hash only, and matches the rest in the browser", async () => {
    const asked: string[] = [];
    const sha = (s: string) => createHash("sha1").update(s).digest("hex").toUpperCase();
    const f = (async (url: string, init: RequestInit) => {
      asked.push(url);
      expect(new Headers(init.headers).get("add-padding")).toBe("true");
      const prefix = url.slice(RANGE_API.length);
      const lines = [`${sha("Summer2025").slice(5)}:4120`, "0000000000000000000000000000000000A:0"].filter(() => prefix === sha("Summer2025").slice(0, 5));
      return new Response(lines.join("\r\n"));
    }) as unknown as typeof fetch;
    const found = await leaks(items, f);
    expect([...found]).toEqual([
      ["payroll", 4120],
      ["webinar", 4120],
    ]);
    expect(asked.every((u) => /\/range\/[0-9A-F]{5}$/.test(u))).toBe(true);
    // Summer2025 is used twice and asked about once.
    expect(asked.length).toBe(3);
  });
});

describe("two-step codes", () => {
  // RFC 6238, appendix B: the SHA-1 seed "12345678901234567890" and its 8-digit codes.
  const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  it.each([
    [59, "94287082"],
    [1111111109, "07081804"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
  ])("gives the RFC 6238 code at %i", async (seconds, code) => {
    const spec = parseTotp(`otpauth://totp/Example:emily?secret=${seed}&digits=8&issuer=Example`)!;
    expect((await totp(spec, seconds * 1000)).code).toBe(code);
  });

  it("reads plain base32 secrets and SHA-256 URIs, and says how long a code lasts", async () => {
    const plain = parseTotp("jbsw y3dp ehpk 3pxp")!;
    expect(plain).toMatchObject({ digits: 6, period: 30, algorithm: "SHA-1" });
    expect((await totp(plain, 1_000)).remaining).toBe(29);
    // RFC 6238 SHA-256 seed: "12345678901234567890123456789012".
    const sha256 = parseTotp("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256")!;
    expect((await totp(sha256, 59_000)).code).toBe("46119246");
    expect(parseTotp("steam://ABCDEF")).toBeNull();
    expect(parseTotp("not base32!")).toBeNull();
    expect(parseTotp(null)).toBeNull();
  });
});
