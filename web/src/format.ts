// Dates in the page's language, and Bitwarden's device types by name.
import { useLocalePreference } from "@openasy/ui";
import { useCallback } from "react";

/** "14 Mar 2026", or "4 Nov, 09:12" with the time. */
export function useDate() {
  const [locale] = useLocalePreference();
  return useCallback(
    (iso: string | null | undefined, time = false) => {
      if (!iso) return "–";
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return "–";
      return new Intl.DateTimeFormat(
        locale,
        time ? { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" } : { day: "numeric", month: "short", year: "numeric" },
      ).format(d);
    },
    [locale],
  );
}

/** Vaultwarden's names for Bitwarden's device types (src/db/models/device.rs). */
const DEVICES: Record<number, string> = {
  0: "Android",
  1: "iOS",
  2: "Chrome extension",
  3: "Firefox extension",
  4: "Opera extension",
  5: "Edge extension",
  6: "Windows",
  7: "macOS",
  8: "Linux",
  9: "Chrome",
  10: "Firefox",
  11: "Opera",
  12: "Edge",
  13: "Internet Explorer",
  14: "Browser",
  15: "Android",
  16: "Windows",
  17: "Safari",
  18: "Vivaldi",
  19: "Vivaldi extension",
  20: "Safari extension",
  21: "SDK",
  22: "Server",
  23: "Windows CLI",
  24: "macOS CLI",
  25: "Linux CLI",
  26: "DuckDuckGo",
};

export const deviceName = (type: number | null) => (type === null ? "–" : (DEVICES[type] ?? `Device ${type}`));
