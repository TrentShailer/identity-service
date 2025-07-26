import { Intl, Temporal } from "npm:temporal-polyfill@0.3.0";

export function parseUtcToLocalDateTime(utcTimestamp: string): Temporal.ZonedDateTime {
  const timezone = formatOptions().timeZone;
  return Temporal.Instant.from(utcTimestamp).toZonedDateTimeISO(timezone);
}

export function formatOptions(): globalThis.Intl.ResolvedDateTimeFormatOptions {
  return Intl.DateTimeFormat().resolvedOptions();
}

export { Intl, Temporal };
