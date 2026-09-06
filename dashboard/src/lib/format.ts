import type { Severity } from "./types";

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

export const ROLE_COLOR: Record<string, string> = {
  server: "var(--server)",
  endpoint: "var(--endpoint)",
  scanner: "var(--scanner)",
  external: "var(--external)",
};

export function roleColor(role: string): string {
  return ROLE_COLOR[role] ?? "var(--endpoint)";
}

export function sevVar(sev: Severity): string {
  return `var(--${sev})`;
}
