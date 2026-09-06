// The data contract emitted by `athar --data`. Mirrors the Python
// build_report_data() output exactly, so the dashboard and the HTML report
// render from the same shape.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface HostDNS { name: string; type: string; }
export interface HostHTTP { method: string; host: string; path: string; creds: string; }

export interface HttpObject {
  kind: string; method?: string; host?: string; path?: string;
  filename?: string; content_type?: string; declared_bytes: number;
  truncated: boolean; sha256: string; body_kind: string; preview: string;
}

export interface Certificate {
  subject: string; issuer: string; self_signed?: boolean;
  expired?: boolean; lifetime_days?: number; not_after?: string;
}

export interface Session { protocol: string; detail: string; }

export interface Host {
  ip: string; mac: string; role: string; packets: number; bytes: number;
  peers: number; services: number[]; protocols: string[]; flagged: boolean;
  private: boolean; geo?: Record<string, string>; dns: HostDNS[];
  http: HostHTTP[]; sni: string[]; ja3: string[]; ja3s: string[];
  objects?: HttpObject[]; certificates?: Certificate[]; sessions?: Session[];
  findings: number[];
}

export interface Edge { a: string; b: string; bytes: number; packets: number; suspicious: boolean; }

export interface CaseEvent {
  t: number; severity: Severity; detector: string; title: string;
  summary: string; src: string; dst: string; technique: string;
  evidence: Record<string, unknown>;
}

export interface Flow {
  src: string; dst: string; sport: number; dport: number; proto: string;
  service: string; packets: number; bytes: number; dur: number;
}

export interface Provenance {
  examiner: string; organization: string; case_number: string; authority: string;
  source_path: string; source_sha256: string; source_bytes: number;
  tool: string; tool_version: string; backend: string; analyzed_at: string;
}

export interface StageEvent {
  severity: Severity; title: string; summary: string; detector: string; technique: string;
}
export interface Stage { tactic: string; events: StageEvent[]; }
export interface Story {
  host: string; score: number; span: number; tactics: string[]; stages: Stage[];
}

export interface TcpHealth {
  retransmissions: number; fast_retransmissions: number; out_of_order: number;
  resets: number; zero_window: number; syns: number;
}

export interface CaseData {
  source: string; started_iso: string; ended_iso: string; duration: number;
  packets: number; bytes: number; host_count: number; flow_count: number;
  case_id: string; provenance?: Provenance | null; tcp_health?: TcpHealth;
  stories?: Story[]; severity: Record<Severity, number>;
  hosts: Host[]; edges: Edge[]; events: CaseEvent[]; flows: Flow[];
}

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
