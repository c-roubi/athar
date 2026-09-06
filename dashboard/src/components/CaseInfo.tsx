import type { Provenance, TcpHealth } from "../lib/types";

export function EvidencePanel({ prov }: { prov: Provenance }) {
  const rows = ([
    ["source", prov.source_path],
    ["sha-256", prov.source_sha256],
    ["examiner", prov.examiner],
    ["organization", prov.organization],
    ["case number", prov.case_number],
    ["legal authority", prov.authority],
    ["analyzed at", prov.analyzed_at],
    ["tool", `${prov.tool} ${prov.tool_version} (${prov.backend} core)`],
  ] as [string, string][]).filter(([, v]) => v);
  return (
    <div className="evidence">
      {rows.map(([k, v]) => (
        <div className="ev-row" key={k}>
          <span className="ev-k">{k}</span>
          <span className="ev-v">{v}</span>
        </div>
      ))}
    </div>
  );
}

export function TcpHealthPanel({ health }: { health: TcpHealth }) {
  const cells: [string, number, boolean][] = [
    ["retransmissions", health.retransmissions, health.retransmissions > 0],
    ["fast retransmit", health.fast_retransmissions, health.fast_retransmissions > 0],
    ["out of order", health.out_of_order, health.out_of_order > 0],
    ["resets", health.resets, health.resets > 0],
    ["zero window", health.zero_window, health.zero_window > 0],
    ["syns", health.syns, false],
  ];
  return (
    <div className="tcp-health">
      {cells.map(([label, n, warn]) => (
        <div className={`th-cell ${warn ? "warn" : ""}`} key={label}>
          <div className="th-n">{n.toLocaleString()}</div>
          <div className="th-l">{label}</div>
        </div>
      ))}
    </div>
  );
}
