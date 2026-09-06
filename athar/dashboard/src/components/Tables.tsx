import { fmtBytes } from "../lib/format";
import type { CaseEvent, Flow, Host } from "../lib/types";

export function HostTable({
  hosts,
  query,
  selected,
  onSelect,
}: {
  hosts: Host[];
  query: string;
  selected: string | null;
  onSelect: (ip: string) => void;
}) {
  const q = query.trim().toLowerCase();
  const rows = q ? hosts.filter((h) => h.ip.toLowerCase().includes(q)) : hosts;
  return (
    <table>
      <thead>
        <tr>
          <th>Address</th>
          <th>Role</th>
          <th>Protocols</th>
          <th className="num">Packets</th>
          <th className="num">Volume</th>
          <th className="num">Peers</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((h) => (
          <tr
            key={h.ip}
            className={`host-row ${h.flagged ? "flagged" : ""} ${h.ip === selected ? "sel" : ""}`}
            onClick={() => onSelect(h.ip)}
          >
            <td>{h.ip}</td>
            <td className={`role-${h.role}`}>{h.role}</td>
            <td>
              {h.protocols.map((p) => (
                <span className="tag" key={p}>
                  {p}
                </span>
              ))}
            </td>
            <td className="num">{h.packets.toLocaleString()}</td>
            <td className="num">{fmtBytes(h.bytes)}</td>
            <td className="num">{h.peers}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function FlowTable({ flows }: { flows: Flow[] }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Source</th>
          <th>Destination</th>
          <th>Service</th>
          <th className="num">Packets</th>
          <th className="num">Volume</th>
          <th className="num">Duration</th>
        </tr>
      </thead>
      <tbody>
        {flows.slice(0, 40).map((f, i) => (
          <tr key={i}>
            <td>
              {f.src}:{f.sport}
            </td>
            <td>
              {f.dst}:{f.dport}
            </td>
            <td>{f.service || f.proto}</td>
            <td className="num">{f.packets}</td>
            <td className="num">{fmtBytes(f.bytes)}</td>
            <td className="num">{f.dur}s</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function Timeline({ events, duration }: { events: CaseEvent[]; duration: number }) {
  const span = Math.max(duration, 1);
  return (
    <div className="timeline">
      <div className="eyebrow">events across the capture window</div>
      <div className="tl-track">
        <div className="tl-line" />
        {events.map((e, i) => (
          <div
            key={i}
            className={`tl-ev sev-bg-${e.severity}`}
            style={{ left: `${(e.t / span) * 100}%` }}
            title={`+${e.t}s  ${e.title}: ${e.summary}`}
          />
        ))}
      </div>
      <div className="tl-axis">
        <span>+0s</span>
        <span>+{span.toFixed(0)}s</span>
      </div>
    </div>
  );
}
