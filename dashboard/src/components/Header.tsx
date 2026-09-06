import type { ChangeEvent } from "react";
import { fmtBytes } from "../lib/format";
import { SEVERITIES } from "../lib/types";
import type { CaseData, Severity } from "../lib/types";

interface Props {
  data: CaseData;
  active: Set<Severity>;
  onToggle: (sev: Severity) => void;
  query: string;
  onQuery: (q: string) => void;
  onLoad: (file: File) => void;
}

export default function Header({ data, active, onToggle, query, onQuery, onLoad }: Props) {
  const alerts = Object.values(data.severity).reduce((a, b) => a + b, 0);
  const stats: [string, string | number][] = [
    ["hosts", data.host_count],
    ["conversations", data.flow_count],
    ["packets", data.packets.toLocaleString()],
    ["volume", fmtBytes(data.bytes)],
    ["duration", `${data.duration}s`],
  ];

  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) onLoad(f);
  };

  return (
    <header className="case">
      <div className="case-top">
        <div>
          <div className="case-id">{data.case_id}</div>
          <h1>Network forensic report</h1>
          <div className="src">{data.source}</div>
        </div>
        <div className="window">
          capture window
          <br />
          <b>{data.started_iso}</b>
          <br />
          to <b>{data.ended_iso}</b>
        </div>
      </div>

      <div className="stats">
        {stats.map(([label, value]) => (
          <div className="stat" key={label}>
            <div className="n">{value}</div>
            <div className="l">{label}</div>
          </div>
        ))}
        <div className="stat alert">
          <div className="n">{alerts}</div>
          <div className="l">findings</div>
        </div>
      </div>

      <div className="toolbar">
        <div className="filters">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              className={`sevchip sev-${s} ${active.has(s) ? "on" : "off"}`}
              onClick={() => onToggle(s)}
            >
              {s} <span className="count">{data.severity[s]}</span>
            </button>
          ))}
        </div>
        <div className="tools">
          <input
            className="search"
            placeholder="search host ip…"
            value={query}
            onChange={(e) => onQuery(e.target.value)}
          />
          <label className="loadbtn">
            Load JSON
            <input type="file" accept="application/json,.json" onChange={onFile} hidden />
          </label>
        </div>
      </div>
    </header>
  );
}
