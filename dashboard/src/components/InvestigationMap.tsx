import { useMemo } from "react";
import { computeLayout } from "../lib/layout";
import { roleColor } from "../lib/format";
import type { Edge, Host } from "../lib/types";

interface Props {
  hosts: Host[];
  edges: Edge[];
  selected: string | null;
  query: string;
  onSelect: (ip: string) => void;
}

export default function InvestigationMap({ hosts, edges, selected, query, onSelect }: Props) {
  const layout = useMemo(() => computeLayout(hosts, edges), [hosts, edges]);
  const q = query.trim().toLowerCase();

  return (
    <svg viewBox={`0 0 ${layout.width} ${layout.height}`} className="map">
      {layout.edges.map((e, i) => {
        const a = layout.nodes[e.s];
        const b = layout.nodes[e.t];
        const width = e.suspicious ? 2 : Math.max(0.5, Math.min(3, Math.log2(e.bytes / 2000 + 1) * 0.5));
        return (
          <g key={i}>
            {e.suspicious && (
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="var(--crit)" strokeWidth={6} opacity={0.14} />
            )}
            <line
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke={e.suspicious ? "var(--crit)" : "var(--line2)"}
              strokeWidth={width}
              opacity={e.suspicious ? 0.9 : 0.5}
            />
          </g>
        );
      })}
      {layout.nodes.map((n) => {
        const color = roleColor(n.role);
        const isSel = n.ip === selected;
        const isMatch = q !== "" && n.ip.toLowerCase().includes(q);
        const short = n.ip.length > 15 ? n.ip.split(".").slice(-2).join(".") : n.ip;
        return (
          <g key={n.ip} className="node" onClick={() => onSelect(n.ip)} style={{ cursor: "pointer" }}>
            {n.flagged && (
              <circle cx={n.x} cy={n.y} r={n.r + 6} fill="none" stroke="var(--crit)" strokeWidth={1} opacity={0.7} />
            )}
            {isMatch && (
              <circle cx={n.x} cy={n.y} r={n.r + 10} fill="none" stroke="var(--accent)" strokeWidth={1.5} />
            )}
            <circle
              cx={n.x}
              cy={n.y}
              r={n.r}
              fill={color}
              fillOpacity={isSel ? 0.5 : 0.22}
              stroke={color}
              strokeWidth={isSel ? 3 : 1.5}
            />
            <text x={n.x} y={n.y + n.r + 13} textAnchor="middle" className="node-label">
              {short}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
