import type { Edge, Host } from "./types";

export interface LaidOutNode {
  ip: string;
  x: number;
  y: number;
  r: number;
  role: string;
  flagged: boolean;
}

export interface LaidOutEdge {
  s: number;
  t: number;
  bytes: number;
  suspicious: boolean;
}

export interface Layout {
  nodes: LaidOutNode[];
  edges: LaidOutEdge[];
  width: number;
  height: number;
}

// A small, deterministic force-directed layout: repulsion between all nodes,
// spring attraction along edges, and a gentle pull to the centre. Deterministic
// so the same case always lays out identically.
export function computeLayout(hosts: Host[], edges: Edge[], width = 680, height = 460): Layout {
  const index: Record<string, number> = {};
  hosts.forEach((h, i) => (index[h.ip] = i));

  let seed = 1337;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);

  const nodes: LaidOutNode[] = hosts.map((h) => ({
    ip: h.ip,
    role: h.role,
    flagged: h.flagged,
    r: 6 + Math.min(22, Math.sqrt(h.bytes) / 40),
    x: width / 2 + (rnd() - 0.5) * width * 0.7,
    y: height / 2 + (rnd() - 0.5) * height * 0.7,
  }));
  const vel = nodes.map(() => ({ x: 0, y: 0 }));

  const es: LaidOutEdge[] = edges
    .filter((e) => index[e.a] != null && index[e.b] != null)
    .map((e) => ({ s: index[e.a], t: index[e.b], bytes: e.bytes, suspicious: e.suspicious }));

  for (let it = 0; it < 320; it++) {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const d = Math.hypot(dx, dy) || 0.1;
        const f = 2600 / (d * d);
        vel[i].x += (dx / d) * f;
        vel[i].y += (dy / d) * f;
        vel[j].x -= (dx / d) * f;
        vel[j].y -= (dy / d) * f;
      }
    }
    for (const e of es) {
      const a = nodes[e.s];
      const b = nodes[e.t];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.hypot(dx, dy) || 0.1;
      const f = (d - 120) * 0.012;
      vel[e.s].x += (dx / d) * f;
      vel[e.s].y += (dy / d) * f;
      vel[e.t].x -= (dx / d) * f;
      vel[e.t].y -= (dy / d) * f;
    }
    nodes.forEach((n, i) => {
      vel[i].x += (width / 2 - n.x) * 0.006;
      vel[i].y += (height / 2 - n.y) * 0.006;
      n.x += vel[i].x * 0.85;
      n.y += vel[i].y * 0.85;
      vel[i].x *= 0.82;
      vel[i].y *= 0.82;
      n.x = Math.max(n.r + 8, Math.min(width - n.r - 8, n.x));
      n.y = Math.max(n.r + 8, Math.min(height - n.r - 8, n.y));
    });
  }
  return { nodes, edges: es, width, height };
}
