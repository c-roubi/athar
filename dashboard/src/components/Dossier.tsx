import { fmtBytes } from "../lib/format";
import type { CaseEvent, Host } from "../lib/types";

interface Props {
  host: Host | undefined;
  events: CaseEvent[];
}

export default function Dossier({ host, events }: Props) {
  if (!host) {
    return (
      <div className="dossier">
        <div className="empty">
          Select a device on the map
          <br />
          to open its dossier.
        </div>
      </div>
    );
  }
  const findings = host.findings.map((i) => events[i]).filter(Boolean);
  const geo = host.geo ?? {};
  const geoLine = [geo.scope, geo.country, geo.city, geo.asn, geo.organization]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="dossier">
      <h3>{host.ip}</h3>
      <div className={`role role-${host.role}`}>
        {host.role}
        {host.flagged ? " · flagged" : ""}
      </div>

      <div className="d-grid">
        <Cell k="packets" v={host.packets.toLocaleString()} />
        <Cell k="volume" v={fmtBytes(host.bytes)} />
        <Cell k="peers" v={String(host.peers)} />
        <Cell k="services" v={host.services.join(", ") || "—"} />
      </div>

      {geoLine && <Block label="network scope"><div>{geoLine}</div></Block>}
      {host.mac && <Block label="hardware"><div>{host.mac}</div></Block>}

      {findings.length > 0 && (
        <div className="d-block">
          <div className="lbl">findings</div>
          {findings.map((f, i) => (
            <div className="route" key={i} style={{ marginTop: 6 }}>
              <span className={`chip sev-${f.severity}`}>{f.severity}</span> {f.title}
            </div>
          ))}
        </div>
      )}

      {host.sessions && host.sessions.length > 0 && (
        <Block label="protocol sessions">
          {host.sessions.map((s, i) => (
            <div key={i}>
              <span className="t">{s.protocol}</span>
              {s.detail}
            </div>
          ))}
        </Block>
      )}

      {host.certificates && host.certificates.length > 0 && (
        <Block label="tls certificates">
          {host.certificates.map((c, i) => (
            <div key={i}>
              <span className="t">{c.subject || "?"}</span>
              {[c.self_signed ? "self-signed" : "", c.expired ? "expired" : "",
                c.lifetime_days != null ? `${c.lifetime_days}d` : ""]
                .filter(Boolean)
                .join(" · ")}
              {c.self_signed ? <span className="cred"> [self-signed]</span> : null}
            </div>
          ))}
        </Block>
      )}

      {host.objects && host.objects.length > 0 && (
        <Block label="reconstructed content">
          {host.objects.map((o, i) => (
            <div key={i}>
              <span className="t">{o.method || o.kind}</span>
              {(o.host || "") + (o.path || "")} · {(o.declared_bytes / 1024).toFixed(1)} KB
              {o.filename ? <span className="cred"> {o.filename}</span> : null}
            </div>
          ))}
        </Block>
      )}

      {host.dns.length > 0 && (
        <Block label="dns lookups">
          {host.dns.map((d, i) => (
            <div key={i}>
              <span className="t">{d.type}</span>
              {d.name}
            </div>
          ))}
        </Block>
      )}

      {host.http.length > 0 && (
        <Block label="http requests">
          {host.http.map((r, i) => (
            <div key={i}>
              <span className="t">{r.method}</span>
              {r.host}
              {r.path}
              {r.creds ? <span className="cred"> [auth: {r.creds}]</span> : null}
            </div>
          ))}
        </Block>
      )}

      {host.sni.length > 0 && (
        <Block label="tls server names">
          {host.sni.map((s, i) => (
            <div key={i}>{s}</div>
          ))}
        </Block>
      )}

      {host.ja3.length > 0 && (
        <Block label="ja3 fingerprints">
          {host.ja3.map((s, i) => (
            <div key={i}>{s}</div>
          ))}
        </Block>
      )}

      {host.ja3s.length > 0 && (
        <Block label="ja3s (server) fingerprints">
          {host.ja3s.map((s, i) => (
            <div key={i}>{s}</div>
          ))}
        </Block>
      )}
    </div>
  );
}

function Cell({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <div className="k">{k}</div>
      <div className="v">{v}</div>
    </div>
  );
}

function Block({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="d-block">
      <div className="lbl">{label}</div>
      <div className="d-list">{children}</div>
    </div>
  );
}
