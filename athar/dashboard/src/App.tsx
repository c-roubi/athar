import { useMemo, useState } from "react";
import Header from "./components/Header";
import Findings from "./components/Findings";
import Narratives from "./components/Narratives";
import { EvidencePanel, TcpHealthPanel } from "./components/CaseInfo";
import InvestigationMap from "./components/InvestigationMap";
import Dossier from "./components/Dossier";
import { FlowTable, HostTable, Timeline } from "./components/Tables";
import { SEVERITIES } from "./lib/types";
import type { CaseData, Severity } from "./lib/types";
import sampleCase from "./sample-case.json";

const SAMPLE = sampleCase as unknown as CaseData;

export default function App() {
  const [data, setData] = useState<CaseData>(SAMPLE);
  const [selected, setSelected] = useState<string | null>(firstFlagged(SAMPLE));
  const [query, setQuery] = useState("");
  const [active, setActive] = useState<Set<Severity>>(new Set(SEVERITIES));
  const [error, setError] = useState<string | null>(null);

  const selectedHost = useMemo(
    () => data.hosts.find((h) => h.ip === selected),
    [data, selected],
  );

  const toggle = (sev: Severity) => {
    setActive((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) next.delete(sev);
      else next.add(sev);
      return next;
    });
  };

  const load = (file: File) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const parsed = JSON.parse(String(reader.result)) as CaseData;
        if (!parsed.hosts || !parsed.events) throw new Error("not an athar data file");
        setData(parsed);
        setSelected(firstFlagged(parsed));
        setQuery("");
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "could not read file");
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="wrap">
      <Header
        data={data}
        active={active}
        onToggle={toggle}
        query={query}
        onQuery={setQuery}
        onLoad={load}
      />
      {error && <div className="error">Could not load file: {error}</div>}

      {data.stories && data.stories.length > 0 && (
        <section className="section">
          <h2>Attack narratives</h2>
          <Narratives stories={data.stories} onSelectHost={setSelected} />
        </section>
      )}

      <section className="section">
        <h2>Findings</h2>
        <Findings events={data.events} activeSeverities={active} onSelectHost={setSelected} />
      </section>

      <section className="section">
        <h2>Investigation map</h2>
        <div className="investigation">
          <div className="map-panel">
            <div className="hint">click any device</div>
            <InvestigationMap
              hosts={data.hosts}
              edges={data.edges}
              selected={selected}
              query={query}
              onSelect={setSelected}
            />
            <div className="map-legend">
              <Legend color="var(--server)" label="server" />
              <Legend color="var(--endpoint)" label="endpoint" />
              <Legend color="var(--scanner)" label="scanner" />
              <Legend color="var(--external)" label="external" />
              <Legend color="var(--crit)" label="suspicious link" />
            </div>
          </div>
          <Dossier host={selectedHost} events={data.events} />
        </div>
      </section>

      <section className="section">
        <h2>Timeline</h2>
        <Timeline events={data.events} duration={data.duration} />
      </section>

      {data.tcp_health && (
        <section className="section">
          <h2>TCP health</h2>
          <TcpHealthPanel health={data.tcp_health} />
        </section>
      )}

      <section className="section">
        <h2>Host inventory</h2>
        <HostTable hosts={data.hosts} query={query} selected={selected} onSelect={setSelected} />
      </section>

      <section className="section">
        <h2>Top conversations</h2>
        <FlowTable flows={data.flows} />
      </section>

      {data.provenance && (
        <section className="section">
          <h2>Evidence &amp; chain of custody</h2>
          <EvidencePanel prov={data.provenance} />
        </section>
      )}

      <footer className="foot">
        athar dashboard · react + typescript · authorised forensic use only
      </footer>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span>
      <i className="dot" style={{ background: color }} />
      {label}
    </span>
  );
}

function firstFlagged(data: CaseData): string | null {
  return data.hosts.find((h) => h.flagged)?.ip ?? data.hosts[0]?.ip ?? null;
}
