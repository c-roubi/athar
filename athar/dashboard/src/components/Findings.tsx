import type { CaseEvent, Severity } from "../lib/types";

interface Props {
  events: CaseEvent[];
  activeSeverities: Set<Severity>;
  onSelectHost: (ip: string) => void;
}

export default function Findings({ events, activeSeverities, onSelectHost }: Props) {
  const shown = events.filter((e) => activeSeverities.has(e.severity));
  if (shown.length === 0) {
    return <div className="empty faint">No findings match the current filter.</div>;
  }
  return (
    <div>
      {shown.map((e, i) => (
        <div className="finding" key={i}>
          <div className={`bar sev-${e.severity}`} />
          <div className="body">
            <div className="head">
              <span className={`chip sev-${e.severity}`}>{e.severity}</span>
              <span className="title">{e.title}</span>
            </div>
            <div className="sum">{e.summary}</div>
            {e.src && (
              <div className="route">
                <button className="linkish" onClick={() => onSelectHost(e.src)}>
                  {e.src}
                </button>
                {e.dst && (
                  <>
                    {" → "}
                    <button className="linkish" onClick={() => onSelectHost(e.dst)}>
                      {e.dst}
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
          <div className="meta">
            {e.detector}
            {e.technique && (
              <>
                <br />
                <span className="att">{e.technique}</span>
              </>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
