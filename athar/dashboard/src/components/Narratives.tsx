import type { Story } from "../lib/types";

interface Props {
  stories: Story[];
  onSelectHost: (ip: string) => void;
}

export default function Narratives({ stories, onSelectHost }: Props) {
  if (stories.length === 0) {
    return <div className="empty faint">No multi-stage activity correlated.</div>;
  }
  return (
    <div>
      {stories.slice(0, 6).map((s) => (
        <div className="story" key={s.host}>
          <div className="story-head">
            <button className="story-host linkish" onClick={() => onSelectHost(s.host)}>
              {s.host}
            </button>
            <span className="story-score">threat score {s.score}</span>
            <span className="story-span">over {s.span}s</span>
          </div>
          <div className="killchain">
            {s.tactics.map((t, i) => (
              <span key={t} className="kc">
                {i > 0 && <span className="kc-arrow">→</span>}
                <span className="phase">{t}</span>
              </span>
            ))}
          </div>
          {s.stages.map((stage) => (
            <div className="stage" key={stage.tactic}>
              <div className="stage-tactic">{stage.tactic}</div>
              {stage.events.map((e, i) => (
                <div className="stage-ev" key={i}>
                  <span className={`chip sev-${e.severity}`}>{e.severity}</span>{" "}
                  {e.summary} <span className="att">{e.technique}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}
