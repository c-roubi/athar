"""Run the validation scenarios and measure per-detector error rates.

For every labelled scenario it runs athar, compares the findings against the
ground truth, and computes true/false positives and negatives per detector,
plus precision, recall and false-positive rate. Writes a Markdown and a JSON
report so the numbers can be cited (a known error rate is a Daubert factor).

    python validation/run.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import scenarios as S  # noqa: E402

from athar import __version__, analyze  # noqa: E402


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0


def evaluate() -> tuple[dict[str, Counts], int, int]:
    per: dict[str, Counts] = defaultdict(Counts)
    benign_total = benign_clean = 0

    with tempfile.TemporaryDirectory() as tmp:
        for sc in S.scenarios():
            path = Path(tmp) / f"{sc.name}.pcap"
            path.write_bytes(sc.pcap)
            case = analyze(path)
            detected = {(e.detector, e.src_ip) for e in case.events
                        if e.detector in S.DETECTORS}
            expected = sc.expected

            for det in S.DETECTORS:
                exp = {p for p in expected if p[0] == det}
                got = {p for p in detected if p[0] == det}
                per[det].tp += len(got & exp)
                per[det].fp += len(got - exp)
                per[det].fn += len(exp - got)

            if sc.label == "negative":
                benign_total += 1
                if not detected:
                    benign_clean += 1

    return per, benign_clean, benign_total


def main() -> int:
    per, benign_clean, benign_total = evaluate()

    lines = [
        "# athar detector validation report",
        "",
        f"Tool version: **{__version__}**",
        "",
        "Synthetic labelled scenarios (clear positives, benign controls, and "
        "near-threshold boundary cases). Findings are matched to ground truth as "
        "`(detector, host)` pairs.",
        "",
        "| Detector | TP | FP | FN | Precision | Recall |",
        "|---|---|---|---|---|---|",
    ]
    report: dict[str, object] = {"tool_version": __version__, "detectors": {}}
    detectors: dict[str, object] = {}
    for det, c in per.items():
        lines.append(f"| `{det}` | {c.tp} | {c.fp} | {c.fn} | "
                     f"{c.precision():.2f} | {c.recall():.2f} |")
        detectors[det] = {"tp": c.tp, "fp": c.fp, "fn": c.fn,
                          "precision": round(c.precision(), 3), "recall": round(c.recall(), 3)}
    report["detectors"] = detectors
    report["benign_controls"] = {"clean": benign_clean, "total": benign_total}

    lines += [
        "",
        f"Benign controls with **zero** findings (no false alarms): "
        f"{benign_clean}/{benign_total}.",
        "",
        "> Boundary scenarios sit deliberately close to detection thresholds; any "
        "errors there characterise the tool near its decision boundary rather than "
        "on clear-cut traffic.",
    ]

    out_md = ROOT / "docs" / "validation-report.md"
    out_json = ROOT / "docs" / "validation-report.json"
    out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out_json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwrote {out_md} and {out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
