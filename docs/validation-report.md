# athar detector validation report

Tool version: **0.17.0**

Synthetic labelled scenarios (clear positives, benign controls, and near-threshold boundary cases). Findings are matched to ground truth as `(detector, host)` pairs.

| Detector | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| `port_scan` | 2 | 0 | 0 | 1.00 | 1.00 |
| `plaintext_credentials` | 1 | 0 | 0 | 1.00 | 1.00 |
| `beaconing` | 2 | 0 | 0 | 1.00 | 1.00 |
| `dns_tunneling` | 2 | 0 | 0 | 1.00 | 1.00 |

Benign controls with **zero** findings (no false alarms): 4/4.

> Boundary scenarios sit deliberately close to detection thresholds; any errors there characterise the tool near its decision boundary rather than on clear-cut traffic.
