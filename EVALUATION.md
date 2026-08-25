# DRACARYS — Evaluation Methodology

DRACARYS is scored against an **objective ground truth**, not against its own claims.
The lab (`lab/ground_truth.py`) is the answer key; the harness
(`dracarys/evaluation/harness.py`) compares what a campaign actually *persisted*
(findings, evidence, attack paths, retests) to that key.

## Run it
```bash
make eval            # or: dracarys eval
```
Sample output (heuristic planner, one campaign):
```json
{
  "expected": 5, "detected": 5,
  "true_positives": 5, "false_positives": 0, "false_negatives": 0,
  "precision": 1.0, "recall": 1.0, "f1": 1.0,
  "validation_rate": 1.0, "evidence_completeness": 1.0,
  "attack_chain_discovered": true, "attack_paths_to_canary": 2,
  "remediation_success": 1.0, "retest_success": 1.0, "regression_rate": 0.0
}
RESULT: PASS ✓
```

## Metrics

| Metric | Definition |
|---|---|
| **precision** | confirmed findings that match a real ground-truth id ÷ all confirmed findings |
| **recall** | ground-truth vulns discovered ÷ all ground-truth vulns |
| **f1** | harmonic mean of precision and recall |
| **validation_rate** | confirmed hypotheses ÷ decided hypotheses (confirmed + disproven + inconclusive) |
| **evidence_completeness** | findings citing ≥1 evidence record ÷ findings |
| **attack_chain_discovered** | at least one persisted path reaches the canary |
| **attack_paths_to_canary** | number of distinct chains that reach the crown-jewel |
| **remediation_success** | findings with a generated remediation ÷ findings |
| **retest_success** | retests that flipped `confirmed → disproven` (FIX VERIFIED) ÷ retests |
| **regression_rate** | retests that remained exploitable (FIX FAILED) ÷ retests |

## Why the scores are meaningful
- **Precision/recall** compare against a fixed set of ground-truth ids (`LAB-*`). A
  hallucinated finding (unknown id) would lower precision; a missed vuln would lower recall.
- **Evidence completeness** guards against prose-only findings — each finding must carry
  hashed request/response evidence.
- **Retest success** is the strongest signal: it can only be earned by replaying the
  original attack against a freshly patched instance and observing it fail.

## CI gate
The CI pipeline runs `dracarys eval` and fails the build unless recall, precision, and
retest success are perfect — so a regression that breaks discovery, chaining, or fix
verification blocks merge. Coverage is gated at ≥80%.

## Extending the benchmark
Add a new `LAB-XXX-001` (vulnerable + patched paths, ground truth, an attack module with
a deterministic criterion, and a remediation). The harness scores it automatically:
expected count grows, and recall/retest reflect whether DRACARYS discovers and fixes it.

## Scanner generalization (does detection actually transfer?)

The lab metrics above score the *specific* chain. The important question for a real tool is
whether the **generic detectors** find vulnerabilities in apps they were never written for.
That is measured by the generalization scorecard:

```bash
dracarys scan-selftest        # (also gated in CI)
```

It scans built-in, independent vulnerable apps (`dracarys/scanner/testbed.py`) whose
endpoints, parameter names, and shapes (HTML vs JSON API) are deliberately unlike the lab,
and scores:

| Metric | Meaning | Current |
|---|---|---|
| `recall` | ground-truth vuln classes detected ÷ expected, across the fixture apps | **1.0** (10/10) |
| `false_positives_safe` | serious findings raised against a **hardened control** app | **0** |
| `per_app` | expected / found / missed per app | all classes found |

Because the fixtures are independent of the detectors, this is a genuine (if small)
generalization test rather than a tautology. The CI pipeline fails if recall drops below
0.95 or any false positive appears on the control app — so a detector regression blocks merge.
