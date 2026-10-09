# Plan format

Each file under `plans/` is a YAML document that conforms to
[`schema/plan.schema.json`](../schema/plan.schema.json). The validator
(`tools/validate_plans.py`) enforces the schema and the cross-checks below.

## Required fields

| Field | Purpose |
| --- | --- |
| `id` | Stable identifier `PTL-NNN` |
| `title` | Short human title |
| `technique` | Primary Enterprise ATT&CK technique |
| `tactic` | ATT&CK tactic shortname valid for that technique |
| `platforms` | One or more of Windows, Linux, macOS |
| `authorization_required` | Must be `true` |
| `preconditions` | Lab state required before the procedure |
| `procedure` | Ordered steps with `name`, `description`, `command`, `shell`, `elevation_required` |
| `telemetry` | Expected events: `source`, `event_id`, `data_component`, `signal` |
| `detection_strategies` | ATT&CK detection strategy IDs (`DETnnnn`) covering a plan technique |
| `detections` | Cross-references into [detection-rules](https://github.com/bfleming-bitflow/detection-rules) |
| `mitigations` | ATT&CK mitigations mapped to the technique (may be empty when ATT&CK maps none) |
| `hardening` | Concrete configuration steps beyond the ATT&CK mitigation list |
| `cleanup` | Steps that restore the lab host |
| `references` | At least two HTTPS sources that document the technique or the procedure |

Optional: `additional_techniques`, `atomic_tests` (Atomic Red Team GUIDs).

## Cross-checks

- Technique, tactic, data-component, detection-strategy and mitigation identifiers must exist in
  the vendored ATT&CK 19.2 CSVs under `data/`.
- Each mitigation must be mapped by ATT&CK to the plan's technique or its parent. If ATT&CK maps
  any mitigation, the plan must list at least one.
- Each `telemetry` `(source, event_id)` pair must appear in `data/windows-events.yml`.
- Each detection path must exist in `data/detection-rules-manifest.csv` and be tagged with the
  claimed techniques.
- Procedure commands must use an allowlisted living-off-the-land executable, must not match the
  forbidden-pattern list (download cradles, IEX, UNC paths, bypass flags, and similar), and any
  URL host must end in `.lab.test`.
- The file name must start with the lowercased plan id.

## Coverage claims

Use `expected-match` only when the detection rule's logic would fire on the telemetry the plan
produces. Use `partial` when the rule needs an extra condition (for example a YARA rule that only
matches when the command is written to a file). Use `gap` when no overlapping rule exists and the
plan documents that absence.
