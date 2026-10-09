# purple-team-lab

ATT&CK-mapped adversary emulation plans for an isolated Windows lab. Each plan documents a
benign, allowlisted procedure, the telemetry it should produce, the overlapping rules in
[detection-rules](https://github.com/bfleming-bitflow/detection-rules), and the ATT&CK
mitigations that apply.

Plans are documentation. Running them requires written authorization and a dedicated lab; see
[docs/lab-architecture.md](docs/lab-architecture.md).

## Plans

| ID | Technique | Tactic | Title |
| --- | --- | --- | --- |
| [PTL-001](plans/ptl-001-encoded-powershell-command.yml) | T1027.010, T1059.001 | stealth | Encoded PowerShell command |
| [PTL-002](plans/ptl-002-certutil-download.yml) | T1105 | command-and-control | Certutil URL download |
| [PTL-003](plans/ptl-003-lsass-comsvcs-minidump.yml) | T1003.001 | credential-access | LSASS memory read via comsvcs.dll MiniDump |
| [PTL-004](plans/ptl-004-run-key-persistence.yml) | T1547.001 | persistence | Run key persistence |
| [PTL-005](plans/ptl-005-scheduled-task-creation.yml) | T1053.005 | persistence | Scheduled task creation |
| [PTL-006](plans/ptl-006-shadow-copy-deletion.yml) | T1490 | impact | Shadow copy deletion with vssadmin |
| [PTL-007](plans/ptl-007-clear-security-event-log.yml) | T1685.005 | defense-impairment | Clear Security event log |

The [coverage matrix](docs/coverage.md) lists detection strategies, Sigma/YARA overlap and
mitigations for each plan.

## Scope

In scope:

- YAML emulation plans that overlap the public detection-rules set;
- a JSON Schema, a validator and a coverage renderer;
- a lab architecture note covering isolation, authorization and rules of engagement;
- vendored Enterprise ATT&CK 19.2 identifiers used for validation.

Out of scope:

- live malware, exploit code, credential dumping tools or any binary that is not a built-in
  Windows utility;
- plans that reach hosts outside the reserved `*.lab.test` domain;
- production or customer environments of any kind.

## Repository layout

```text
plans/                 Emulation plans, one YAML file per technique exercise
docs/                  Lab architecture, plan format and generated coverage matrix
schema/                JSON Schema for plans
data/                  Vendored ATT&CK 19.2 identifiers, Windows event catalog, detection-rules manifest
tools/                 Plan validator, coverage renderer, reference data generators
tests/                 pytest suite
```

## Validation

`tools/validate_plans.py` checks every file in `plans/`:

| Check | Rule |
| --- | --- |
| Schema | Document conforms to `schema/plan.schema.json` |
| ATT&CK | Technique, tactic, data-component, detection-strategy and mitigation IDs are current; the tactic is valid for the technique; mitigations are mapped to the technique or its parent |
| Telemetry | Each `(source, event_id)` pair is listed in `data/windows-events.yml` |
| Detections | Paths exist in the pinned detection-rules manifest and carry the claimed techniques |
| Commands | Executables are allowlisted; forbidden patterns (download cradles, IEX, UNC, bypass flags) are rejected; URL hosts end in `.lab.test` |
| Identity | File name starts with the lowercased plan id; plan ids are unique |

## Development

Requires Python 3.11 or later.

```sh
make venv     # create .venv and install pinned development dependencies
make check    # ruff, yamllint, pymarkdown, plan validation, coverage check, pytest
```

The same checks run in GitHub Actions on every push and pull request
([.github/workflows/ci.yml](.github/workflows/ci.yml)).

## Limitations

- Procedures are simplified, allowlisted forms of public Atomic Red Team tests. They are not a
  substitute for a full red-team engagement and do not cover every variant of a technique.
- Detection coverage is reasoned from rule logic and expected telemetry. A plan marked
  `expected-match` has not necessarily been executed against a live SIEM in this repository.
- ATT&CK identifiers are validated against version 19.2. Mappings can change between releases.
- The lab architecture document describes required controls; this repository cannot enforce them
  on your hosts.

## Licensing

This repository uses two licenses:

| Material | License |
| --- | --- |
| Written content: `plans/`, `docs/` and the README files | [CC BY 4.0](LICENSE-CONTENT) |
| Code and configuration: `tools/`, `tests/`, `schema/`, build and CI files | [MIT](LICENSE) |

`data/` contains identifiers derived from MITRE ATT&CK, which is subject to the
[ATT&CK terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), and a
manifest generated from detection-rules. Atomic Red Team GUIDs, where cited, belong to Red Canary
and are referenced for cross-identification only.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).
