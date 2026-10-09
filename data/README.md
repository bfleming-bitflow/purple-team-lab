# Reference data

| File | Content | Upstream |
| --- | --- | --- |
| `ATTACK_VERSION` | Enterprise ATT&CK version string | [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) |
| `attack-enterprise-techniques.csv` | Technique ID, name and tactics | Same |
| `attack-enterprise-tactics.csv` | Tactic ID, shortname and display name | Same |
| `attack-enterprise-mitigations.csv` | Mitigation ID and name | Same |
| `attack-enterprise-technique-mitigations.csv` | Technique-to-mitigation edges | Same |
| `attack-enterprise-data-components.csv` | Data component ID and name | Same |
| `attack-enterprise-detection-strategies.csv` | Strategy ID and covered techniques | Same |
| `attack-enterprise-analytics.csv` | Analytic ID, strategy and data components | Same |
| `windows-events.yml` | Event IDs used by plan telemetry, with Microsoft documentation links | Microsoft Learn |
| `detection-rules-manifest.csv` | Kind, path, identifier, name and techniques of each rule | [detection-rules](https://github.com/bfleming-bitflow/detection-rules) at commit `3cbe65f` (v0.1.0) |

Tactic shortnames follow the current ATT&CK vocabulary, including `stealth` (`TA0005`) and
`defense-impairment` (`TA0112`). Technique `T1070.001` is revoked in ATT&CK 19.2 in favour of
`T1685.005`; plans must use the current identifier.

To refresh ATT&CK data after a new release:

```sh
python tools/attack_data.py --bundle enterprise-attack-<version>.json
```

To refresh the detection-rules manifest from a local checkout:

```sh
python tools/detection_manifest.py --repo ../detection-rules
```
