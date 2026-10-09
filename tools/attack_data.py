"""Regenerate the vendored ATT&CK reference files from an Enterprise ATT&CK STIX bundle.

Usage:
    python tools/attack_data.py --bundle enterprise-attack-19.2.json
    python tools/attack_data.py --bundle enterprise-attack-19.2.json --check

The bundle is published at https://github.com/mitre-attack/attack-stix-data. Revoked and
deprecated objects are excluded.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

# Files this repository vendors. Each name maps to a generator below.
OUTPUTS = (
    "attack-enterprise-techniques.csv",
    "attack-enterprise-tactics.csv",
    "attack-enterprise-mitigations.csv",
    "attack-enterprise-technique-mitigations.csv",
    "attack-enterprise-data-components.csv",
    "attack-enterprise-detection-strategies.csv",
    "attack-enterprise-analytics.csv",
)


class Bundle:
    def __init__(self, objects: list[dict]) -> None:
        self.objects = objects
        self.by_id = {obj["id"]: obj for obj in objects}

    @staticmethod
    def external_id(obj: dict) -> str | None:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    @staticmethod
    def live(obj: dict) -> bool:
        return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)

    def of_type(self, kind: str) -> list[dict]:
        return [obj for obj in self.objects if obj["type"] == kind and self.live(obj)]

    def relationships(self, kind: str) -> list[dict]:
        return [obj for obj in self.of_type("relationship") if obj["relationship_type"] == kind]

    def version(self) -> str:
        collections = self.of_type("x-mitre-collection")
        if len(collections) != 1:
            raise ValueError("expected exactly one x-mitre-collection object")
        return str(collections[0]["x_mitre_version"])


def _rows_to_csv(header: list[str], rows: Iterable[list[str]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return buffer.getvalue()


def techniques(bundle: Bundle) -> str:
    rows = []
    for obj in bundle.of_type("attack-pattern"):
        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
        rows.append([bundle.external_id(obj), obj["name"], ";".join(tactics)])
    return _rows_to_csv(["technique_id", "name", "tactics"], sorted(rows))


def tactics(bundle: Bundle) -> str:
    rows = [
        [bundle.external_id(obj), obj["x_mitre_shortname"], obj["name"]]
        for obj in bundle.of_type("x-mitre-tactic")
    ]
    return _rows_to_csv(["tactic_id", "shortname", "name"], sorted(rows))


def _mitigation_objects(bundle: Bundle) -> dict[str, dict]:
    return {
        obj["id"]: obj
        for obj in bundle.of_type("course-of-action")
        if (bundle.external_id(obj) or "").startswith("M")
    }


def mitigations(bundle: Bundle) -> str:
    rows = [[bundle.external_id(obj), obj["name"]] for obj in _mitigation_objects(bundle).values()]
    return _rows_to_csv(["mitigation_id", "name"], sorted(rows))


def _technique_ids(bundle: Bundle) -> dict[str, str]:
    return {obj["id"]: bundle.external_id(obj) for obj in bundle.of_type("attack-pattern")}


def technique_mitigations(bundle: Bundle) -> str:
    mits = _mitigation_objects(bundle)
    techs = _technique_ids(bundle)
    pairs = {
        (techs[rel["target_ref"]], bundle.external_id(mits[rel["source_ref"]]))
        for rel in bundle.relationships("mitigates")
        if rel["source_ref"] in mits and rel["target_ref"] in techs
    }
    return _rows_to_csv(["technique_id", "mitigation_id"], sorted(pairs))


def data_components(bundle: Bundle) -> str:
    rows = [[bundle.external_id(obj), obj["name"]] for obj in bundle.of_type("x-mitre-data-component")]
    return _rows_to_csv(["data_component_id", "name"], sorted(rows))


def detection_strategies(bundle: Bundle) -> str:
    techs = _technique_ids(bundle)
    detects: dict[str, set[str]] = {}
    for rel in bundle.relationships("detects"):
        if rel["target_ref"] in techs:
            detects.setdefault(rel["source_ref"], set()).add(techs[rel["target_ref"]])
    rows = [
        [bundle.external_id(obj), obj["name"], ";".join(sorted(detects.get(obj["id"], set())))]
        for obj in bundle.of_type("x-mitre-detection-strategy")
    ]
    return _rows_to_csv(["strategy_id", "name", "technique_ids"], sorted(rows))


def analytics(bundle: Bundle) -> str:
    parent: dict[str, str] = {}
    for strategy in bundle.of_type("x-mitre-detection-strategy"):
        for ref in strategy.get("x_mitre_analytic_refs", []):
            parent[ref] = bundle.external_id(strategy) or ""
    rows = []
    for obj in bundle.of_type("x-mitre-analytic"):
        components = sorted(
            {
                bundle.external_id(bundle.by_id[source["x_mitre_data_component_ref"]]) or ""
                for source in obj.get("x_mitre_log_source_references", [])
                if source.get("x_mitre_data_component_ref") in bundle.by_id
            }
        )
        rows.append(
            [
                bundle.external_id(obj),
                parent.get(obj["id"], ""),
                ";".join(sorted(obj.get("x_mitre_platforms", []))),
                ";".join(components),
            ]
        )
    return _rows_to_csv(["analytic_id", "strategy_id", "platforms", "data_component_ids"], sorted(rows))


def software(bundle: Bundle) -> str:
    rows = [
        [bundle.external_id(obj), obj["name"], obj["type"]]
        for kind in ("malware", "tool")
        for obj in bundle.of_type(kind)
    ]
    return _rows_to_csv(["software_id", "name", "type"], sorted(rows))


GENERATORS: dict[str, Callable[[Bundle], str]] = {
    "attack-enterprise-techniques.csv": techniques,
    "attack-enterprise-tactics.csv": tactics,
    "attack-enterprise-mitigations.csv": mitigations,
    "attack-enterprise-technique-mitigations.csv": technique_mitigations,
    "attack-enterprise-data-components.csv": data_components,
    "attack-enterprise-detection-strategies.csv": detection_strategies,
    "attack-enterprise-analytics.csv": analytics,
    "attack-enterprise-software.csv": software,
}


def build(bundle: Bundle) -> dict[str, str]:
    files = {name: GENERATORS[name](bundle) for name in OUTPUTS}
    files["ATTACK_VERSION"] = bundle.version() + "\n"
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--bundle", type=Path, required=True, help="enterprise-attack-<version>.json")
    parser.add_argument("--output-dir", type=Path, default=DATA)
    parser.add_argument("--check", action="store_true", help="fail if vendored files differ")
    args = parser.parse_args(argv)

    bundle = Bundle(json.loads(args.bundle.read_text(encoding="utf-8"))["objects"])
    files = build(bundle)
    stale = []
    for name, content in files.items():
        target = args.output_dir / name
        if args.check:
            current = target.read_text(encoding="utf-8") if target.exists() else None
            if current != content:
                stale.append(name)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            print(f"wrote {target}")
    if stale:
        print(f"out of date: {', '.join(stale)}", file=sys.stderr)
        return 1
    if args.check:
        print(f"reference data matches ATT&CK {bundle.version()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
