"""Validate adversary emulation plans against the schema and vendored ATT&CK data.

Usage:
    python tools/validate_plans.py [PLAN ...]

With no arguments, every file in plans/ is checked. Validation covers the JSON Schema, the ATT&CK
technique, tactic, data-component and mitigation identifiers, the relationship between techniques
and tactics, cross-references into the detection-rules manifest, Windows event identifiers from the
local catalog and a safety allowlist for the simulated commands.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent
PLANS = ROOT / "plans"
SCHEMA = ROOT / "schema" / "plan.schema.json"
DATA = ROOT / "data"

# Executables permitted in simulated procedures. These are the living-off-the-land binaries and
# well-known atomic-test commands the plans emulate; novel offensive tooling is not allowed.
ALLOWED_COMMANDS = frozenset(
    {
        "attrib",
        "bcdedit",
        "certutil",
        "cmd",
        "icacls",
        "powershell",
        "pwsh",
        "reg",
        "rundll32",
        "schtasks",
        "vssadmin",
        "wevtutil",
        "wmic",
    }
)

# Patterns (matched on the lowercased command) that would execute fetched or decoded code, reach a
# network share, or add evasion flags that the plans do not need.
FORBIDDEN_PATTERNS = (
    r"\biex\b",
    r"invoke-expression",
    r"invoke-webrequest",
    r"invoke-restmethod",
    r"\biwr\b",
    r"\birm\b",
    r"downloadstring",
    r"downloaddata",
    r"downloadfile",
    r"frombase64string",
    r"\\\\[a-z0-9]",  # UNC path
    r"mimikatz",
    r"-nop\b",
    r"-noprofile",
    r"-windowstyle",
    r"bypass",
)

URL = re.compile(r"https?://([^/\s:'\"]+)", re.IGNORECASE)
LAB_DOMAIN = ".lab.test"
COMMAND_TOKEN = re.compile(r"[A-Za-z0-9_.-]+")


@dataclass
class Plan:
    path: Path
    data: dict


@cache
def _csv_column(name: str, column: str) -> frozenset[str]:
    with (DATA / name).open(encoding="utf-8", newline="") as handle:
        return frozenset(row[column] for row in csv.DictReader(handle))


@cache
def technique_tactics() -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    with (DATA / "attack-enterprise-techniques.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            mapping[row["technique_id"]] = set(filter(None, row["tactics"].split(";")))
    return mapping


def tactic_shortnames() -> frozenset[str]:
    return _csv_column("attack-enterprise-tactics.csv", "shortname")


@cache
def detection_strategies() -> dict[str, set[str]]:
    with (DATA / "attack-enterprise-detection-strategies.csv").open(encoding="utf-8", newline="") as handle:
        return {
            row["strategy_id"]: set(filter(None, row["technique_ids"].split(";")))
            for row in csv.DictReader(handle)
        }


@cache
def mitigation_names() -> dict[str, str]:
    with (DATA / "attack-enterprise-mitigations.csv").open(encoding="utf-8", newline="") as handle:
        return {row["mitigation_id"]: row["name"] for row in csv.DictReader(handle)}


def data_component_ids() -> frozenset[str]:
    return _csv_column("attack-enterprise-data-components.csv", "data_component_id")


@cache
def technique_mitigations() -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    with (DATA / "attack-enterprise-technique-mitigations.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            mapping.setdefault(row["technique_id"], set()).add(row["mitigation_id"])
    return mapping


@cache
def detection_manifest() -> dict[str, set[str]]:
    with (DATA / "detection-rules-manifest.csv").open(encoding="utf-8", newline="") as handle:
        return {
            row["path"]: set(filter(None, row["techniques"].split(";"))) for row in csv.DictReader(handle)
        }


@cache
def windows_events() -> set[tuple[str, int]]:
    catalog = yaml.safe_load((DATA / "windows-events.yml").read_text(encoding="utf-8"))
    return {(entry["source"], int(entry["event_id"])) for entry in catalog["events"]}


@cache
def schema_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def load(path: Path) -> Plan:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("plan must be a YAML mapping")
    return Plan(path=path, data=data)


def check_schema(plan: Plan) -> list[str]:
    errors = []
    for error in sorted(schema_validator().iter_errors(plan.data), key=lambda e: list(e.absolute_path)):
        location = "/".join(str(part) for part in error.absolute_path) or "(root)"
        errors.append(f"schema: {location}: {error.message}")
    return errors


def check_attack(plan: Plan) -> list[str]:
    errors = []
    data = plan.data
    tactics = technique_tactics()
    techniques = [data["technique"], *data.get("additional_techniques", [])]
    for technique in techniques:
        if technique not in tactics:
            errors.append(f"{technique} is not a current Enterprise ATT&CK technique")
    tactic = data["tactic"]
    if tactic not in tactic_shortnames():
        errors.append(f"tactic {tactic!r} is not a current ATT&CK tactic shortname")
    elif data["technique"] in tactics and tactic not in tactics[data["technique"]]:
        valid = ", ".join(sorted(tactics[data["technique"]]))
        errors.append(f"tactic {tactic!r} is not valid for {data['technique']} (expected one of: {valid})")
    for source in data.get("telemetry", []):
        component = source.get("data_component")
        if component and component not in data_component_ids():
            errors.append(f"telemetry data_component {component} is not a current ATT&CK data component")
    strategies = detection_strategies()
    for strategy in data.get("detection_strategies", []):
        if strategy not in strategies:
            errors.append(f"detection strategy {strategy} is not a current ATT&CK detection strategy")
        elif not strategies[strategy] & set(techniques):
            errors.append(f"detection strategy {strategy} does not cover any technique in this plan")
    names = mitigation_names()
    applicable: set[str] = set()
    for technique in techniques:
        applicable |= technique_mitigations().get(technique, set())
        applicable |= technique_mitigations().get(technique.split(".")[0], set())
    for mitigation in data.get("mitigations", []):
        mid = mitigation.get("id")
        if mid not in names:
            errors.append(f"mitigation {mid} is not a current ATT&CK mitigation")
            continue
        if mitigation.get("name") != names[mid]:
            errors.append(
                f"mitigation {mid} is named {names[mid]!r} in ATT&CK, not {mitigation.get('name')!r}"
            )
        if mid not in applicable:
            errors.append(f"mitigation {mid} is not mapped to this plan's techniques (or their parents)")
    if applicable and not data.get("mitigations"):
        errors.append(
            f"ATT&CK maps mitigations to this plan's techniques ({', '.join(sorted(applicable))}); "
            "list at least one"
        )
    return errors


def check_detections(plan: Plan) -> list[str]:
    errors = []
    manifest = detection_manifest()
    techniques = {plan.data["technique"], *plan.data.get("additional_techniques", [])}
    for index, detection in enumerate(plan.data.get("detections", [])):
        path = detection.get("path")
        covered = detection.get("techniques", [])
        if path not in manifest:
            errors.append(f"detections[{index}]: {path} is not in data/detection-rules-manifest.csv")
            continue
        for technique in covered:
            if technique not in manifest[path]:
                errors.append(f"detections[{index}]: {path} is not tagged with {technique}")
            if technique not in techniques:
                errors.append(f"detections[{index}]: {technique} is not a technique of this plan")
    return errors


def check_commands(plan: Plan) -> list[str]:
    errors = []
    for index, step in enumerate(plan.data.get("procedure", [])):
        command = step.get("command", "")
        lowered = command.lower()
        for forbidden in FORBIDDEN_PATTERNS:
            if re.search(forbidden, lowered):
                errors.append(f"procedure[{index}]: command contains disallowed pattern {forbidden!r}")
        for host in URL.findall(command):
            if not host.lower().endswith(LAB_DOMAIN):
                errors.append(
                    f"procedure[{index}]: URL host {host!r} is outside the lab domain ({LAB_DOMAIN})"
                )
        tokens = COMMAND_TOKEN.findall(command)
        if not tokens:
            errors.append(f"procedure[{index}]: command has no executable token")
            continue
        executable = tokens[0].split("\\")[-1].removesuffix(".exe").lower()
        if executable not in ALLOWED_COMMANDS:
            errors.append(
                f"procedure[{index}]: executable {executable!r} is not in the safe allowlist "
                f"({', '.join(sorted(ALLOWED_COMMANDS))})"
            )
    return errors


def check_telemetry(plan: Plan) -> list[str]:
    errors = []
    catalog = windows_events()
    for index, source in enumerate(plan.data.get("telemetry", [])):
        key = (source.get("source"), source.get("event_id"))
        if key not in catalog:
            errors.append(
                f"telemetry[{index}]: ({source.get('source')!r}, {source.get('event_id')}) "
                "is not listed in data/windows-events.yml"
            )
    return errors


def check_identity(plan: Plan) -> list[str]:
    errors = []
    plan_id = str(plan.data.get("id", ""))
    if plan_id and not plan.path.name.startswith(plan_id.lower() + "-"):
        errors.append(f"file name must start with '{plan_id.lower()}-'")
    return errors


def validate_plan(path: Path) -> list[str]:
    try:
        plan = load(path)
    except (ValueError, yaml.YAMLError) as exc:
        return [str(exc)]
    errors = check_schema(plan)
    if errors:
        return errors
    for check in (check_attack, check_telemetry, check_detections, check_commands, check_identity):
        errors.extend(check(plan))
    return errors


def discover() -> list[Path]:
    return sorted(PLANS.glob("*.yml"))


def validate(paths: list[Path]) -> int:
    failures = 0
    ids: dict[str, Path] = {}
    for path in paths:
        errors = validate_plan(path)
        try:
            plan_id = load(path).data.get("id")
        except (ValueError, yaml.YAMLError):
            plan_id = None
        if plan_id in ids:
            errors.append(f"duplicate plan id {plan_id} (also in {ids[plan_id].name})")
        elif plan_id:
            ids[plan_id] = path
        for error in errors:
            print(f"{_display(path)}: {error}", file=sys.stderr)
        failures += bool(errors)
    if failures:
        print(f"{failures} of {len(paths)} plan(s) failed validation", file=sys.stderr)
        return 1
    print(f"{len(paths)} plan(s) valid")
    return 0


def _display(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("plans", nargs="*", type=Path)
    args = parser.parse_args(argv)
    paths = args.plans or discover()
    if not paths:
        print("no plans found", file=sys.stderr)
        return 1
    return validate(paths)


if __name__ == "__main__":
    sys.exit(main())
