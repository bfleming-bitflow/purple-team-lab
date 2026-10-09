"""Render the ATT&CK coverage matrix for the plans in this repository.

Usage:
    python tools/render_coverage.py            # write docs/coverage.md
    python tools/render_coverage.py --check    # exit 1 if docs/coverage.md is stale
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PLANS = ROOT / "plans"
OUTPUT = ROOT / "docs" / "coverage.md"


def load_plans() -> list[dict]:
    plans = []
    for path in sorted(PLANS.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["_path"] = path.as_posix().removeprefix(str(ROOT) + "/")
        plans.append(data)
    return plans


def render(plans: list[dict]) -> str:
    lines = [
        "# Coverage matrix",
        "",
        "Generated from the plans in `plans/`. Do not edit by hand; regenerate with",
        "`python tools/render_coverage.py`.",
        "",
        "| Plan | Technique | Tactic | Detection strategies | Sigma | YARA | Mitigations |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for plan in plans:
        techniques = [plan["technique"], *plan.get("additional_techniques", [])]
        sigma = []
        yara = []
        for detection in plan.get("detections", []):
            path = detection["path"]
            tag = f"{Path(path).stem} ({detection['coverage']})"
            if path.endswith(".yar"):
                yara.append(tag)
            else:
                sigma.append(tag)
        mitigations = ", ".join(m["id"] for m in plan.get("mitigations", [])) or "—"
        lines.append(
            "| [{id}]({path}) | {tech} | {tactic} | {det} | {sigma} | {yara} | {mit} |".format(
                id=plan["id"],
                path=plan["_path"],
                tech=", ".join(techniques),
                tactic=plan["tactic"],
                det=", ".join(plan.get("detection_strategies", [])),
                sigma="; ".join(sigma) or "—",
                yara="; ".join(yara) or "—",
                mit=mitigations,
            )
        )
    lines.append("")
    lines.append(f"{len(plans)} plan(s).")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if docs/coverage.md is stale")
    args = parser.parse_args(argv)
    content = render(load_plans())
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != content:
            print(f"{OUTPUT.relative_to(ROOT)} is stale; run tools/render_coverage.py", file=sys.stderr)
            return 1
        print(f"{OUTPUT.relative_to(ROOT)} is up to date")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
