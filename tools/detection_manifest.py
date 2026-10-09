"""Build the pinned manifest of rules published in the detection-rules repository.

Usage:
    python tools/detection_manifest.py --repo ../detection-rules
    python tools/detection_manifest.py --repo ../detection-rules --check

The manifest lets this repository validate cross-references (rule path, identifier and ATT&CK
techniques) without a network dependency. Record the detection-rules commit used in
data/README.md when regenerating.
"""

from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "data" / "detection-rules-manifest.csv"

SIGMA_TAG = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
YARA_RULE = re.compile(r"^\s*rule\s+(\w+)", re.MULTILINE)
YARA_META = re.compile(r'^\s*(id|mitre_attack)\s*=\s*"([^"]*)"', re.MULTILINE)


def sigma_rows(repo: Path) -> list[list[str]]:
    rows = []
    for path in sorted((repo / "rules" / "sigma").rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        techniques = sorted(
            f"T{match.group(1)}" for tag in data.get("tags", []) if (match := SIGMA_TAG.match(str(tag)))
        )
        rows.append(
            [
                "sigma",
                path.relative_to(repo).as_posix(),
                str(data["id"]),
                path.stem,
                ";".join(techniques),
            ]
        )
    return rows


def yara_rows(repo: Path) -> list[list[str]]:
    rows = []
    for path in sorted((repo / "rules" / "yara").glob("*.yar")):
        text = path.read_text(encoding="utf-8")
        names = YARA_RULE.findall(text)
        if len(names) != 1:
            raise ValueError(f"{path}: expected exactly one rule")
        meta = dict(YARA_META.findall(text))
        techniques = sorted(set(TECHNIQUE.findall(meta.get("mitre_attack", ""))))
        rows.append(["yara", path.relative_to(repo).as_posix(), meta["id"], names[0], ";".join(techniques)])
    return rows


def render(repo: Path) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["kind", "path", "rule_id", "name", "techniques"])
    writer.writerows(sorted(sigma_rows(repo) + yara_rows(repo)))
    return buffer.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--repo", type=Path, required=True, help="path to a detection-rules checkout")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true", help="fail if the manifest is out of date")
    args = parser.parse_args(argv)

    content = render(args.repo)
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else None
        if current != content:
            print(f"stale: {args.output}", file=sys.stderr)
            return 1
        print("manifest is up to date")
        return 0
    args.output.write_text(content, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
