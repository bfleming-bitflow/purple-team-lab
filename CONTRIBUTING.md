# Contributing

Contributions that correct or add plans, or improve the tooling, are welcome.

## Before you start

Read [docs/lab-architecture.md](docs/lab-architecture.md) and
[docs/plan-format.md](docs/plan-format.md). Plans that do not follow them, or that introduce
commands outside the allowlist, will not be merged.

## Adding a plan

1. Copy an existing file under `plans/` and assign the next free `PTL-NNN` identifier. Name the
   file `<id-lowercase>-<slug>.yml`.
2. Map the technique and tactic against `data/attack-enterprise-techniques.csv` for the version in
   `data/ATTACK_VERSION`. Prefer current identifiers (for example `T1685.005` instead of the
   revoked `T1070.001`).
3. Keep procedure commands on the allowlist. Hosts in URLs must end in `.lab.test`.
4. List telemetry events that already appear in `data/windows-events.yml`, or add the event with
   a Microsoft documentation link first.
5. Cross-reference overlapping rules from detection-rules and set coverage honestly
   (`expected-match`, `partial` or `gap`).
6. Run `python tools/render_coverage.py` after the plan is valid.
7. Run `make check`.
8. Add the plan to the table in `README.md` and an entry under "Unreleased" in `CHANGELOG.md`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(plans): ...`,
`fix(plans): ...`, `feat(tools): ...`, `docs: ...`, `test: ...`, `build: ...`.

## Licensing of contributions

By contributing, you agree that written content is licensed under CC BY 4.0 and code under the
MIT License, as described in `README.md`.
