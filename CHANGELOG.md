# Changelog

All notable changes to this project are documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Raise `tools/` test coverage above 80% and enforce the threshold in pytest/CI via
  `pytest-cov` (`--cov-fail-under=80`).

## [0.1.0] - 2026-10-09

### Added

- Seven ATT&CK-mapped adversary emulation plans covering encoded PowerShell, certutil download,
  LSASS MiniDump via comsvcs.dll, Run key persistence, scheduled task creation, shadow copy
  deletion and Security event log clearing, each with allowlisted procedures, expected telemetry,
  detection-rules cross-references and ATT&CK mitigations.
- Lab architecture note covering isolation, written authorization and rules of engagement, plus a
  plan format guide.
- JSON Schema for plans and `tools/validate_plans.py` for schema, ATT&CK, telemetry catalog,
  detection manifest, command safety and identity checks.
- Coverage matrix generator (`tools/render_coverage.py`) and vendored Enterprise ATT&CK 19.2
  identifiers, Windows event catalog and a pinned detection-rules v0.1.0 manifest.
- Test suite, GitHub Actions workflow and dual licensing (CC BY 4.0 for content, MIT for tooling).

[Unreleased]: https://github.com/bfleming-bitflow/purple-team-lab/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bfleming-bitflow/purple-team-lab/releases/tag/v0.1.0
