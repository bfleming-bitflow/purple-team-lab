## Summary

<!-- What the change adds or corrects, and which public sources support it. -->

## Checklist

- [ ] The plan uses only allowlisted living-off-the-land commands and hosts under `*.lab.test`.
- [ ] Every ATT&CK technique, tactic, mitigation, data component and detection strategy ID is
      current for the version in `data/ATTACK_VERSION`.
- [ ] Telemetry event IDs are listed in `data/windows-events.yml` with a Microsoft reference.
- [ ] Detection coverage claims (`expected-match` / `partial` / `gap`) match the referenced
      rule logic.
- [ ] `authorization_required` is true and cleanup restores the lab host.
- [ ] `make check` passes locally.
- [ ] `CHANGELOG.md` has an entry under "Unreleased".
