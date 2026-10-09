# Security policy

## Scope

This repository contains documentation of adversary emulation plans and a small Python tool that
processes local YAML files. It does not run as a service, contains no malware samples and handles
no credentials.

Reports are welcome for:

- vulnerabilities in `tools/` or the CI workflow (for example unsafe YAML loading or workflow
  injection);
- a plan whose procedure reaches outside the allowlisted commands or the `*.lab.test` domain;
- factual errors in telemetry, detection coverage or mitigation mapping that would mislead a
  defender, with the public source that shows the correction.

Vulnerabilities in third-party products should be reported to their vendors.

## Reporting

Use GitHub private vulnerability reporting ("Report a vulnerability" under the Security tab).
Include the affected file, the expected and actual content, and public references that support
the correction.

Factual corrections that are not security-relevant can be filed as regular issues.

## Handling of plans

Never attach malware samples, live payloads, memory dumps or production credentials to issues or
pull requests. Plans must keep network destinations under `*.lab.test` and must not introduce
download cradles, encoded IEX launchers or similar patterns rejected by the validator.
