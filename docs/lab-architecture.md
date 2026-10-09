# Lab architecture

This document describes the isolation, authorization and rules of engagement that apply to every
plan in this repository. Plans are documentation: they describe what a purple team may run in a
controlled lab. They are not permission to run anything on any system.

## Isolation

- Run plans only on hosts and networks that are dedicated to adversary emulation and that have
  no production data, no production credentials and no route to production networks.
- Prefer a hypervisor-isolated Windows guest with a host-only or internal virtual network. Outbound
  Internet access, if present at all, should be limited to a laboratory proxy that can only reach
  names under the reserved `*.lab.test` domain used in the plans.
- Collect logs off-host (Sysmon, Security, PowerShell) before any plan that deletes local evidence.
  The collector must sit outside the guest under test.
- Treat memory dumps, registry exports and log extracts as sensitive. Delete them during the plan's
  cleanup step and never commit them to this repository.

## Authorization

- Every plan sets `authorization_required: true`. Execution without written authorization from the
  owner of the lab and of any shared infrastructure is out of scope for this project.
- Authorization should name the plans to be run, the hosts in scope, the window of execution and
  the person responsible for cleanup and for notifying the blue team.
- Plans that touch LSASS, clear event logs or delete Volume Shadow Copies require elevated rights
  and an explicit acknowledgment that those actions can destroy local evidence on the guest.

## Rules of engagement

1. Stay inside the allowlisted commands of the plan. Do not substitute live malware, offensive
   frameworks or unpackaged exploit code.
2. Do not change the destination of any network step to a host outside `*.lab.test`.
3. Stop if telemetry collection fails. A plan without captured events does not produce a useful
   purple-team result and may leave the guest in a worse state.
4. Run cleanup even when the procedure fails partway through. Record deviations in the exercise
   notes, not by editing the plan after the fact.
5. Share findings with the blue team: which detections fired, which were partial or gaps, and
   which hardening steps remain open.

## Relationship to Atomic Red Team

Where a plan lists `atomic_tests`, the GUID refers to a public Atomic Red Team test that exercises
the same technique. The procedure in this repository is a simplified, allowlisted form of that
test, chosen so that the validator can enforce safety constraints. Prefer the plan's procedure
inside this lab; consult the Atomic Red Team source only as a reference.
