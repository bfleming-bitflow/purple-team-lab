# Coverage matrix

Generated from the plans in `plans/`. Do not edit by hand; regenerate with
`python tools/render_coverage.py`.

| Plan | Technique | Tactic | Detection strategies | Sigma | YARA | Mitigations |
| --- | --- | --- | --- | --- | --- | --- |
| [PTL-001](plans/ptl-001-encoded-powershell-command.yml) | T1027.010, T1059.001 | stealth | DET0505, DET0455 | proc_creation_win_powershell_encoded_command (expected-match) | powershell_encoded_command_launcher (partial) | M1049, M1040, M1038 |
| [PTL-002](plans/ptl-002-certutil-download.yml) | T1105 | command-and-control | DET0060 | proc_creation_win_certutil_url_download (expected-match) | certutil_download_or_decode_command (partial) | M1031, M1037 |
| [PTL-003](plans/ptl-003-lsass-comsvcs-minidump.yml) | T1003.001 | credential-access | DET0363 | proc_access_win_lsass_memory_read_access (partial) | lsass_memory_dump_command (partial) | M1043, M1040, M1026 |
| [PTL-004](plans/ptl-004-run-key-persistence.yml) | T1547.001 | persistence | DET0365 | registry_set_win_run_key_suspicious_target (expected-match) | registry_run_key_persistence_command (partial) | — |
| [PTL-005](plans/ptl-005-scheduled-task-creation.yml) | T1053.005 | persistence | DET0441 | proc_creation_win_schtasks_create_suspicious_action (expected-match) | — | M1047, M1028, M1018 |
| [PTL-006](plans/ptl-006-shadow-copy-deletion.yml) | T1490 | impact | DET0329 | proc_creation_win_shadow_copy_deletion (expected-match) | shadow_copy_deletion_command (partial) | M1053, M1028, M1038 |
| [PTL-007](plans/ptl-007-clear-security-event-log.yml) | T1685.005 | defense-impairment | DET0532 | proc_creation_win_wevtutil_clear_log (expected-match) | — | M1029, M1022 |

7 plan(s).
