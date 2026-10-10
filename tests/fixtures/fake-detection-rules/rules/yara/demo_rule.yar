rule Demo_Yara_Rule
{
    meta:
        id = "22222222-2222-2222-2222-222222222222"
        author = "test"
        date = "2026-10-09"
        description = "Fixture YARA rule for manifest generator tests"
        mitre_attack = "T1059.001 T1105"
        severity = "low"
        license = "DRL 1.1"

    strings:
        $a = "demo-fixture" ascii

    condition:
        $a
}
