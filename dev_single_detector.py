from core.pipeline import linux_log
from detectors.linux.reverse_shell import (
    detect_reverse_shell
)

FILE_PATH = (
    "data/samples/linux/attack/"
    "ThreatWeaver_linux_attack_dataset_complete.log"
)

YEAR = 2026

events = linux_log(FILE_PATH, YEAR)

findings = detect_reverse_shell(events)

print(f"TOTAL EVENTS: {len(events)}")
print(f"TOTAL FINDINGS: {len(findings)}")

for i, finding in enumerate(findings, start=1):
    print(f"\n[{i}]")
    print(f"Type: {finding.finding_type}")
    print(f"Title: {finding.title}")
    print(f"Severity: {finding.severity}")
    print(f"User: {finding.user}")
    print(f"Host: {finding.host}")
    print(f"Time: {finding.start_time}")

    for key, value in finding.attributes.items():
        print(f"{key}: {value}")