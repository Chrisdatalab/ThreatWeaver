from services.analyzer import analyze_file, run_correlations


FILE_PATH = (
    "data/samples/linux/attack/"
    "ThreatWeaver_linux_attack_dataset_complete.log"
)

LOG_TYPE = "linux"
YEAR = 2026


findings = analyze_file(
    FILE_PATH,
    LOG_TYPE,
    YEAR
)

print("=" * 60)
print(f"TOTAL FINDINGS: {len(findings)}")
print("=" * 60)

for i, finding in enumerate(findings, start=1):
    print(f"\n[{i}]")
    print(finding)


correlations = run_correlations(findings)

print("\n" + "=" * 60)
print(f"TOTAL CORRELATIONS: {len(correlations)}")
print("=" * 60)

for i, correlation in enumerate(correlations, start=1):
    print(f"\n[{i}]")
    print(correlation)