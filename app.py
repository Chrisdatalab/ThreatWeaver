from services.analyzer import (
    analyze_linux,
    analyze_web,
    run_correlations,
    finding_to_dict,
    findings_to_dict,
)

from reporting.console import print_findings

def main():

    linux_findings = analyze_linux(
        "data/samples/linux/attack/auth_attack_scenarios.log",
        year=2026
    )

    web_normal_findings = analyze_web(
        "data/samples/web/normal/access_normal.log"
    )

    web_attack_findings = analyze_web(
        "data/samples/web/attack/access_attack.log"
    )

    findings = (
        linux_findings
        + web_normal_findings
        + web_attack_findings
    )

    correlated = run_correlations(findings)

    print_findings(findings)

    print("\n========== CORRELATED ==========\n")

    print_findings(correlated)
    print(findings_to_dict(findings)[0])


if __name__ == "__main__":
    main()