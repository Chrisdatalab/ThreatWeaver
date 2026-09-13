from services.analyzer import (
    analyze_linux,
    analyze_web,
    run_correlations,
    finding_to_dict,
    findings_to_dict,
    build_ai_context
)

from reporting.console import print_findings
from services.ai_analyst import build_ai_prompt,analyze_security_context
from database.db import get_connection
from database.investigations import create_investigation
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

    context = build_ai_context(findings, correlated)

    prompt = build_ai_prompt(context)

    analysis = analyze_security_context(context)

    #print(analysis)
  
        



if __name__ == "__main__":
    main()