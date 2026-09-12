from core.pipeline import linux_log
from detectors.linux import ssh_bruteforce,sensitive_file_access,account_manipulation
from detectors.linux import privilege_escalation,persistence,suspicious_download
from detectors.linux import ssh_password_spray,suspicious_execution,log_tampering
from detectors.linux import suspicious_permission_change,sensitive_archive,suspicious_privileged_shell
from reporting.console import print_findings
from correlation import ssh_to_privileged_shell, download_to_execution

def main():
    events = linux_log("data/samples/linux/attack/auth_attack_scenarios.log",year=2026)

    findings = []

    findings.extend(ssh_bruteforce.detect_ssh_bruteforce(events))
    findings.extend(ssh_password_spray.detect_ssh_password_spray(events))
    findings.extend(sensitive_file_access.detect_sensitive_file_access(events))
    findings.extend(account_manipulation.detect_account_manipulation(events))
    findings.extend(privilege_escalation.detect_privilege_escalation(events))
    findings.extend(persistence.detect_persistence(events))
    findings.extend(suspicious_download.detect_suspicious_download(events))
    findings.extend(suspicious_execution.detect_suspicious_execution(events))
    findings.extend(log_tampering.detect_log_tampering(events))
    findings.extend(suspicious_permission_change.detect_suspicious_permission_change(events))
    findings.extend(sensitive_archive.detect_sensitive_archive(events))
    findings.extend(suspicious_privileged_shell.detect_suspicious_privileged_shell(events))

    correlated = []

    correlated.extend(
        ssh_to_privileged_shell.correlate_ssh_to_privileged_shell(findings)
    )

    correlated.extend(
        download_to_execution.correlate_download_to_execution(findings)
    )
    
    print_findings(findings)
    print_findings(correlated)
   # print_findings(suspicious_execution.detect_suspicious_execution(events))

  

if __name__ == "__main__":
    main()