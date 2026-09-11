from core.pipeline import linux_log
from detectors.linux import ssh_bruteforce,sensitive_file_access,account_manipulation
from detectors.linux import privilege_escalation,persistence,suspicious_download
from detectors.linux import ssh_password_spray,suspicious_execution,log_tampering
from detectors.linux import suspicious_permission_change,sensitive_archive
from reporting.console import print_findings

def main():
   # linux_log("data/samples/linux/normal/auth_normal.log")
    events=linux_log("data/samples/linux/attack/auth_attack_scenarios.log")
    
    #findings = ssh_bruteforce.detect_ssh_bruteforce(events)
    #findings=sensitive_file_access.detect_sensitive_file_access(events)
    #findings=account_manipulation.detect_account_manipulation(events)
    #findings=privilege_escalation.detect_privilege_escalation(events)
    #findings=persistence.detect_persistence(events)
    # findings=suspicious_download.detect_suspicious_download(events)
    # findings=log_tampering.detect_log_tampering(events)
    # findings=suspicious_permission_change.detect_suspicious_permission_change(events)
    findings=sensitive_archive.detect_sensitive_archive(events)
    print_findings(findings)
    

  

if __name__ == "__main__":
    main()