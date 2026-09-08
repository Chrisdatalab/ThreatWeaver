from core.pipeline import linux_log
from detectors.linux.ssh_bruteforce import detect_ssh_bruteforce
from reporting.console import print_findings

def main():
   # linux_log("data/samples/linux/normal/auth_normal.log")
    events=linux_log("data/samples/linux/attack/auth_attack_scenarios.log")
    findings = detect_ssh_bruteforce(events)

    

    print_findings(findings)

if __name__ == "__main__":
    main()