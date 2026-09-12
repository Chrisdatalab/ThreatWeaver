from datetime import datetime, timedelta
from models.finding import Finding

def correlate_ssh_to_privileged_shell(findings):
    ssh_attacks = []
    privileged_shells = []
    correlated = []
    for finding in findings:
        if finding.finding_type in ["ssh_bruteforce", "ssh_password_spray"]:
            ssh_attacks.append(finding)

        elif finding.finding_type == "privileged_shell":
            privileged_shells.append(finding)
    for attack in ssh_attacks:
        attack_time = attack.end_time
        
        for shell in privileged_shells:
            if attack.host != shell.host:
                continue
            shell_time = shell.start_time
            if shell_time <= attack_time:
                continue
            time_difference = shell_time - attack_time
            if time_difference > timedelta(minutes=15):
                continue
            if attack.finding_type == "ssh_bruteforce":
                if attack.user != shell.user:
                    continue
            elif attack.finding_type == "ssh_password_spray":
                users = attack.attributes.get("unique_user", [])

                if shell.user not in users:
                    continue
        
            
            correlation_finding = Finding(
                        finding_type="possible_ssh_compromise",
                        title="SSH Attack Followed by Privileged Shell",
                        description=f"User {shell.user} started a privileged shell using sudo.",
                        severity="critical",
                        source="linux",
                        host=shell.host,
                        user=shell.user,
                        src_ip=attack.src_ip,
                        start_time=attack.start_time,
                        event_count=attack.event_count+shell.event_count,
                        end_time=shell.end_time,
                        events=attack.events+shell.events,
                        attributes={
                            "attack_type": "ssh_compromise",
                            "time_gap_seconds": time_difference.total_seconds(),
                            "attack_src_ip": attack.src_ip
                            }
                        
                    )
            correlated.append(correlation_finding)
    return correlated