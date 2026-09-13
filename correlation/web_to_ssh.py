from models.finding import Finding
from datetime import timedelta

WEB_ATTACK_TYPES = [
    "path_traversal",
    "sql_injection",
    "xss",
    "sensitive_path_probing",
]

SSH_ATTACK_TYPES = [
    "ssh_bruteforce",
    "ssh_password_spray",
]
def correlate_web_to_ssh(findings):
    group = {}
    correlated = []
    for finding in findings:
        key = finding.src_ip

        if (
            finding.finding_type not in WEB_ATTACK_TYPES
            and finding.finding_type not in SSH_ATTACK_TYPES
        ):
            continue

        if key not in group:
            group[key] = {
                "web": [],
                "ssh": []
            }

        if finding.finding_type in WEB_ATTACK_TYPES:
            group[key]["web"].append(finding)

        elif finding.finding_type in SSH_ATTACK_TYPES:
            group[key]["ssh"].append(finding)
    for ip, value in group.items():
        if not value["web"] or not value["ssh"]:
            continue
        for w_finding in value["web"]:
            for s_finding in value["ssh"]:
                gap = s_finding.start_time - w_finding.end_time
                if gap < timedelta(0) or gap > timedelta(minutes=15):
                    continue
                correlation_finding = Finding(
                            finding_type="web_to_ssh_attack",
                            title="Web Attack Followed by SSH Attack",
                            description=f"Source IP {ip} performed a web attack followed by SSH attack activity.",
                            severity="CRITICAL",
                            source="correlation",
                            host=s_finding.host,
                            user=s_finding.user,
                            src_ip=s_finding.src_ip,
                            start_time=w_finding.start_time,
                            event_count=w_finding.event_count + s_finding.event_count,
                            end_time=s_finding.end_time,
                            events=s_finding.events+w_finding.events,
                            attributes={
                                "correlation_type": "web_to_ssh",
                                "web_attack_type": w_finding.finding_type,
                                "ssh_attack_type": s_finding.finding_type,
                                "time_gap_seconds": gap.total_seconds(),
                            }
                            
                        )
                correlated.append(correlation_finding)
    return correlated