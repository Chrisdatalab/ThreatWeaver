from core.pipeline import linux_log, web_log

from detectors.linux import (
    ssh_bruteforce,
    sensitive_file_access,
    account_manipulation,
    privilege_escalation,
    persistence,
    suspicious_download,
    ssh_password_spray,
    suspicious_execution,
    log_tampering,
    suspicious_permission_change,
    sensitive_archive,
    suspicious_privileged_shell,
)

from detectors.web import (
    path_traversal,
    sql_injection,
    xss,
    sensitive_path,
)

from correlation import (
    ssh_to_privileged_shell,
    download_to_execution,
    web_to_ssh,
)

def analyze_file(file_path, log_type, year=None):
    if log_type == "linux":
        return analyze_linux(file_path, year)

    elif log_type == "web":
        return analyze_web(file_path)

    else:
        raise ValueError(f"Unsupported log type: {log_type}")
def analyze_linux(file_path, year):
    findings = []

    linux_events = linux_log(file_path, year)

    
    findings.extend(
        ssh_bruteforce.detect_ssh_bruteforce(linux_events)
    )

    findings.extend(
        ssh_password_spray.detect_ssh_password_spray(linux_events)
    )

    findings.extend(
        sensitive_file_access.detect_sensitive_file_access(linux_events)
    )

    findings.extend(
        account_manipulation.detect_account_manipulation(linux_events)
    )

    findings.extend(
        privilege_escalation.detect_privilege_escalation(linux_events)
    )

    findings.extend(
        persistence.detect_persistence(linux_events)
    )

    findings.extend(
        suspicious_download.detect_suspicious_download(linux_events)
    )

    findings.extend(
        suspicious_execution.detect_suspicious_execution(linux_events)
    )

    findings.extend(
        log_tampering.detect_log_tampering(linux_events)
    )

    findings.extend(
        suspicious_permission_change.detect_suspicious_permission_change(
            linux_events
        )
    )

    findings.extend(
        sensitive_archive.detect_sensitive_archive(linux_events)
    )

    findings.extend(
        suspicious_privileged_shell.detect_suspicious_privileged_shell(
            linux_events
        )
    )
    return findings
def analyze_web(file_path):
    findings = []

    web_events = web_log(file_path, year=None)

    findings.extend(
            path_traversal.detect_path_traversal(web_events)
        )
    
    findings.extend(
        sql_injection.detect_sql_injection(web_events)
    )

    findings.extend(
        xss.detect_xss(web_events)
    )

    findings.extend(
        sensitive_path.detect_sensitive_path(web_events)
    )



    return findings
def run_correlations(findings):
    correlated = []

    
    correlated.extend(
        ssh_to_privileged_shell.correlate_ssh_to_privileged_shell(findings)
    )

    correlated.extend(
        download_to_execution.correlate_download_to_execution(findings)
    )
    correlated.extend(
        web_to_ssh.correlate_web_to_ssh(findings)
    )
    return correlated
def finding_to_dict(finding):
    data = {
        "finding_type": finding.finding_type,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "source": finding.source,
        "host": finding.host,
        "user": finding.user,
        "src_ip": finding.src_ip,
        "start_time": finding.start_time.isoformat() if finding.start_time else None,
        "end_time": finding.end_time.isoformat() if finding.end_time else None,
        "event_count": finding.event_count,
        "attributes": finding.attributes,
    }

    return data
def findings_to_dict(findings):
    return [finding_to_dict(finding) for finding in findings]