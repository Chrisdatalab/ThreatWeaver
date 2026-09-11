from models.finding import Finding
import shlex,os
from urllib.parse import urlparse

SENSITIVE_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/audit/",
]
FILE_TAMPERING_COMMANDS = [
    "rm",
    "shred",
    "truncate",
]

JOURNAL_TAMPERING_OPTIONS = [
    "--vacuum-time",
    "--vacuum-size",
    "--vacuum-files",
]
def detect_log_tampering(events):
    findings=[]
    
    
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts=shlex.split(command)
        if not parts:
            continue
        suspicious_log_tampering=False
        details={}
        ex=os.path.basename(parts[0])
        if ex in FILE_TAMPERING_COMMANDS:
            for v in parts[1:]:
                if any(v.startswith(argument) for argument in SENSITIVE_LOG_PATHS):
                    suspicious_log_tampering=True
                    break
        elif ex =="journalctl":
            for v in parts[1:]:
                if any(v.startswith(option) for option in JOURNAL_TAMPERING_OPTIONS):
                    suspicious_log_tampering=True
                    break
        elif ex=="history":
            if "-c" in parts[1:]:
                suspicious_log_tampering = True
        if not suspicious_log_tampering:
            continue
        details["raw_command"]=command

        security="HIGH"
        finding = Finding(
                    finding_type="log_tampering",
                    title="Possible Log Tampering Detected",
                    description=f"User {event.user} performed an operation that may delete or modify system logs.",
                    severity=security,
                    source="linux",
                    host=event.host,
                    user=event.user,
                    src_ip=event.src_ip,
                    start_time=event.timestamp,
                    event_count=1,
                    end_time=event.timestamp,
                    events=[event],
                    attributes=details
                    
                )
        findings.append(finding)



    return findings