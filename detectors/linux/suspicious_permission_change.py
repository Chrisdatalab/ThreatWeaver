from models.finding import Finding
import shlex,os

EXEC_PERMISSION_MODES = [
    "+x",
    "u+x",
    "g+x",
    "o+x",
    "a+x",
]
EXEC_NUMERIC_MODES = [
    "700",
    "711",
    "744",
    "755",
    "770",
    "775",
    "777",
]
SUSPICIOUS_DIRS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]
def detect_suspicious_permission_change(events):
    findings=[]
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts=shlex.split(command)
        if not parts:
            continue
        suspicious_permission=False
        has_exec_mode = False
        has_suspicious_path = False
        details={}
        executable = os.path.basename(parts[0])
        if executable=="chmod":
            for v in parts[1:]:
                if v in EXEC_PERMISSION_MODES or v in EXEC_NUMERIC_MODES:
                    has_exec_mode = True
                    
                if any(v.startswith(argument) for argument in SUSPICIOUS_DIRS):
                    has_suspicious_path = True
                if has_exec_mode and has_suspicious_path:
                    break
            if has_exec_mode and has_suspicious_path:
                suspicious_permission = True
        if not suspicious_permission:
            continue
        security="HIGH"
        details["raw_command"]=command
        finding = Finding(
                finding_type="suspicious_permission_change",
                title="Suspicious Permission Change Detected",
                description=f"User {event.user} added executable permissions to a file in a suspicious directory.",
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