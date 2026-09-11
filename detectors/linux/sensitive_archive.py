from models.finding import Finding
import shlex,os

ARCHIVE_COMMANDS = [
    "tar",
    "zip",
    "7z",
]
SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/ssh",
    "/root/.ssh",
]
SENSITIVE_NAMES = [
    "/.ssh/",
    "authorized_keys",
]
def detect_sensitive_archive(events):
    findings=[]
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts=shlex.split(command)
        if not parts:
            continue
        sensitive_archive=False
        details={}
        executable = os.path.basename(parts[0])
        if executable in ARCHIVE_COMMANDS:
            for v in parts[1:]:
                if (
                    any(
                        v == argument or v.startswith(argument + "/")
                        for argument in SENSITIVE_PATHS
                    )
                    or any(name in v for name in SENSITIVE_NAMES)
                ):
                    sensitive_archive = True
                    break
        if not sensitive_archive:
            continue
       
        security="HIGH"
        details["raw_command"]=command
        finding = Finding(
                finding_type="sensitive_archive",
                title="Sensitive Archive Detected",
                description=f"User {event.user} archived sensitive files or directories.",
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
    