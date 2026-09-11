from models.finding import Finding
import shlex,os
from urllib.parse import urlparse
# TODO: support command wrappers such as nohup, timeout, env
SUSPICIOUS_EXEC_DIRS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
]
WRAPPERS = [
    "sudo",
    "nohup",
    "env",
    "timeout",
    "nice",
]

EXECUTORS = [
    "sh",
    "bash",
    "dash",
    "zsh",
    "python",
    "python3",
    "perl",
    "ruby",
]
def detect_suspicious_execution(events):
    findings = []

    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts=shlex.split(command)
        if not parts:
            continue
        suspicious_execution=False
        details={}
        

        if any(parts[0].startswith(argument) for argument in SUSPICIOUS_EXEC_DIRS):
            suspicious_execution = True
           
        else:
            execu = os.path.basename(parts[0])
            if execu in EXECUTORS:
                for v in parts[1:]:
                    if any(v.startswith(directory) for directory in SUSPICIOUS_EXEC_DIRS):
                        suspicious_execution = True
                        break
        
            
            
        
        if not suspicious_execution:
            continue
        details["raw_command"]=command
        security="HIGH"
        finding = Finding(
                    finding_type="suspicious_execution",
                    title="Suspicious Execution Detected",
                    description=f"User {event.user} execution suspicious file.",
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