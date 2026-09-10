from models.finding import Finding
import shlex, os

SHELL_COMMANDS = [
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "su",
]
def detect_privilege_escalation(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue
        command = event.attributes.get("command", "")  
        parts = shlex.split(command)

        if not parts:
            continue
        details={}
        executable = os.path.basename(parts[0])
        target_user = event.attributes.get("target_user")
        if target_user == "root" and event.user!= "root" and executable in SHELL_COMMANDS:
            
            details["action"]="root_shell"
            details["executed_shell"]=executable
            details["target_user"]=target_user
            details["raw_command"]=command
            finding = Finding(
                        finding_type="privilege_escalation",
                        title="Privilege Escalation Detected",
                        description=f"User {event.user} obtained a root shell using {executable}.",
                        severity="high",
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