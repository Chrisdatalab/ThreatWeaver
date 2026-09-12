from models.finding import Finding
import shlex,os

SHELL_COMMANDS = [
    "bash",
    "sh",
    "zsh",
]

PRIVILEGE_COMMANDS = [
    "su",
]
def detect_suspicious_privileged_shell(events):
    findings=[]
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts=shlex.split(command)
        if not parts:
            continue
        suspicious_shell = False
        indicators = []
        details={}
        executable = os.path.basename(parts[0])
        if executable in SHELL_COMMANDS:
            if "-c" not in parts[1:]:
                suspicious_shell=True
                indicators.append("interactive_shell")
        elif command in ["-i", "-s"]:
            suspicious_shell=True
            indicators.append("sudo_shell_option")

        elif executable in PRIVILEGE_COMMANDS:
            suspicious_shell=True
            indicators.append("privilege_switch")
        if not suspicious_shell:
            continue
        details["indicators"] = indicators
        details["raw_command"]=command
        security="HIGH"
        finding = Finding(
                    finding_type="privileged_shell",
                    title="Suspicious Privileged Shell",
                    description=f"User {event.user} started a privileged shell using sudo.",
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
