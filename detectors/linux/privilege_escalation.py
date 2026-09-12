from models.finding import Finding
import shlex, os

SHELL_COMMANDS = [
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "fish",
]
def shell_uses_command_option(args):
    for arg in args:
        if arg == "--":
            break

        if not arg.startswith("-") or arg == "-":
            break

        if arg == "--command" or arg.startswith("--command="):
            return True

        if not arg.startswith("--") and "c" in arg[1:]:
            return True

    return False
def su_uses_command_option(args):
    for arg in args:
        if arg == "-c":
            return True
        if not arg.startswith("--") and arg.startswith("-") and "c" in arg[1:]:
            return True
        if arg == "--command":
            return True
        if arg.startswith("--command="):
            return True
        

    return False
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
        if target_user == "root" and event.user!= "root":
            if executable == "su":
                if su_uses_command_option(parts[1:]):
                    continue

            elif executable in SHELL_COMMANDS:
                if shell_uses_command_option(parts[1:]):
                    continue
            else:
                continue
            
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