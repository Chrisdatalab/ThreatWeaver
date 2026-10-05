from models.finding import Finding
from helper.command_linux_parser import parse_command
import os
# Detect common Linux reverse shell techniques using
# nc/ncat, /dev/tcp, socat, and Python sockets.
#
# HIGH = strong reverse shell behavior detected.
p=[
    "dup2(",
    "subprocess",
    "pty.spawn"
]
def detect_reverse_shell(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue
        command = event.attributes.get("command", "")   
        parts=parse_command(command)
        if not parts:
            continue
        has_sus=False
        details={}
        security=""
        sus_act=""
        executable = os.path.basename(parts[0])
        if executable in ["nc", "ncat"]:
            if "-l" in parts or "--listen" in parts:
                continue
            for a in parts[1:]:
                if a in ["-e","--exec"]:
                    index=parts.index(a)
                    
                    for b in parts[index+1:]:
                        if b in ["/bin/bash", "/bin/sh"]:
                            security="HIGH"
                            sus_act="Netcat reverse shell"
                            has_sus=True
                            break
        elif executable=="bash" or executable=="sh":
            for a in parts[1:]:
                if "/dev/tcp/" in a:
                    security="HIGH"
                    sus_act="Reverse shell using /dev/tcp"
                    has_sus=True
                    break
        elif executable == "socat":
            payload = " ".join(parts[1:]).lower()
            if "exec:" in payload or "system:" in payload:
                if (
                    "/bin/bash" in payload
                    or "/bin/sh" in payload
                    or "bash -i" in payload
                    or "sh -i" in payload
                ):
                    security = "HIGH"
                    sus_act = "Reverse shell using socat"
                    has_sus = True
        elif executable in ["python","python3"]:
            payload=" ".join(parts[1:]).lower()
            if "socket" in payload and "connect(" in payload:
                if "/bin/bash" in payload or "/bin/sh" in payload:
                    if any(v in payload for v in p):
                        security="HIGH"
                        sus_act = "Python reverse shell"
                        has_sus=True
                        
        if not has_sus:
            continue

        details["raw_command"] = command
        details["sus_act"] = sus_act

        finding = Finding(
            finding_type="reverse_shell",
            title="Reverse Shell Detected",
            description=f"{event.user} {sus_act}",
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