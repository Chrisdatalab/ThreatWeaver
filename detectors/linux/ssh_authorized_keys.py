from models.finding import Finding
from helper.command_linux_parser import parse_command
import os

# Detect suspicious modifications to SSH authorized_keys files.
#
# Monitors writes to:
#   - /root/.ssh/authorized_keys
#   - /home/<user>/.ssh/authorized_keys
#
# Supports echo/redirection, tee, cp, and mv.
# HIGH = explicit SSH key insertion.
# MEDIUM = authorized_keys modified, but exact content is unknown.
def detect_ssh_authorized_key(events):
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
        # Detect authorized_keys replacement using cp or mv.
        if executable=="cp" or executable=="mv":
            if len(parts)>=3:
                if parts[-1] == ".ssh/authorized_keys" or parts[-1].endswith(".ssh/authorized_keys"):
                    security="MEDIUM"
                    has_sus=True
                    if executable=="cp":
                        sus_act="File copied to authorized_keys"     
                    elif executable=="mv":
                        sus_act="File moved to authorized_keys"  
        # Detect direct writes using tee.
        elif executable == "tee":
                    for a in parts[1:]:
                        if a.endswith("/.ssh/authorized_keys"):
                            security="MEDIUM"
                            has_sus=True
                            sus_act="authorized_keys modified using tee"     
                            break   
        # Detect SSH key insertion using shell redirection.
        elif executable=="echo":
             if len(parts)<3:
                  continue
             for b in parts[1:]:
                  
                if b in [">",">>"]:
                    index=parts.index(b)
                    if (index+1)<=len(parts):
                        for a in parts[index+1:]:
                            if a.endswith(".ssh/authorized_keys"):
                                security="HIGH"
                                sus_act="SSH public key added to authorized_keys"
                                has_sus=True
        
        if not has_sus:
            continue
        details["raw_command"]=command
        details["sus_act"]=sus_act
        
        finding = Finding(
                    finding_type="ssh_authorized_keys",
                    title="SSH Authorized Key Modification Detected",
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

        