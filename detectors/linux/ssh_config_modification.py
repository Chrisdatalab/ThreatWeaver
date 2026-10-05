from models.finding import Finding
from helper.command_linux_parser import parse_command
import os

# Detect suspicious modifications to OpenSSH server configuration files.
#
# Targets:
#   - /etc/ssh/sshd_config
#   - /etc/ssh/sshd_config.d/*
#
# Supports sed, tee, cp, and mv.
# Detects dangerous settings such as PermitRootLogin yes,
# PasswordAuthentication yes, PermitEmptyPasswords yes,
# and PubkeyAuthentication no.
#
# HIGH = known dangerous setting change.
# MEDIUM = SSH config modified, but exact content is unknown.
def detect_ssh_config_modification(events):
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
        # Detect dangerous sed modifications.
        if executable == "sed":
            if len(parts)>1:
                for a in parts[1:]:
                    if a=="-i" or a.startswith("-i."):
                        
                        index=parts.index(a)
                        has_replacement=False
                        for c in parts[index+1:]:
                            if c.startswith("s/"):
                                sed_p=c.split("/")
                                if len(sed_p)<3:
                                    continue
                                replacement=sed_p[2]
                                if len(replacement.split())==2:
                                    new_config_key, new_value = replacement.split()
                                    has_replacement=True
                                    break
                        if not has_replacement:
                            continue
                        index=parts.index(c)
                        if (index+1)<len(parts):
                            for b in parts[index+1:]:
                                if b == "/etc/ssh/sshd_config" or b.startswith("/etc/ssh/sshd_config.d/"):

                                    if new_config_key in ["PermitRootLogin","PasswordAuthentication","PermitEmptyPasswords"]:
                                        if new_value=="yes":
                                            security="HIGH"
                                            has_sus=True
                                            sus_act=new_config_key+" enabled"
                                    elif new_config_key == "PubkeyAuthentication":
                                        if new_value=="no":
                                            security="MEDIUM"
                                            has_sus=True
                                            sus_act=new_config_key+" disabled"
        # Detect direct writes using tee.
        elif executable == "tee":
            for a in parts[1:]:
                if a == "/etc/ssh/sshd_config" or a.startswith("/etc/ssh/sshd_config.d/"):
                    security="MEDIUM"
                    has_sus=True
                    sus_act="SSH configuration modified with tee"     
                    break   
        # Detect SSH config replacement using cp or mv.
        elif executable=="cp" or executable=="mv":
            if len(parts)>=3:
                if parts[-1] == "/etc/ssh/sshd_config" or parts[-1].startswith("/etc/ssh/sshd_config.d/"):
                    security="MEDIUM"
                    has_sus=True
                    if executable=="cp":
                        sus_act="Copied file to SSH configuration"     
                    elif executable=="mv":
                        sus_act="Moved file to SSH configuration"  
        if not has_sus:
            continue
        details["raw_command"]=command
        details["sus_act"]=sus_act
        
        finding = Finding(
                    finding_type="ssh_config_modification",
                    title="SSH_Config_Modification_Detected",
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

