# Security Control Disable Detection
# Detects attempts to disable or weaken Linux security controls
# that protect system logging, auditing, firewalling, and access control.
#
# Detects:
# stopping, disabling, or masking security-related services
# disabling UFW
# disabling Linux auditing with auditctl
# switching SELinux to permissive mode
#
# Category: Defense Evasion / Security Control Impairment
from models.finding import Finding
import shlex, os

SECURITY_SERVICES = [
    "auditd",
    "rsyslog",
    "fail2ban",
    "firewalld",
    "ufw",
    "apparmor",
]

SYSTEMCTL_ACTIONS = [
    "stop",
    "disable",
    "mask",
]


def detect_security_control_disable(events):
    findings = []
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts = shlex.split(command)

        if not parts:
            continue
        detected = False
        control = ""
        action = ""
        executable = os.path.basename(parts[0])
        if executable == "systemctl":
            for v in parts[1:]:
                if v in SYSTEMCTL_ACTIONS:
                    action = v
                    index = parts.index(v)

                    for service in parts[index + 1:]:
                        service_name = os.path.basename(service)

                        if service_name.endswith(".service"):
                            service_name = service_name[:-8]

                        if service_name in SECURITY_SERVICES:
                            detected = True
                            control = service_name
                            break

                    if detected:
                        break

        elif executable == "service":
            if len(parts) >= 3:
                service_name = parts[1]

                if service_name.endswith(".service"):
                    service_name = service_name[:-8]

                if (
                    service_name in SECURITY_SERVICES
                    and parts[2] == "stop"
                ):
                    detected = True
                    control = service_name
                    action = "stop"

        elif executable == "ufw":
            if "disable" in parts[1:]:
                detected = True
                control = "ufw"
                action = "disable"

        elif executable == "auditctl":
            if "-e" in parts:
                index = parts.index("-e")

                if (
                    index + 1 < len(parts)
                    and parts[index + 1] == "0"
                ):
                    detected = True
                    control = "auditd"
                    action = "disable_auditing"

        elif executable == "setenforce":
            if len(parts) >= 2 and parts[1] == "0":
                detected = True
                control = "selinux"
                action = "set_permissive"

        if not detected:
            continue

        details = {
            "control": control,
            "action": action,
            "raw_command": command,
        }

        finding = Finding(
            finding_type="security_control_disable",
            title="Security Control Disable Activity Detected",
            description=(
                f"User {event.user} attempted to disable or weaken "
                f"security control {control}."
            ),
            severity="HIGH",
            source="linux",
            host=event.host,
            user=event.user,
            src_ip=event.src_ip,
            start_time=event.timestamp,
            end_time=event.timestamp,
            event_count=1,
            events=[event],
            attributes=details,
        )

        findings.append(finding)

    return findings