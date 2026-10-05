from models.finding import Finding
from helper.command_linux_parser import parse_command
import os

# Detect suspicious modifications to shell startup files.
#
# Monitors .bashrc, .profile, /etc/profile, and /etc/bash.bashrc.
# Supports echo/printf redirection, tee, cp, mv, and sed.
# HIGH = suspicious command is added to a shell profile.
# MEDIUM = shell profile is modified but malicious content is unclear.
FILE_ADD = [
    ".bashrc",
    ".profile",
    "/etc/profile",
    "/etc/bash.bashrc",
]

STRONG_PAYLOAD_INDICATORS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/dev/tcp",
    "curl",
    "wget",
    "nc ",
    "ncat",
    "socat",
    "base64",
]

WEAK_PAYLOAD_INDICATORS = [
    "bash",
    "sh ",
    "python",
    "perl",
    "ruby",
    "&",
]


def detect_shell_profile_persistence(events):
    findings = []

    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts = parse_command(command)

        if not parts:
            continue

        has_sus = False
        details = {}
        security = ""
        sus_act = ""

        executable = os.path.basename(parts[0])

        # Detect echo/printf redirection into shell profile files
        if executable in ["echo", "printf"]:
            if len(parts) < 3:
                continue

            for b in parts[1:]:
                if b in [">", ">>"]:
                    index = parts.index(b)

                    # Everything between executable and redirect is the payload
                    payload = " ".join(parts[1:index]).lower()

                    strong_hit = any(
                        indicator in payload
                        for indicator in STRONG_PAYLOAD_INDICATORS
                    )

                    weak_hits = sum(
                        1
                        for indicator in WEAK_PAYLOAD_INDICATORS
                        if indicator in payload
                    )

                    # Check the redirect target
                    for target in parts[index + 1:]:
                        if any(target.endswith(v) for v in FILE_ADD):
                            has_sus = True

                            if strong_hit or weak_hits >= 2:
                                security = "HIGH"
                                sus_act = "Suspicious command added to shell profile"
                            else:
                                security = "MEDIUM"
                                sus_act = "Shell profile modified"

                            break

                if has_sus:
                    break

        # Detect replacement using cp or mv
        elif executable in ["cp", "mv"]:
            if len(parts) >= 3:
                target = parts[-1]

                if any(target.endswith(v) for v in FILE_ADD):
                    security = "MEDIUM"
                    has_sus = True

                    if executable == "cp":
                        sus_act = "Shell profile replaced using cp"
                    else:
                        sus_act = "Shell profile replaced using mv"

        # Detect direct writes using tee
        elif executable == "tee":
            for target in parts[1:]:
                if any(target.endswith(v) for v in FILE_ADD):
                    security = "MEDIUM"
                    has_sus = True
                    sus_act = "Shell profile modified using tee"
                    break

        # Detect in-place modification using sed
        elif executable == "sed":
            for a in parts[1:]:
                if a == "-i" or a.startswith("-i."):
                    index = parts.index(a)

                    for target in parts[index + 1:]:
                        if any(target.endswith(v) for v in FILE_ADD):
                            security = "MEDIUM"
                            has_sus = True
                            sus_act = "Shell profile modified using sed"
                            break

                if has_sus:
                    break

        if not has_sus:
            continue

        details["raw_command"] = command
        details["sus_act"] = sus_act

        finding = Finding(
            finding_type="shell_profile_persistence",
            title="Shell Profile Persistence Detected",
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