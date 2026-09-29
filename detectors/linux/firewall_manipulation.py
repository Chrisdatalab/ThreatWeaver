from models.finding import Finding
import shlex, os

# Firewall Manipulation Detection
# Detects high-risk changes to Linux firewall rules that may weaken
# host network protections or allow unauthorized inbound access.
#
# Detects:
# iptables rule flushing
# iptables default INPUT/FORWARD policy changed to ACCEPT
# nftables ruleset flushing
# UFW allow rules
#
# Category: Defense Evasion / Firewall Modification
def detect_firewall_manipulation(events):
    findings = []

    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")
        parts = shlex.split(command)

        if not parts:
            continue

        security = ""
        has_sus = False
        details = {}

        executable = os.path.basename(parts[0])

        # iptables
        if executable == "iptables":
            for v in parts[1:]:

                # Flush firewall rules
                if v in ["-F", "--flush"]:
                    security = "HIGH"
                    has_sus = True

                    details = {
                        "tool": "iptables",
                        "action": "flush",
                        "raw_command": command,
                    }
                    break

                # Change default policy to ACCEPT
                elif v in ["-P", "--policy"]:
                    index = parts.index(v)

                    if len(parts[index + 1:]) >= 2:
                        chain = parts[index + 1]
                        policy = parts[index + 2]

                        if (
                            chain in ["INPUT", "FORWARD"]
                            and policy == "ACCEPT"
                        ):
                            security = "HIGH"
                            has_sus = True

                            details = {
                                "tool": "iptables",
                                "action": "policy_change",
                                "chain": chain,
                                "policy": policy,
                                "raw_command": command,
                            }
                            break

        # nftables
        elif executable == "nft":
            if len(parts[1:]) >= 2:
                action = parts[1]
                target = parts[2]

                if action == "flush" and target == "ruleset":
                    security = "HIGH"
                    has_sus = True

                    details = {
                        "tool": "nft",
                        "action": "flush",
                        "target": target,
                        "raw_command": command,
                    }

        # UFW
        elif executable == "ufw":
            if len(parts[1:]) >= 2:
                action = parts[1]
                target = parts[2]

                if action == "allow":
                    security = "MEDIUM"
                    has_sus = True

                    details = {
                        "tool": "ufw",
                        "action": "allow",
                        "target": target,
                        "raw_command": command,
                    }

        if not has_sus:
            continue

        finding = Finding(
            finding_type="firewall_manipulation",
            title="Firewall Manipulation Detected",
            description=(
                f"User {event.user} performed a firewall modification "
                f"using {details['tool']}."
            ),
            severity=security,
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