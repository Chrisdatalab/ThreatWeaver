from models.finding import Finding
import shlex,os
# Detects suspicious network listeners created using nc, ncat, or socat.

# Detection Logic:
# 1. Identify listening commands using nc, ncat, or socat.
# 2. Assign MEDIUM severity when a network listener is detected.
# 3. Assign HIGH severity when the listener executes a shell (bash or sh).
# 4. Generate a Finding containing command details and severity.
def detect_suspicious_listener(events):
    findings=[]
    for event in events:
        if event.event_type != "sudo_command":
            continue

        command = event.attributes.get("command", "")

        # Handle invalid command syntax
        try:
            parts=shlex.split(command)
        except ValueError:
            continue

        if not parts:
            continue

        has_suspicious = False
        details={}
        executable = os.path.basename(parts[0])

        # Detect ncat listening
        if executable=="ncat":
            for a in parts[1:]:
                if a=="--listen" or (
                    a.startswith("-") and not a.startswith("--") and "l" in a[1:]
                ):
                    security="MEDIUM"
                    has_suspicious=True

        # Detect nc listening
        elif executable=="nc":
            for a in parts[1:]:
                if a.startswith("-") and not a.startswith("--") and "l" in a[1:]:
                    security="MEDIUM"
                    has_suspicious=True

        # Detect socat listening
        elif executable=="socat":
            for a in parts[1:]:
                if a.startswith(("TCP-LISTEN:","TCP4-LISTEN:","TCP6-LISTEN:")):
                    security="MEDIUM"
                    has_suspicious=True

        if not has_suspicious:
            continue

        # Check whether the listener executes a shell
        for index in range(1,len(parts)):
            b=parts[index]

            # Detect nc and ncat shell execution
            if executable in ["nc","ncat"]:

                if b=="-e" or (
                    executable=="ncat" and b in ["--exec","--sh-exec"]
                ):
                    if index+1<len(parts):
                        target=parts[index+1].strip().split()

                        if target and os.path.basename(target[0]) in ["bash","sh"]:
                            security="HIGH"

                # Detect ncat --exec=/bin/bash
                elif executable=="ncat" and b.startswith(("--exec=","--sh-exec=")):
                    target=b.split("=",1)[1].strip().split()

                    if target and os.path.basename(target[0]) in ["bash","sh"]:
                        security="HIGH"

            # Detect socat shell execution
            elif executable=="socat":
                if b.startswith(("EXEC:","SYSTEM:")):

                    # Remove EXEC/SYSTEM prefix and optional socat parameters
                    target=b.split(":",1)[1].split(",",1)[0].strip().split()

                    if target and os.path.basename(target[0]) in ["bash","sh"]:
                        security="HIGH"

        details["command"]=command
        details["tool"]=executable
        details["shell_execution"]=(security=="HIGH")

        # Describe the detected behavior
        if security=="HIGH":
            description=f"User {event.user} started a network listener executing a shell using {executable}."
        else:
            description=f"User {event.user} started a network listener using {executable}."

        finding = Finding(
                finding_type="suspicious_listener",
                title="Suspicious Listener Detected",
                description=description,
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