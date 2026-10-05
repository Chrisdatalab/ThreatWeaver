import shlex,os

# splits sudo command strings into arguments and unwraps commands executed
# through "bash -c" or "sh -c", allowing detectors to inspect the real command

# return effective command after remove shell wrapper
def parse_command(command):
    parts=shlex.split(command)
    if not parts:
        return []
    executable=os.path.basename(parts[0])
    if executable in ["bash","sh"]:
        if len(parts)>2:
            if parts[1]=="-c":
                return shlex.split(parts[2])
    return parts