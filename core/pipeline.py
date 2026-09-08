from parsers import linux_auth
from core import log_loader
def linux_log(file_path):
    events=[]
    for line in log_loader.read_linux_log(file_path):
        event = linux_auth.parse_line(line)
        # print(event)
        # print()
        events.append(event)
    return events