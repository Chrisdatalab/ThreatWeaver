from parsers import linux_auth,web_access,windows_event
from core import log_loader
def linux_log(file_path,year):
    events=[]
    for line in log_loader.read_linux_log(file_path):
        event = linux_auth.parse_line(line,year)
        # print(event)
        # print()
        events.append(event)
    return events
def web_log(file_path, year=None):
    events = []

    for line in log_loader.read_web_log(file_path):
        event = web_access.parse_line(line, year)
        if event is not None:
            events.append(event)

    return events
def windows_log(file_path, year=None):
    events = []
    
    for line in log_loader.read_windows_log(file_path):
        event = windows_event.parse_line(line, year)
        if event is not None:
            events.append(event)