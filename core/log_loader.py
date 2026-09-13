

def read_linux_log(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            yield line
def read_web_log(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            yield line
def read_windows_log(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            yield line