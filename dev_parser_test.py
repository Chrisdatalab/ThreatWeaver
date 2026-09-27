from core import log_loader
from parsers import linux_auth
from pathlib import Path


FILE_PATH = "data/samples/linux/attack/ThreatWeaver_linux_attack_dataset_complete.log"
OUTPUT_PATH = "data/output/linux_unknown_events.log"
YEAR = 2026

total = 0
recognized = 0
unknown = 0
unknown_lines = []


for line in log_loader.read_linux_log(FILE_PATH):
    line = line.strip()

    if not line or line.startswith("#"):
        continue

    total += 1

    event = linux_auth.parse_line(line, YEAR)

    if event.event_type != "unknown":
        recognized += 1
    else:
        unknown += 1
        unknown_lines.append(line)


Path("data/output").mkdir(parents=True, exist_ok=True)

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    for line in unknown_lines:
        f.write(line + "\n")


print("=" * 50)
print(f"Total log lines: {total}")
print(f"Recognized:      {recognized}")
print(f"Unknown:         {unknown}")
print(f"Recognition rate: {recognized / total * 100:.1f}%")
print(f"\nUnknown events saved to: {OUTPUT_PATH}")