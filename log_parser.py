import re
from datetime import datetime

LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s*\|\s*"
    r"user=(?P<username>\S+)\s*\|\s*"
    r"ip=(?P<ip>\S+)\s*\|\s*"
    r"event=(?P<event>\S+)\s*\|\s*"
    r"status=(?P<status>\S+)\s*\|\s*"
    r"location=(?P<location>.+)$"
)


def parse_line(line):

    line = line.strip()
    if not line:
        return None

    match = LINE_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()
    try:
        datetime.strptime(data["timestamp"], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    required = ["timestamp", "username", "ip", "event", "status"]
    if any(not data.get(field) for field in required):
        return None

    location_raw = data.get("location", "")
    if "," in location_raw:
        city, country = location_raw.split(",", 1)
    else:
        city, country = location_raw, ""

    return {
        "timestamp": data["timestamp"],
        "username": data["username"],
        "ip": data["ip"],
        "event_type": data["event"],
        "status": data["status"],
        "location": city.strip(),
        "country": country.strip(),
    }
def parse_log_file(path):
    records = []
    seen = set()

    stats = {
        "total_lines": 0,
        "parsed": 0,
        "malformed": 0,
        "duplicates": 0,
    }
    with open(path, "r") as f:
        for raw_line in f:
            if not raw_line.strip():
                continue

            stats["total_lines"] += 1
            record = parse_line(raw_line)

            if record is None:
                stats["malformed"] += 1
                continue

            dedupe_key = (
                record["timestamp"],
                record["username"],
                record["ip"],
                record["event_type"],
            )
            if dedupe_key in seen:
                stats["duplicates"] += 1
                continue

            seen.add(dedupe_key)
            records.append(record)
            stats["parsed"] += 1

    return records, stats
if __name__ == "__main__":
    records, stats = parse_log_file("logs/auth.log")
    print("Parse summary:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print("\nSample record:")
    if records:
        print(records[0])