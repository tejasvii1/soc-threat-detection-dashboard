import random
from datetime import datetime, timedelta

LOG_PATH = "logs/auth.log"
USERS = ["jsmith", "amartin", "rpatel", "kwilson", "lchen", "dgarcia", "tnguyen"]
LOCATIONS = {
    "203.0.113.10": ("New York", "US"),
    "203.0.113.45": ("Chicago", "US"),
    "198.51.100.23": ("London", "UK"),
    "198.51.100.77": ("Berlin", "DE"),
    "192.0.2.15": ("Tokyo", "JP"),
    "192.0.2.88": ("Sydney", "AU"),
    "203.0.113.99": ("Toronto", "CA"),
}
USER_HOME_IP = {
    "jsmith": "203.0.113.10",    # New York
    "amartin": "198.51.100.77",  # Berlin
    "rpatel": "203.0.113.45",    # Chicago
    "kwilson": "198.51.100.23",  # London
    "lchen": "203.0.113.10",     # New York — starting point for impossible travel case
    "dgarcia": "192.0.2.88",     # Sydney
    "tnguyen": "203.0.113.99",   # Toronto
}
KNOWN_BAD_IPS = ["45.155.205.13", "185.220.101.4", "91.219.237.244"]
for bad_ip in KNOWN_BAD_IPS:
    LOCATIONS[bad_ip] = ("Unknown", "XX")

NORMAL_IPS = [ip for ip in LOCATIONS if ip not in KNOWN_BAD_IPS]
LOG_LINES = []

def log(ts, username, ip, event_type, status):
    location, country = LOCATIONS.get(ip, ("Unknown", "XX"))
    line = (
        f"{ts.strftime('%Y-%m-%d %H:%M:%S')} | "
        f"user={username} | ip={ip} | event={event_type} | "
        f"status={status} | location={location},{country}"
    )
    LOG_LINES.append((ts, line))
def generate_normal_traffic(start_time, count=150):
    ts = start_time
    for _ in range(count):
        ts += timedelta(seconds=random.randint(20, 300))
        user = random.choice(USERS)
        ip = USER_HOME_IP[user]
        status = "success" if random.random() < 0.9 else "failure"
        event = "login_success" if status == "success" else "login_failure"
        log(ts, user, ip, event, status)
def generate_brute_force(start_time):
    attacker_ip = "45.155.205.13"  # also a known-bad IP -> double signal
    target_user = "rpatel"
    ts = start_time
    attempts = random.randint(8, 15)
    for _ in range(attempts):
        ts += timedelta(seconds=random.randint(10, 40))  # fast, bursty
        log(ts, target_user, attacker_ip, "login_failure", "failure")
    # attacker eventually gives up (or succeeds - toggle if you want a "breach")
    ts += timedelta(seconds=30)
    log(ts, target_user, attacker_ip, "login_failure", "failure")
def generate_impossible_travel(start_time):
    user = "lchen"
    ny_ip = "203.0.113.10"     # New York
    tokyo_ip = "192.0.2.15"    # Tokyo

    ts_ny = start_time
    log(ts_ny, user, ny_ip, "login_success", "success")

    ts_tokyo = ts_ny + timedelta(minutes=random.randint(12, 20))
    log(ts_tokyo, user, tokyo_ip, "login_success", "success")
def generate_suspicious_ip_activity(start_time):
    ts = start_time
    for bad_ip in KNOWN_BAD_IPS[1:]:  # first one already used in brute force
        ts += timedelta(minutes=random.randint(1, 5))
        user = random.choice(USERS)
        status = random.choice(["failure", "failure", "success"])
        event = "login_success" if status == "success" else "login_failure"
        log(ts, user, bad_ip, event, status)
def main():
    base_time = datetime.now() - timedelta(hours=2)

    generate_normal_traffic(base_time, count=150)
    generate_brute_force(base_time + timedelta(minutes=30))
    generate_impossible_travel(base_time + timedelta(minutes=50))
    generate_suspicious_ip_activity(base_time + timedelta(minutes=70))

    LOG_LINES.sort(key=lambda x: x[0])

    with open(LOG_PATH, "w") as f:
        for _, line in LOG_LINES:
            f.write(line + "\n")

    print(f"Generated {len(LOG_LINES)} log lines -> {LOG_PATH}")

if __name__ == "__main__":
    main()