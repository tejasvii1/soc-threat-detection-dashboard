import math
from datetime import datetime, timedelta
from db import get_connection, insert_alert
from discord_notify import send_discord_alert

from config import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MIN,
    IMPOSSIBLE_TRAVEL_WINDOW_MIN,
    MAX_PLAUSIBLE_SPEED_KMH,
    KNOWN_BAD_IPS,
    SUSPICIOUS_IP_DEDUPE_WINDOW_MIN,
    ESCALATION_WINDOW_MIN,
    ESCALATION_MIN_HIGH_ALERTS,
)

CITY_COORDS = {
    "New York": (40.7128, -74.0060),
    "Chicago": (41.8781, -87.6298),
    "London": (51.5074, -0.1278),
    "Berlin": (52.5200, 13.4050),
    "Tokyo": (35.6895, 139.6917),
    "Sydney": (-33.8688, 151.2093),
    "Toronto": (43.6532, -79.3832),
}
MITRE_MAP = {
    "brute_force": ("T1110", "Brute Force"),
    "impossible_travel": ("T1078", "Valid Accounts"),
    "suspicious_ip": ("T1110", "Brute Force"),
}

TS_FORMAT = "%Y-%m-%d %H:%M:%S"

def parse_ts(ts_str):
    return datetime.strptime(ts_str, TS_FORMAT)

def haversine_km(coord1, coord2):
    lat1, lon1 = coord1
    lat2, lon2 = coord2
    R = 6371  # Earth radius in km
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))

def _alert_exists(rule_name, ip, around, tolerance_minutes=1):
    lower = (around - timedelta(minutes=tolerance_minutes)).strftime(TS_FORMAT)
    upper = (around + timedelta(minutes=tolerance_minutes)).strftime(TS_FORMAT)
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT 1 FROM alerts
            WHERE rule_name = ? AND ip_address = ?
              AND triggered_at BETWEEN ? AND ?
            LIMIT 1
            """,
            (rule_name, ip, lower, upper),
        ).fetchone()
    return row is not None

def detect_brute_force():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT timestamp, username, ip_address
            FROM events
            WHERE status = 'failure'
            ORDER BY ip_address, timestamp
            """
        ).fetchall()

    by_ip = {}
    for row in rows:
        by_ip.setdefault(row["ip_address"], []).append(
            (parse_ts(row["timestamp"]), row["username"])
        )

    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
    alerts_created = 0

    for ip, attempts in by_ip.items():
        attempts.sort(key=lambda x: x[0])
        left = 0
        for right in range(len(attempts)):
            while attempts[right][0] - attempts[left][0] > window:
                left += 1
            count = right - left + 1
            if count > BRUTE_FORCE_THRESHOLD:
                window_start = attempts[left][0]
                window_end = attempts[right][0]
                target_user = attempts[right][1]
                if not _alert_exists("Brute Force", ip, window_end):
                    technique_id, technique_name = MITRE_MAP["brute_force"]
                    triggered_at_str = window_end.strftime(TS_FORMAT)
                    details_str = (f"{count} failed logins from {ip} between "
                                    f"{window_start.strftime(TS_FORMAT)} and {triggered_at_str}")
                    insert_alert(
                        rule_name="Brute Force",
                        triggered_at=triggered_at_str,
                        severity="HIGH",
                        username=target_user,
                        ip_address=ip,
                        mitre_technique_id=technique_id,
                        mitre_technique_name=technique_name,
                        details=details_str,
                    )
                    send_discord_alert(
                        rule_name="Brute Force",
                        severity="HIGH",
                        username=target_user,
                        ip_address=ip,
                        mitre_technique_id=technique_id,
                        mitre_technique_name=technique_name,
                        triggered_at=triggered_at_str,
                        details=details_str,
                    )
                    alerts_created += 1
                break  # one alert per cluster is enough

    return alerts_created

def detect_impossible_travel():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT timestamp, username, ip_address, location, country
            FROM events
            WHERE status = 'success'
            ORDER BY username, timestamp
            """
        ).fetchall()

    by_user = {}
    for row in rows:
        by_user.setdefault(row["username"], []).append(row)

    window = timedelta(minutes=IMPOSSIBLE_TRAVEL_WINDOW_MIN)
    alerts_created = 0

    for username, logins in by_user.items():
        for i in range(len(logins) - 1):
            a, b = logins[i], logins[i + 1]
            ts_a, ts_b = parse_ts(a["timestamp"]), parse_ts(b["timestamp"])
            delta = ts_b - ts_a

            if delta > window or delta.total_seconds() <= 0:
                continue
            if a["country"] == b["country"]:
                continue

            coord_a = CITY_COORDS.get(a["location"])
            coord_b = CITY_COORDS.get(b["location"])
            if not coord_a or not coord_b:
                continue

            distance_km = haversine_km(coord_a, coord_b)
            hours = delta.total_seconds() / 3600
            required_speed_kmh = distance_km / hours

            if required_speed_kmh > MAX_PLAUSIBLE_SPEED_KMH:
                if not _alert_exists("Impossible Travel", b["ip_address"], ts_b):
                    technique_id, technique_name = MITRE_MAP["impossible_travel"]
                    details_str = (
                        f"{username} logged in from {a['location']} at {a['timestamp']} "
                        f"then {b['location']} at {b['timestamp']} "
                        f"({distance_km:.0f} km in {delta}, requires {required_speed_kmh:.0f} km/h)"
                    )
                    insert_alert(
                        rule_name="Impossible Travel",
                        triggered_at=b["timestamp"],
                        severity="CRITICAL",
                        username=username,
                        ip_address=b["ip_address"],
                        mitre_technique_id=technique_id,
                        mitre_technique_name=technique_name,
                        details=details_str,
                    )
                    send_discord_alert(
                        rule_name="Impossible Travel",
                        severity="CRITICAL",
                        username=username,
                        ip_address=b["ip_address"],
                        mitre_technique_id=technique_id,
                        mitre_technique_name=technique_name,
                        triggered_at=b["timestamp"],
                        details=details_str,
                    )
                    alerts_created += 1

    return alerts_created
def detect_suspicious_ip():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT timestamp, username, ip_address FROM events ORDER BY timestamp"
        ).fetchall()

    alerts_created = 0
    for row in rows:
        if row["ip_address"] in KNOWN_BAD_IPS:
            ts = parse_ts(row["timestamp"])
            if not _alert_exists("Suspicious IP", row["ip_address"], ts, tolerance_minutes=SUSPICIOUS_IP_DEDUPE_WINDOW_MIN):
                technique_id, technique_name = MITRE_MAP["suspicious_ip"]
                details_str = f"Login attempt from known malicious IP {row['ip_address']}"
                insert_alert(
                    rule_name="Suspicious IP",
                    triggered_at=row["timestamp"],
                    severity="HIGH",
                    username=row["username"],
                    ip_address=row["ip_address"],
                    mitre_technique_id=technique_id,
                    mitre_technique_name=technique_name,
                    details=details_str,
                )
                send_discord_alert(
                    rule_name="Suspicious IP",
                    severity="HIGH",
                    username=row["username"],
                    ip_address=row["ip_address"],
                    mitre_technique_id=technique_id,
                    mitre_technique_name=technique_name,
                    triggered_at=row["timestamp"],
                    details=details_str,
                )
                alerts_created += 1

    return alerts_created
def escalate_severity():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, username, triggered_at
            FROM alerts
            WHERE severity = 'HIGH' AND username IS NOT NULL
            ORDER BY username, triggered_at
            """
        ).fetchall()

    by_user = {}
    for row in rows:
        by_user.setdefault(row["username"], []).append(row)

    window = timedelta(minutes=ESCALATION_WINDOW_MIN)
    ids_to_escalate = set()

    for username, alerts in by_user.items():
        alerts.sort(key=lambda r: r["triggered_at"])
        for i in range(len(alerts)):
            ts_i = parse_ts(alerts[i]["triggered_at"])
            cluster = [alerts[i]["id"]]
            for j in range(i + 1, len(alerts)):
                ts_j = parse_ts(alerts[j]["triggered_at"])
                if ts_j - ts_i <= window:
                    cluster.append(alerts[j]["id"])
            if len(cluster) >= ESCALATION_MIN_HIGH_ALERTS:
                ids_to_escalate.update(cluster)
    if ids_to_escalate:
        with get_connection() as conn:
            conn.executemany(
                "UPDATE alerts SET severity = 'CRITICAL' WHERE id = ?",
                [(i,) for i in ids_to_escalate],
            )
    return len(ids_to_escalate)
def main():
    bf = detect_brute_force()
    it = detect_impossible_travel()
    si = detect_suspicious_ip()
    esc = escalate_severity()

    print(f"Brute force alerts:           {bf}")
    print(f"Impossible travel alerts:     {it}")
    print(f"Suspicious IP alerts:         {si}")
    print(f"Alerts escalated to CRITICAL: {esc}")
if __name__ == "__main__":
    main()