import yaml

with open("config.yml", "r") as f:
    _config = yaml.safe_load(f)

BRUTE_FORCE_THRESHOLD = _config["detection"]["brute_force"]["threshold"]
BRUTE_FORCE_WINDOW_MIN = _config["detection"]["brute_force"]["window_minutes"]

IMPOSSIBLE_TRAVEL_WINDOW_MIN = _config["detection"]["impossible_travel"]["window_minutes"]
MAX_PLAUSIBLE_SPEED_KMH = _config["detection"]["impossible_travel"]["max_plausible_speed_kmh"]

SUSPICIOUS_IP_DEDUPE_WINDOW_MIN = _config["detection"]["suspicious_ip"]["dedupe_window_minutes"]

KNOWN_BAD_IPS = set(_config["known_bad_ips"])

ESCALATION_WINDOW_MIN = _config["severity_escalation"]["window_minutes"]
ESCALATION_MIN_HIGH_ALERTS = _config["severity_escalation"]["min_high_alerts"]